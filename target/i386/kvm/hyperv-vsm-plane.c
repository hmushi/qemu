/*
 * Hyper-V VSM: plane API implementation (include/hw/hyperv/vsm-plane-api.h)
 * on KVM planes.
 *
 * One KVM plane per VTL, created at HvCallEnablePartitionVtl; one X86CPU
 * per VTL per VP, the plane vCPU being a sibling of the plane-0 CPUState
 * (accel/kvm: shares its host thread, kvm_run page and halt condition). A
 * VTL switch moves the TLFS-shared register state between the siblings,
 * then makes the sibling the CPUState the thread runs next
 * (kvm_plane_select()) and leaves the current kvm_cpu_exec().
 *
 * KVM_RUN always goes to the plane-0 fd with kvm_run->plane naming the plane
 * to run (KVM_CAP_PLANES_USERSPACE_SWITCH, written by accel/kvm);
 * hv_plane_pre_run() sets req_exit_planes so a higher plane's pending
 * interrupt ends the lower plane's KVM_RUN with KVM_EXIT_PLANE_EVENT cause
 * INTERRUPT (hv_plane_vtl_event()).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "qapi/error.h"
#include "migration/blocker.h"
#include "system/cpus.h"
#include "system/hw_accel.h"
#include "system/kvm_int.h"
#include "hw/core/boards.h"
#include "hw/hyperv/hyperv.h"
#include "hw/i386/apic_internal.h"
#include "hw/pci/msi.h"
#include "cpu.h"
#include "kvm_i386.h"
#include "hyperv-vsm.h"
#include "trace.h"

/* bit N set: KVM plane N exists (plane 0 always) */
static unsigned int planes_created = BIT(0);
static Error *vsm_mig_blocker;

int hv_plane_active_vtl(CPUState *cs)
{
    return cs->kvm_plane;
}

CPUState *hv_plane_vcpu(uint32_t vp_index, int vtl)
{
    CPUState *cs;

    /* plane CPUStates share the cpu_index of their plane-0 sibling */
    CPU_FOREACH(cs) {
        if (cs->cpu_index == vp_index && !cs->kvm_plane_leader) {
            break;
        }
    }
    if (!cs || vtl == 0) {
        return cs;
    }
    for (cs = qatomic_rcu_read(&cs->kvm_plane_next); cs;
         cs = qatomic_rcu_read(&cs->kvm_plane_next)) {
        if (cs->kvm_plane == vtl) {
            return cs;
        }
    }
    return NULL;
}

KVMState *hv_plane_kvm_state(CPUState *cs)
{
    /*
     * One KVMState and one GSI routing table for all planes: the kernel
     * keeps a single table and KVM_SET_GSI_ROUTING on a plane fd replaces it
     * tagged with that plane, so SINT routes carry the plane in the entry
     * (hw/hyperv/hyperv.c) and MSIs go to the plane fd (hv_plane_send_msi()).
     */
    return kvm_state;
}

/*
 * Planes get their own TDP root only: with shadow paging (ept=0 / npt=0)
 * all planes share the roots and no per-VTL protection holds.
 */
static bool host_has_tdp(void)
{
    static const char *const params[] = {
        "/sys/module/kvm_intel/parameters/ept",
        "/sys/module/kvm_amd/parameters/npt",
    };
    g_autofree char *val = NULL;

    for (int i = 0; i < ARRAY_SIZE(params); i++) {
        if (g_file_get_contents(params[i], &val, NULL, NULL)) {
            return val[0] == 'Y' || val[0] == '1';
        }
    }
    return false;
}

int hv_plane_create(int vtl)
{
    int ret;

    if (vtl <= 0 || vtl >= HV_NUM_VTLS) {
        return -EINVAL;
    }
    if (planes_created & BIT(vtl)) {
        return 0;                       /* kept across a system reset */
    }
    if (!host_has_tdp()) {
        error_report("hyperv-vsm: VTL%d needs EPT/NPT (two-dimensional "
                     "paging) in KVM", vtl);
        return -ENOTSUP;
    }

    ret = kvm_create_plane(vtl);
    trace_hyperv_vsm_plane_create(vtl, ret);
    if (ret < 0) {
        return ret;
    }
    planes_created |= BIT(vtl);

    /* TODO: vmstate for the plane vCPUs, the VSM registers and attributes */
    if (!vsm_mig_blocker) {
        error_setg(&vsm_mig_blocker, "Hyper-V VSM: a VTL above 0 is enabled");
        migrate_add_blocker(&vsm_mig_blocker, &error_abort);
    }
    return 0;
}

CPUState *hv_plane_vcpu_create(uint32_t vp_index, int vtl)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    CPUState *leader = hv_plane_vcpu(vp_index, 0);
    Error *err = NULL;
    Object *obj;
    CPUState *cs;

    if (!leader || !(planes_created & BIT(vtl))) {
        return NULL;
    }
    cs = hv_plane_vcpu(vp_index, vtl);
    if (cs) {
        return cs;                      /* kept across a system reset */
    }

    /*
     * Same CPU model and features as the sibling (the -cpu string is a
     * class-wide default); x86_cpu_pre_plug() copies the APIC ID, topology
     * and cpu_index; the KVM accel creates the plane vCPU on the sibling's
     * thread. Realized hotplug-style: the generic realize resumes it, so it
     * is runnable once hv_plane_run_vtl() selects it.
     */
    bql_lock();
    obj = object_new(ms->cpu_type);
    cs = CPU(obj);
    cs->kvm_plane = vtl;
    cs->kvm_plane_leader = leader;
    qdev_realize(DEVICE(obj), NULL, &err);
    object_unref(obj);
    if (err) {
        error_reportf_err(err, "hyperv-vsm: cannot create VP %u VTL%d: ",
                          vp_index, vtl);
        cs = NULL;
    }
    bql_unlock();

    trace_hyperv_vsm_plane_vcpu_create(vp_index, vtl, !!cs);
    return cs;
}

static void select_plane_work(CPUState *leader, run_on_cpu_data arg)
{
    kvm_plane_select(arg.host_ptr);
}

void hv_plane_reset(void)
{
    CPUState *cs;

    CPU_FOREACH(cs) {
        if (cs->kvm_plane_next) {
            run_on_cpu(cs, select_plane_work, RUN_ON_CPU_HOST_PTR(cs));
        }
    }
}

int hv_plane_vcpu_start(uint32_t vp_index, int start_vtl)
{
    CPUState *cs = hv_plane_vcpu(vp_index, start_vtl);

    if (!cs) {
        return -ENOENT;
    }

    trace_hyperv_vsm_plane_vcpu_start(vp_index, start_vtl);
    cs->halted = 0;
    /* the kick ends the VP thread's KVM_RUN; it then runs @cs */
    run_on_cpu(cs->kvm_plane_leader ? cs->kvm_plane_leader : cs,
               select_plane_work, RUN_ON_CPU_HOST_PTR(cs));
    return 0;
}

int hv_plane_set_memory_attrs(int vtl, hwaddr addr, hwaddr size, uint64_t attrs)
{
    struct kvm_plane_memory_attributes pattrs = {
        .plane = vtl,
        .address = addr,
        .size = size,
        .attributes = attrs,
    };

    if (vtl < 0 || !(planes_created & BIT(vtl))) {
        return -ENOENT;
    }
    return kvm_vm_ioctl(kvm_state, KVM_SET_PLANE_MEMORY_ATTRIBUTES, &pattrs);
}

int hv_plane_translate(CPUState *cs, struct kvm_translation2 *tr)
{
    return kvm_vcpu_ioctl(cs, KVM_TRANSLATE2, tr);
}

int hv_plane_set_tlb_flush_inhibit(CPUState *cs, bool inhibit)
{
    struct kvm_hyperv_tlb_flush_inhibit set = {
        .inhibit = inhibit ? KVM_HYPERV_INHIBIT_TLB_FLUSH :
                             KVM_HYPERV_UNINHIBIT_TLB_FLUSH,
    };

    return kvm_vcpu_ioctl(cs, KVM_HYPERV_SET_TLB_FLUSH_INHIBIT, &set);
}

/*
 * VTL switch. Everything runs on the VP's one host thread, from inside the
 * KVM exit handler of the plane that stops.
 */
static CPUState *vtl_sibling(CPUState *cs, int vtl)
{
    return hv_plane_vcpu(hyperv_vp_index(cs), vtl);
}

/* planes of @cs's VP whose pending interrupts preempt plane @vtl (TLFS 15.3) */
static uint16_t higher_planes(CPUState *cs, int vtl)
{
    CPUState *leader = cs->kvm_plane_leader ? cs->kvm_plane_leader : cs;
    uint16_t mask = 0;

    for (cs = qatomic_rcu_read(&leader->kvm_plane_next); cs;
         cs = qatomic_rcu_read(&cs->kvm_plane_next)) {
        if (cs->kvm_plane > vtl) {
            mask |= BIT(cs->kvm_plane);
        }
    }
    return mask;
}

/*
 * The last descriptor reading of each plane that was actually read back from
 * KVM. The shutdown dump has no table base of its own to translate, because
 * that field reads zero on that path while the global table reads correctly.
 */
static struct {
    uint64_t base;
    uint32_t limit;
    bool valid;
} last_idt[HV_NUM_VTLS];

/* descriptor state of both planes at a switch step; idt/gdt are per-VTL */
static void trace_desc_state(const char *phase, CPUState *cs, CPUState *target)
{
    CPUState *c[2] = { cs, target };
    int i;

    for (i = 0; i < 2; i++) {
        CPUX86State *env = &X86_CPU(c[i])->env;
        int vtl = hv_plane_active_vtl(c[i]);

        trace_hyperv_vsm_plane_desc_state(phase, hyperv_vp_index(c[i]), vtl,
                                          c[i]->vcpu_dirty, env->idt.base,
                                          env->idt.limit, env->gdt.base,
                                          env->gdt.limit);
        /*
         * Keep the last reading for the shutdown dump, which needs a table
         * base to translate and reads zero for it on that path. Only a dirty
         * CPUState has been read back from KVM, so an undirty reading is a
         * stale copy and is not kept.
         */
        if (c[i]->vcpu_dirty && env->idt.base && vtl < HV_NUM_VTLS) {
            last_idt[vtl].base = env->idt.base;
            last_idt[vtl].limit = env->idt.limit;
            last_idt[vtl].valid = true;
        }
    }
}

bool hv_plane_last_idt(int vtl, uint64_t *base, uint32_t *limit)
{
    if (vtl < 0 || vtl >= HV_NUM_VTLS || !last_idt[vtl].valid) {
        return false;
    }
    *base = last_idt[vtl].base;
    *limit = last_idt[vtl].limit;
    return true;
}

int hv_plane_run_vtl(CPUState *cs, int target_vtl, HvPlaneSwitchReason reason)
{
    CPUState *target = vtl_sibling(cs, target_vtl);
    int ret;

    trace_hyperv_vsm_plane_run_vtl(hyperv_vp_index(cs), hv_plane_active_vtl(cs),
                                  target_vtl, reason);
    if (!target) {
        return -ENOENT;
    }
    if (target == cs) {
        return -EINVAL;
    }
    assert(qemu_cpu_is_self(cs) && qemu_cpu_is_self(target));

    /*
     * Both register files current: the shared state is read from @cs and
     * written over @target's, whose private state must not be stale when
     * the whole file is pushed back before its next KVM_RUN (the
     * synchronize marks it dirty).
     */
    trace_desc_state("pre-sync", cs, target);
    cpu_synchronize_state(cs);
    cpu_synchronize_state(target);
    trace_desc_state("post-sync", cs, target);

    bql_lock();
    hyperv_vsm_vtl_switch_state(cs, target, reason);
    bql_unlock();
    trace_desc_state("post-shared", cs, target);

    /* MTRRs, MCG and VP runtime are reset-level MSRs: push them now */
    ret = kvm_put_hv_shared_msrs(X86_CPU(target));
    if (ret < 0) {
        error_report("hyperv-vsm: cannot write the shared MSRs of VP %u "
                     "VTL%d: %s", hyperv_vp_index(cs), target_vtl,
                     strerror(-ret));
        return ret;
    }

    /*
     * A VtlCall or VtlReturn exit is completed by the kernel without reading
     * the shared kvm_run page; every other exit was completed before.
     */
    /* the kernel reports lower interrupts afresh after a switch (no re-arm) */
    target->kvm_plane_vina_armed = hyperv_vsm_vina_armed(target);
    target->halted = 0;
    kvm_plane_select(target);

    /* leave this plane's run loop; the thread picks up @target */
    return EXCP_INTERRUPT;
}

int hv_plane_send_msi(CPUState *cs, MSIMessage msg)
{
    struct kvm_msi msi = {
        .address_lo = (uint32_t)msg.address,
        .address_hi = msg.address >> 32,
        .data = le32_to_cpu(msg.data),
    };

    if (cs->kvm_plane == 0) {
        return kvm_irqchip_send_msi(kvm_state, msg);
    }
    /* KVM_SIGNAL_MSI on the plane fd delivers to that plane's LAPICs */
    return kvm_plane_ioctl(cs->kvm_plane, KVM_SIGNAL_MSI, &msi);
}

/*
 * VINA arming. The kernel reports a lower plane's interrupt once per
 * 0 -> 1 transition of its req_exit_planes bit, or once per "became
 * pending" edge while the bit stays set. After the guest clears
 * vina_asserted the next lower interrupt must be reported again even if
 * it never went away, so the bit is dropped for one KVM_RUN when the VTL
 * goes from asserted back to armed (kvm_plane_vina_armed tracks the
 * previous state).
 */
static uint16_t vina_lower_planes(CPUState *cs, struct kvm_run *run)
{
    bool armed = hyperv_vsm_vina_armed(cs);
    bool rearm = armed && !cs->kvm_plane_vina_armed;

    cs->kvm_plane_vina_armed = armed;
    if (!armed || rearm) {
        return 0;
    }
    return BIT(cs->kvm_plane) - 1;
}

/* post-switch entries read back, and how many of those carried a null */
void hv_plane_pre_run(CPUState *cs, struct kvm_run *run)
{
    /* a higher VTL's pending interrupt ends this VTL's run (TLFS 15.3) */
    run->req_exit_planes = higher_planes(cs, cs->kvm_plane);
    /* a lower VTL's pending interrupt is notified by VINA (TLFS 15.2.3) */
    if (cs->kvm_plane > 0) {
        run->req_exit_planes |= vina_lower_planes(cs, run);
    }

    /*
     * The entry this plane resumes at is where both triple faults are, and
     * our own copy reads correct at every switch, so the question is what
     * the entered state holds rather than what we hold. Read it back here,
     * the last point before KVM_RUN, on an entry whose plane differs from
     * the one the shared page last ran: that is a switch return. Report
     * only a null interrupt table, so a good entry costs one read and no
     * output, and count every read so a zero is a measured zero.
     */
    if (run->plane != cs->kvm_plane &&
        trace_event_get_state_backends(TRACE_HYPERV_VSM_PLANE_ENTRY_NULL)) {
        X86CPU *cpu = X86_CPU(cs);
        int prev_plane = run->plane;
        struct kvm_dtable idt, gdt;
        int rc;

        rc = kvm_get_vcpu_dtables(cs, &idt, &gdt);
        cpu->hv_plane_entry_reads++;
        if (rc < 0 || idt.limit == 0) {
            CPUX86State *env = &cpu->env;

            cpu->hv_plane_entry_nulls++;
            trace_hyperv_vsm_plane_entry_null(hyperv_vp_index(cs),
                                              cs->kvm_plane, prev_plane, rc,
                                              env->idt.base, env->idt.limit,
                                              idt.base, idt.limit,
                                              gdt.base, gdt.limit);
        }
        /*
         * The first entries of every processor and plane, then one in 16.
         * A processor that takes a hundred of the boot's seventy thousand
         * switch returns never reaches a shared period, so a census keyed
         * on a single counter never prints the value it entered with.
         */
        if (cpu->hv_plane_entry_reads <= 8 ||
            !(cpu->hv_plane_entry_reads % 16)) {
            trace_hyperv_vsm_plane_entry_census(hyperv_vp_index(cs),
                                                cs->kvm_plane,
                                                cpu->hv_plane_entry_reads,
                                                cpu->hv_plane_entry_nulls,
                                                idt.base, idt.limit,
                                                gdt.base, gdt.limit);
        }
    }
}

int hv_plane_vtl_event(CPUState *cs, struct kvm_run *run)
{
    struct kvm_plane_event_exit *ev = &run->plane_event;
    uint16_t pending;

    trace_hyperv_vsm_plane_vtl_event(hyperv_vp_index(cs), cs->kvm_plane,
                                    ev->cause, ev->plane, ev->extra[0]);

    switch (ev->cause) {
    case KVM_PLANE_EVENT_INTERRUPT:
        /* extra[0]: req_exit_planes planes with an injectable interrupt */
        pending = ev->extra[0] & higher_planes(cs, cs->kvm_plane);
        if (!pending) {
            return 0;
        }
        return hv_plane_run_vtl(cs, 31 - clz32(pending),
                                HV_PLANE_SWITCH_INTERRUPT);
    case KVM_PLANE_EVENT_LOWER_INTERRUPT:
        /*
         * A lower VTL's interrupt became pending while this VTL runs:
         * notify, keep running this plane. The lower VTL takes its
         * interrupt itself on VtlReturn; VINA does not consume it.
         */
        if (ev->extra[0] & (BIT(cs->kvm_plane) - 1)) {
            hyperv_vsm_vina_notify(cs);
        }
        return 0;
    case KVM_PLANE_EVENT_CREATE_VCPU:
        /* SNP AP creation; Hyper-V VTLs create their vCPUs from userspace */
        qemu_log_mask(LOG_UNIMP, "hyperv-vsm: unexpected plane vCPU creation "
                      "request for plane %u on VP %u\n", ev->plane,
                      hyperv_vp_index(cs));
        return 0;
    default:
        qemu_log_mask(LOG_UNIMP, "hyperv-vsm: unknown plane event %u on VP "
                      "%u\n", ev->cause, hyperv_vp_index(cs));
        return -1;
    }
}

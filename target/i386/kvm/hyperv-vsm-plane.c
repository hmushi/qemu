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
        return -EEXIST;
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

    if (!leader || !(planes_created & BIT(vtl)) ||
        hv_plane_vcpu(vp_index, vtl)) {
        return NULL;
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

static void do_cpu_init_work(CPUState *cs, run_on_cpu_data arg)
{
    do_cpu_init(X86_CPU(cs));
}

int hv_plane_vcpu_reset(CPUState *cs)
{
    if (!cs->kvm_plane) {
        return -EINVAL;
    }
    /* runs on the sibling's thread; cpu_synchronize_post_reset() follows */
    cpu_synchronize_state(cs);
    run_on_cpu(cs, do_cpu_init_work, RUN_ON_CPU_NULL);
    return 0;
}

static void select_plane_work(CPUState *leader, run_on_cpu_data arg)
{
    kvm_plane_select(arg.host_ptr);
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
    cpu_synchronize_state(cs);
    cpu_synchronize_state(target);

    bql_lock();
    hyperv_vsm_vtl_switch_state(cs, target, reason);
    bql_unlock();

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
    target->halted = 0;
    kvm_plane_select(target);

    /* leave this plane's run loop; the thread picks up @target */
    return EXCP_INTERRUPT;
}

void hv_plane_pre_run(CPUState *cs, struct kvm_run *run)
{
    /* a higher VTL's pending interrupt ends this VTL's run (TLFS 15.3) */
    run->req_exit_planes = higher_planes(cs, cs->kvm_plane);
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

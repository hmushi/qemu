/*
 * Hyper-V VSM: the target-neutral plane API implementation on KVM planes.
 *
 * Each VP has one CPUState per VTL; a plane vCPU shares the host thread,
 * kvm_run page and halt condition of its plane-0 sibling. KVM_RUN on the
 * plane-0 fd runs the one plane kvm_plane_select() left runnable.
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
#include "hw/core/cpu.h"
#include "hw/hyperv/hyperv.h"
#include "hw/hyperv/vsm-plane-api.h"
#include "hw/pci/msi.h"
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
     * The kernel keeps a single GSI routing table for all planes, so SINT
     * routes carry their plane in the entry.
     */
    return kvm_state;
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
    if (!hv_plane_arch_host_supported(vtl)) {
        return -ENOTSUP;
    }

    ret = kvm_get_or_create_plane_fd(kvm_state, vtl);
    trace_hyperv_vsm_plane_create(vtl, ret);
    if (ret < 0) {
        return ret;
    }
    planes_created |= BIT(vtl);

    /* Plane vCPUs, VSM registers and memory attributes have no vmstate. */
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
     * Realized hotplug-style with the sibling's CPU model: the generic
     * realize resumes it, so it runs once hv_plane_run_vtl() selects it.
     */
    bql_lock();
    obj = object_new(ms->cpu_type);
    cs = CPU(obj);
    cs->kvm_plane = vtl;
    cs->kvm_plane_leader = leader;
    hv_plane_arch_vcpu_init(cs, leader);
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

/* reselects a leader's own plane at system reset, once per VP */
static void select_plane_work(CPUState *leader, run_on_cpu_data arg)
{
    CPUState *sel = arg.host_ptr;

    trace_hyperv_vsm_plane_selected(hyperv_vp_index(sel), sel->kvm_plane,
                                    "reset");
    kvm_plane_select(sel);
}

void hv_plane_select_start(CPUState *start)
{
    assert(qemu_cpu_is_self(start->kvm_plane_leader ?: start));
    trace_hyperv_vsm_plane_selected(hyperv_vp_index(start), start->kvm_plane,
                                    "start");
    kvm_plane_select(start);
}

void hv_plane_reset(void)
{
    CPUState *cs;

    CPU_FOREACH(cs) {
        if (!cs->kvm_plane_next) {
            continue;
        }
        run_on_cpu(cs, select_plane_work, RUN_ON_CPU_HOST_PTR(cs));
    }
}

int hv_plane_set_memory_attrs(int vtl, hwaddr addr, hwaddr size, uint64_t attrs)
{
    struct kvm_memory_attributes mattrs = {
        .address = addr,
        .size = size,
        .attributes = attrs,
    };

    if (vtl < 0 || !(planes_created & BIT(vtl))) {
        return -ENOENT;
    }
    return kvm_vm_plane_ioctl(kvm_state, vtl, KVM_SET_MEMORY_ATTRIBUTES,
                              &mattrs);
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
     * @target's whole register file is pushed before its next KVM_RUN, so
     * its private state must be current, not only the shared part.
     */
    ret = hv_plane_arch_switch_state(cs, target, reason);
    if (ret < 0) {
        return ret;
    }

    /*
     * A VtlCall or VtlReturn exit is completed by the kernel without reading
     * the shared kvm_run page; every other exit was completed before.
     */
    target->halted = 0;
    trace_hyperv_vsm_plane_selected(hyperv_vp_index(target),
                                    target->kvm_plane, "vtl-switch");
    kvm_plane_select(target);

    return EXCP_INTERRUPT;
}

int hv_plane_send_msi(CPUState *cs, MSIMessage msg)
{
    msg.plane_id = cs->kvm_plane;
    return kvm_irqchip_send_msi(kvm_state, msg);
}

/*
 * The kernel reports other planes' interrupts itself; nothing is armed per
 * run beyond lowering an acknowledged VINA line (TLFS 15.2.3).
 */
void hv_plane_pre_run(CPUState *cs, struct kvm_run *run)
{
    if (cs->kvm_plane > 0) {
        hv_plane_arch_vina_armed(cs);
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
        /* extra[0]: the higher planes with an injectable interrupt */
        pending = ev->extra[0] & higher_planes(cs, cs->kvm_plane);
        if (!pending) {
            return 0;
        }
        return hv_plane_run_vtl(cs, 31 - clz32(pending),
                                HV_PLANE_SWITCH_INTERRUPT);
    case KVM_PLANE_EVENT_LOWER_INTERRUPT:
        /* The lower VTL takes it on VtlReturn; VINA only notifies. */
        if (ev->extra[0] & (BIT(cs->kvm_plane) - 1)) {
            hv_plane_arch_vina_notify(cs);
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

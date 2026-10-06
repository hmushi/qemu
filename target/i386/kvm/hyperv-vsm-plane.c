/*
 * Hyper-V VSM: plane API implementation (include/hw/hyperv/vsm-plane-api.h)
 *
 * This is the file the P4 class-B work rewrites against the KVM planes UAPI.
 * Today every operation that needs a plane returns -ENOSYS, and the VTL
 * switch is Nicolas Saenz Julienne's two-thread choreography ("WIP: rework
 * VTL switching"): the inactive VTL's vCPU thread is parked in
 * KVM_MP_STATE_HV_INACTIVE_VTL and woken through a KVM_SYSTEM_EVENT_WAKEUP
 * exit, the active one is stopped with cs->stop and the hand-over runs as
 * async_run_on_cpu() work on both threads. It is kept so the Hyper-V side
 * (hyperv-vsm.c) has a complete call sequence to compile against, not as a
 * design to port: with planes the switch is one KVM_RUN per VTL on the same
 * thread (D8 form: kvm_run->plane on the plane-0 fd, or the plane vCPU fd).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu/lockable.h"
#include "qemu/main-loop.h"
#include "system/cpus.h"
#include "system/hw_accel.h"
#include "hw/hyperv/hyperv.h"
#include "cpu.h"
#include "kvm_i386.h"
#include "hyperv-vsm.h"
#include "trace.h"

int hv_plane_active_vtl(CPUState *cs)
{
    /* plane-0 CPUStates only; hv_plane_vcpu_create() sets the plane */
    return 0;
}

CPUState *hv_plane_vcpu(uint32_t vp_index, int vtl)
{
    /* VP index is the cpu_index (hyperv_vp_index()); no plane above 0 yet */
    return vtl == 0 ? qemu_get_cpu(vp_index) : NULL;
}

KVMState *hv_plane_kvm_state(CPUState *cs)
{
    /* one KVMState; class B selects the plane fd for routing and MSI */
    return kvm_state;
}

int hv_plane_create(int vtl)
{
    trace_hyperv_vsm_plane_stub("hv_plane_create", vtl);
    return -ENOSYS;
}

CPUState *hv_plane_vcpu_create(uint32_t vp_index, int vtl)
{
    trace_hyperv_vsm_plane_stub("hv_plane_vcpu_create", vtl);
    return NULL;
}

static void do_cpu_init_work(CPUState *cs, run_on_cpu_data arg)
{
    do_cpu_init(X86_CPU(cs));
}

int hv_plane_vcpu_reset(CPUState *cs)
{
    kvm_cpu_synchronize_state(cs);
    qatomic_set(&cs->stop, true);
    run_on_cpu(cs, do_cpu_init_work, RUN_ON_CPU_NULL);
    return 0;
}

int hv_plane_vcpu_start(uint32_t vp_index, int start_vtl)
{
    CPUState *cs = hv_plane_vcpu(vp_index, start_vtl);

    if (!cs) {
        return -ENOENT;
    }
    cpu_resume(cs);
    return 0;
}

int hv_plane_set_memory_attrs(int vtl, hwaddr addr, hwaddr size, uint64_t attrs)
{
    trace_hyperv_vsm_plane_stub("hv_plane_set_memory_attrs", vtl);
    return -ENOSYS;
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
 * VTL switch, current implementation. Per-VP switch bookkeeping lives here,
 * keyed by the VTL1 CPUState, so hyperv-vsm.c carries none of it.
 */
#define VTL_INTERRUPT_PENDING   BIT(0)
#define VTL_CALL_PENDING        BIT(1)

typedef struct HvPlaneVcpu {
    unsigned int event_state;   /* VTL_*_PENDING, atomic */
    bool event_handled;
} HvPlaneVcpu;

/* keyed by the VTL1 CPUState; callers run without the BQL */
static GHashTable *plane_vcpus;
static QemuMutex plane_vcpus_lock;

static void __attribute__((constructor)) plane_vcpus_init(void)
{
    qemu_mutex_init(&plane_vcpus_lock);
    plane_vcpus = g_hash_table_new(NULL, NULL);
}

static HvPlaneVcpu *plane_vcpu(CPUState *cs)
{
    HvPlaneVcpu *pv;

    QEMU_LOCK_GUARD(&plane_vcpus_lock);
    pv = g_hash_table_lookup(plane_vcpus, cs);
    if (!pv) {
        pv = g_new0(HvPlaneVcpu, 1);
        g_hash_table_insert(plane_vcpus, cs, pv);
    }
    return pv;
}

static CPUState *vtl_sibling(CPUState *cs, int vtl)
{
    return hv_plane_vcpu(hyperv_vp_index(cs), vtl);
}

/* VTL1 thread: take over from VTL0 */
static void do_vtl1_entry(CPUState *vtl1, run_on_cpu_data arg)
{
    CPUX86State *env = &X86_CPU(vtl1)->env;
    CPUState *vtl0 = vtl_sibling(vtl1, 0);
    HvPlaneVcpu *pv = plane_vcpu(vtl1);
    unsigned int state = qatomic_read(&pv->event_state);

    trace_hyperv_vsm_plane_vtl_entry(hyperv_vp_index(vtl1), state);

    cpu_synchronize_state(vtl1);
    hyperv_vsm_vtl_switch_state(vtl0, vtl1, state & VTL_CALL_PENDING ?
                                HV_PLANE_SWITCH_VTL_CALL :
                                HV_PLANE_SWITCH_INTERRUPT);
    env->mp_state = KVM_MP_STATE_RUNNABLE;
    cpu_synchronize_post_reset(vtl1);
    vtl1->stop = false;
    vtl1->stopped = false;
    qatomic_set(&pv->event_state, 0);
}

/* VTL0 thread: stop and schedule the VTL1 entry */
static void do_vtl0_upcall(CPUState *vtl0, run_on_cpu_data arg)
{
    CPUState *vtl1 = vtl_sibling(vtl0, 1);
    HvPlaneVcpu *pv = plane_vcpu(vtl1);

    trace_hyperv_vsm_plane_vtl_upcall(hyperv_vp_index(vtl0),
                                      qatomic_read(&pv->event_state),
                                      pv->event_handled);
    if (pv->event_handled) {
        return;
    }

    cpu_synchronize_state(vtl0);
    pv->event_handled = true;
    vtl0->stop = true;
    async_run_on_cpu(vtl1, do_vtl1_entry, RUN_ON_CPU_NULL);
}

/* VTL1 thread: park until KVM reports an event for it */
static void do_vtl1_poll(CPUState *vtl1, run_on_cpu_data arg)
{
    CPUX86State *env = &X86_CPU(vtl1)->env;

    vtl1->stop = false;
    vtl1->stopped = false;
    env->mp_state = KVM_MP_STATE_HV_INACTIVE_VTL;
    kvm_put_mp_state(X86_CPU(vtl1));
    trace_hyperv_vsm_plane_vtl_poll(hyperv_vp_index(vtl1));
}

/* VTL0 thread: take over from VTL1 after VtlReturn */
static void do_vtl0_downcall(CPUState *vtl0, run_on_cpu_data arg)
{
    CPUState *vtl1 = vtl_sibling(vtl0, 1);
    HvPlaneVcpu *pv = plane_vcpu(vtl1);

    trace_hyperv_vsm_plane_vtl_downcall(hyperv_vp_index(vtl0));

    hyperv_vsm_vtl_switch_state(vtl1, vtl0, HV_PLANE_SWITCH_VTL_RETURN);
    cpu_synchronize_post_reset(vtl0);
    pv->event_handled = false;
    vtl0->stop = false;
    vtl0->stopped = false;
    async_run_on_cpu(vtl1, do_vtl1_poll, RUN_ON_CPU_NULL);
}

int hv_plane_run_vtl(CPUState *cs, int target_vtl, HvPlaneSwitchReason reason)
{
    CPUState *target = vtl_sibling(cs, target_vtl);
    HvPlaneVcpu *pv;

    trace_hyperv_vsm_plane_run_vtl(hyperv_vp_index(cs), hv_plane_active_vtl(cs),
                                  target_vtl, reason);
    if (!target) {
        return -ENOENT;
    }

    switch (reason) {
    case HV_PLANE_SWITCH_VTL_CALL:
        pv = plane_vcpu(target);
        qatomic_set(&cs->stop, true);
        qatomic_or(&pv->event_state, VTL_CALL_PENDING);
        async_run_on_cpu(cs, do_vtl0_upcall, RUN_ON_CPU_NULL);
        return EXCP_HALTED;
    case HV_PLANE_SWITCH_VTL_RETURN:
        qatomic_set(&cs->stop, true);
        cpu_synchronize_state(cs);
        async_run_on_cpu(target, do_vtl0_downcall, RUN_ON_CPU_NULL);
        return EXCP_HALTED;
    case HV_PLANE_SWITCH_INTERCEPT:
        /* the SINT0 message wakes the parked VTL1 vCPU (hv_plane_vtl_event) */
        qatomic_set(&cs->stop, true);
        return EXCP_HALTED;
    case HV_PLANE_SWITCH_INTERRUPT:
        pv = plane_vcpu(target);
        qatomic_set(&cs->stop, true);
        qatomic_or(&pv->event_state, VTL_INTERRUPT_PENDING);
        async_run_on_cpu(cs, do_vtl0_upcall, RUN_ON_CPU_NULL);
        return EXCP_HALTED;
    default:
        g_assert_not_reached();
    }
}

int hv_plane_vtl_event(CPUState *cs, struct kvm_run *run)
{
    CPUX86State *env = &X86_CPU(cs)->env;
    HvPlaneVcpu *pv;
    CPUState *vtl0;

    if (run->exit_reason == KVM_EXIT_PLANE_EVENT) {
        /* D8 UAPI: @cs is the running lower plane */
        trace_hyperv_vsm_plane_stub("hv_plane_vtl_event",
                                    kvm_run_plane_event(run)->plane);
        return -ENOSYS;
    }

    /* current implementation: WAKEUP on the parked VTL1 vCPU itself */
    assert(env->mp_state == KVM_MP_STATE_HV_INACTIVE_VTL);
    trace_hyperv_vsm_plane_vcpu_event(hyperv_vp_index(cs),
                                      hv_plane_active_vtl(cs));

    pv = plane_vcpu(cs);
    qatomic_set(&cs->stop, true);

    /* a VTL call is already in flight; the interrupt is taken on entry */
    if (qatomic_read(&pv->event_state)) {
        return EXCP_HALTED;
    }

    /* cross-thread by design of this implementation; see the API contract */
    vtl0 = vtl_sibling(cs, 0);
    return hv_plane_run_vtl(vtl0, hv_plane_active_vtl(cs),
                            HV_PLANE_SWITCH_INTERRUPT);
}

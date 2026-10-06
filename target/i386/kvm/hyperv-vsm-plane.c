/*
 * Hyper-V VSM: plane API implementation (include/hw/hyperv/vsm-plane-api.h)
 *
 * This is the file the P4 class-B work rewrites against the KVM planes UAPI.
 * Today every operation that needs a plane returns -ENOSYS. Nicolas Saenz
 * Julienne's two-thread VTL switch (the inactive VTL parked in a private
 * MP state and woken through KVM_SYSTEM_EVENT_WAKEUP) is gone: with planes
 * the switch is one KVM_RUN per VTL on the same thread (D8 form: the plane
 * vCPU fd, or kvm_run->plane on the plane-0 fd).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
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

int hv_plane_run_vtl(CPUState *cs, int target_vtl, HvPlaneSwitchReason reason)
{
    trace_hyperv_vsm_plane_run_vtl(hyperv_vp_index(cs), hv_plane_active_vtl(cs),
                                  target_vtl, reason);
    return -ENOSYS;
}

void hv_plane_pre_run(CPUState *cs, struct kvm_run *run)
{
}

int hv_plane_vtl_event(CPUState *cs, struct kvm_run *run)
{
    trace_hyperv_vsm_plane_stub("hv_plane_vtl_event", run->plane_event.plane);
    return -ENOSYS;
}

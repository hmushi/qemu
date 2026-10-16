/*
 * Hyper-V VSM on KVM planes: the interface between the VSM layer and the
 * KVM plane that runs each VTL.
 *
 * "vtl" is both the TLFS VTL number and the KVM plane id; plane 0 is VTL0.
 * Every function runs on the vCPU thread of the calling CPUState unless
 * stated otherwise.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef HW_HYPERV_VSM_PLANE_API_H
#define HW_HYPERV_VSM_PLANE_API_H

#include "hw/core/cpu.h"
#include "exec/hwaddr.h"
#include "system/kvm.h"
#include "hw/pci/msi.h"
#include "hw/hyperv/vsm-kvm-abi-stub.h"
#include "hw/hyperv/hyperv-vsm-proto.h"

/* The VTL (KVM plane id) @cs runs in; 0 for a plane-0 vCPU. */
int hv_plane_active_vtl(CPUState *cs);

/*
 * The CPUState of VP @vp_index in VTL @vtl, or NULL if that VP has no vCPU
 * in that plane yet. The VP index is the cpu_index, so @vtl 0 is
 * qemu_get_cpu(@vp_index).
 */
CPUState *hv_plane_vcpu(uint32_t vp_index, int vtl);

/*
 * The KVMState for interrupt routing and MSR filters toward @cs's plane.
 * All planes share one KVMState and GSI routing table; a SINT route entry
 * names its plane.
 */
KVMState *hv_plane_kvm_state(CPUState *cs);

/*
 * Deliver @msg to the interrupt controller of @cs's plane (KVM_SIGNAL_MSI
 * on the plane fd; the VM fd for plane 0). Returns 0 or -errno.
 */
int hv_plane_send_msi(CPUState *cs, MSIMessage msg);

/*
 * Create the plane for @vtl (HvCallEnablePartitionVtl), or reuse one left
 * from before a system reset. Memory, clock and irqchip are shared with
 * plane 0. Returns 0 or -errno.
 */
int hv_plane_create(int vtl);

/*
 * Create the vCPU of VP @vp_index in plane @vtl (HvCallEnableVpVtl); may run
 * on another VP's thread. Pre: hv_plane_create(@vtl) done. Returns the new
 * CPUState in reset state, parked until hv_plane_run_vtl() first targets
 * it, a CPUState left from before a reset as is, or NULL on failure.
 */
CPUState *hv_plane_vcpu_create(uint32_t vp_index, int vtl);

/*
 * Let VP @vp_index run plane @start_vtl (HvCallStartVirtualProcessor). Call
 * with the BQL held, after the target context was loaded and pushed with
 * cpu_synchronize_post_reset(). Returns 0 or -errno.
 */
int hv_plane_vcpu_start(uint32_t vp_index, int start_vtl);

/* First step of a start, on the target vCPU's own thread. */
void hv_plane_select_start(CPUState *start);

/*
 * Restrict plane @vtl's access to [@addr, @addr + @size)
 * (HvCallModifyVtlProtectionMask). @attrs is a mask of
 * KVM_MEMORY_ATTRIBUTE_NR/NW/NX; 0 restores full access. A violating access
 * exits with KVM_EXIT_MEMORY_FAULT on the faulting vCPU. Returns 0 or
 * -errno.
 */
int hv_plane_set_memory_attrs(int vtl, hwaddr addr, hwaddr size,
                              uint64_t attrs);

/*
 * Move the TLFS-shared register state (TLFS 15.3.1) out of the plane vCPU
 * that stops and into the one that runs next. Export needs @cs's registers
 * synchronized; import is followed by cpu_synchronize_post_reset(). The VSM
 * layer implements both, since the field list is Hyper-V semantics.
 */
typedef struct HvVtlSharedState HvVtlSharedState;
void hv_plane_export_shared_state(CPUState *cs, HvVtlSharedState *state);
void hv_plane_import_shared_state(CPUState *cs, const HvVtlSharedState *state);

/* Why the VP changes VTL; the VSM layer turns it into the VTL entry reason. */
typedef enum HvPlaneSwitchReason {
    HV_PLANE_SWITCH_VTL_CALL,       /* HvCallVtlCall: VTL0 -> VTL1 */
    HV_PLANE_SWITCH_VTL_RETURN,     /* HvCallVtlReturn: VTL1 -> VTL0 */
    HV_PLANE_SWITCH_INTERCEPT,      /* memory intercept posted to VTL1 */
    HV_PLANE_SWITCH_INTERRUPT,      /* interrupt pending in a higher VTL */
} HvPlaneSwitchReason;

/*
 * Stop @cs's VTL and run the VP's plane @vtl for @reason, on the same host
 * thread, from inside the KVM exit handler. Pre: hv_plane_vcpu(vp, @vtl)
 * exists. Calls hyperv_vsm_vtl_switch_state() before the target runs.
 * Returns what kvm_arch_handle_exit() returns, or -errno.
 */
int hv_plane_run_vtl(CPUState *cs, int vtl, HvPlaneSwitchReason reason);

/*
 * Handle KVM_EXIT_PLANE_EVENT on running plane @cs. LOWER_INTERRUPT
 * notifies VINA and @cs keeps running; INTERRUPT switches to the highest
 * plane in run->plane_event.extra[0], since a higher VTL's interrupt
 * preempts a lower VTL (TLFS 15.3). Returns what kvm_arch_handle_exit()
 * returns.
 */
int hv_plane_vtl_event(CPUState *cs, struct kvm_run *run);

/*
 * Called by kvm_arch_pre_run() before KVM_RUN on a vCPU that has planes;
 * lowers a VINA line the guest acknowledged.
 */
void hv_plane_pre_run(CPUState *cs, struct kvm_run *run);

/*
 * System reset with VTLs enabled, every vCPU paused. Planes and plane vCPUs
 * persist for reuse; every VP runs plane 0 next.
 */
void hv_plane_reset(void);

/*
 * Walk the page tables of plane vCPU @cs (HvCallTranslateVirtualAddress).
 * The caller fills linear_address, flags and access in @tr; the result
 * fields come back filled. Returns 0 or -errno.
 */
int hv_plane_translate(CPUState *cs, struct kvm_translation2 *tr);

/*
 * Pin (@inhibit) or release the translations of plane vCPU @cs against
 * Hyper-V TLB flush hypercalls from other VPs. Returns 0 or -errno.
 */
int hv_plane_set_tlb_flush_inhibit(CPUState *cs, bool inhibit);

/* Target hooks behind hw/hyperv/vsm-planes.c, for HYPERV_VSM_PLANES. */

/* Whether this host can run plane @vtl; reports the reason when not. */
bool hv_plane_arch_host_supported(int vtl);
/* @plane is created, not yet realized: copy what it shares with @leader. */
void hv_plane_arch_vcpu_init(CPUState *plane, CPUState *leader);
/*
 * VTL switch: sync both register files, move the shared state from @cs to
 * @target keeping @target's private state, and push what the kernel needs
 * before @target's next KVM_RUN. Returns 0 or -errno.
 */
int hv_plane_arch_switch_state(CPUState *cs, CPUState *target,
                               HvPlaneSwitchReason reason);
/*
 * Whether VTL @cs wants lower-VTL interrupts reported (VINA, TLFS 15.2.3).
 * Called before each KVM_RUN of a plane > 0 vCPU; lowers a VINA line the
 * guest acknowledged.
 */
bool hv_plane_arch_vina_armed(CPUState *cs);
/* Assert VINA in @cs's VTL. */
void hv_plane_arch_vina_notify(CPUState *cs);
/*
 * Whether the target raises SINTs itself rather than through a GSI route;
 * true where the kernel has no SynIC (arm64).
 */
bool hv_plane_arch_sint_userspace(void);
/* Assert or deassert @sint's interrupt in @cs's plane; 0 or -errno. */
int hv_plane_arch_sint_set(CPUState *cs, uint32_t sint, bool level);

#endif /* HW_HYPERV_VSM_PLANE_API_H */

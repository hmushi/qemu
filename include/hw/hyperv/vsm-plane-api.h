/*
 * Hyper-V VSM on KVM planes: the plane API contract.
 *
 * This header is the interface between the Hyper-V VSM layer (the hypercall
 * handlers, VTL state and intercept builder in target/i386/kvm/hyperv-vsm.c,
 * plus the per-VTL SynIC routing in hw/hyperv/hyperv.c) and the KVM planes
 * plumbing that runs one plane per VTL. The VSM layer calls KVM only through
 * these functions. The implementation lives in
 * target/i386/kvm/hyperv-vsm-plane.c. Filling that file in against the P2
 * kernel UAPI is the P4 class-B work.
 *
 * Model (vsm-on-planes-phases.md, "QEMU layer", as corrected by workers A
 * and B): one plane per VTL, created lazily at HvCallEnablePartitionVtl; one
 * CPUState per plane per VP, the plane-N CPUState wrapping the plane vCPU fd
 * that KVM_CREATE_VCPU on the plane fd returned; a VTL switch moves the
 * TLFS-shared register state between the siblings and runs the target plane
 * on the same host thread; ModifyVtlProtectionMask is memory attributes
 * (NR/NW/NX) on the lower VTL's plane; a VTL0 fault on VTL1-protected memory
 * is a KVM_EXIT_MEMORY_FAULT with the RWX and PLANE flags; a VTL1 interrupt
 * while VTL0 runs is a plane event that ends VTL0's KVM_RUN. KVM names below
 * are the P2/P3 ones from vsm-kvm-abi-stub.h.
 *
 * The switch UAPI (D8): KVM_RUN on the plane-0 fd with kvm_run->plane
 * selecting the plane and req_exit_planes the planes whose pending
 * interrupt ends the run (KVM_CAP_PLANES_USERSPACE_SWITCH).
 *
 * Requirements the implementation must meet (from the kvm-unit-tests
 * baseline, worker B, B4/B5):
 *  1. CPU properties: hv-vsm (CPUID 0x40000003 EBX bits 16, 17, 21),
 *     hv-xmm-input (EDX bit 4), hv-xmm-output (EDX bit 15, depends on
 *     hv-xmm-input; KVM_CAP_HYPERV_VSM on the VM). No machine option; VTL1
 *     exists only after the guest's EnablePartitionVtl.
 *  2. Shared versus private VP state (TLFS 15.3.1): every switch moves the
 *     shared state between the siblings through hv_plane_export_shared_state()
 *     and hv_plane_import_shared_state(); the private state stays with the
 *     plane vCPU (RIP, RSP, RFLAGS, CR0/CR3/CR4, segment registers, IDT, GDT,
 *     LDT, TR, all MSRs including the Hyper-V ones, the LAPIC).
 *  3. A fresh plane vCPU's LAPIC is a reset-state xAPIC with the sibling's
 *     APIC ID; VP0's VTL1 LAPIC carries the BSP bit. hyperv-vsm.c forces
 *     the BSP bit and SPIV today; the implementation may do it instead.
 *  4. The VP index is shared across VTLs (one cpu_index per VP, every
 *     plane). The reference TSC page content is one per partition: both
 *     VTLs' HV_X64_MSR_REFERENCE_TSC mappings must show the same page
 *     (the only failing test on Nicolas's stack, because his VTL1 was a
 *     separate VM; planes must make it pass).
 *  5. TLB lock: KVM_HYPERV_SET_TLB_FLUSH_INHIBIT on the plane-0 vCPU when
 *     TranslateVirtualAddress asks for it, cleared on VtlReturn
 *     (hv_plane_set_tlb_flush_inhibit()).
 *  6. The GPA intercept message is built from the plane-0 vCPU's post-fault
 *     state (RFLAGS.RF set) plus instruction bytes read at RIP; it needs the
 *     RWX flags from the exit; the instruction length is decoded in QEMU.
 *  7. The hypercall page is per VTL, installed through the HV_X64_MSR_HYPERCALL
 *     filter, with the VTL call and return prologues at the offsets that
 *     HvRegisterVsmCodePageOffsets (0x000D0002) reports.
 *  8. Reset with VTL1 enabled is class D ("TODO VSM RESET" in Nicolas's
 *     tree): nothing here handles it yet.
 *
 * Every function is callable from the vCPU thread of the calling CPUState
 * unless stated otherwise. "vtl" is the TLFS VTL number and the KVM plane
 * id; plane 0 is VTL0, the vCPU QEMU created at machine init.
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

/*
 * hv_plane_active_vtl: the VTL (plane id) a CPUState runs in.
 *
 * Called by every handler to find the caller's VTL, by hw/hyperv/hyperv.c to
 * name per-VTL SynIC pages, and by kvm.c to pick the first vCPU of a VTL
 * for partition-wide MSRs. Plane-0 CPUStates return 0. Was
 * X86_CPU(cs)->namespace in Nicolas's series. Maps to the plane id the
 * CPUState's vCPU fd was created on; no ioctl.
 */
int hv_plane_active_vtl(CPUState *cs);

/*
 * hv_plane_vcpu: sibling lookup, the CPUState of VP @vp_index in VTL @vtl.
 *
 * Called by Get/SetVpRegisters, TranslateVirtualAddress,
 * GetVpIndexFromApicId, StartVirtualProcessor, EnableVpVtl, the VTL switch
 * and hyperv_sint_route_new(). Returns NULL when that VP has no vCPU in
 * that plane yet (EnableVpVtl not run); callers turn NULL into
 * HV_STATUS_INVALID_VP_INDEX or _INVALID_PARAMETER. @vtl 0 is
 * qemu_get_cpu(vp_index): the Hyper-V VP index is the cpu_index
 * (hyperv_vp_index()), as for the rest of hw/hyperv. No ioctl.
 */
CPUState *hv_plane_vcpu(uint32_t vp_index, int vtl);

/*
 * hv_plane_kvm_state: the KVMState through which interrupt routing toward
 * @cs's plane goes.
 *
 * Called by hyperv_sint_route_new()/unref() for KVM_SET_GSI_ROUTING and the
 * irqfd, and by hyperv_vsm_init_vcpu() for KVM_X86_SET_MSR_FILTER. Was
 * cs->kvm_state (one KVMState per companion VM). Under planes there is one
 * KVMState and one GSI routing table on the VM fd; a SINT route entry names
 * its plane (kvm_irq_routing_hv_sint.plane), so this returns kvm_state.
 * KVM_X86_SET_MSR_FILTER is a VM ioctl shared by all planes; the handler
 * dispatches on the faulting vCPU's plane.
 */
KVMState *hv_plane_kvm_state(CPUState *cs);

/*
 * hv_plane_send_msi: deliver @msg to the LAPIC of @cs's plane (the VINA
 * vector of a higher VTL). Maps to KVM_SIGNAL_MSI on the plane fd; plane 0
 * uses the VM fd. Returns 0 or -errno.
 */
int hv_plane_send_msi(CPUState *cs, MSIMessage msg);

/*
 * hv_plane_create: create the plane for @vtl (HvCallEnablePartitionVtl).
 *
 * Called once per VTL by hyperv_hcall_vtl_enable_partition_vtl() after the
 * TLFS checks pass, from the calling VP's thread. A plane left over from
 * before a system reset is reused. Post: plane fd kept by the
 * implementation; memory, clock and
 * irqchip are shared with plane 0 by construction. Maps to
 * KVM_CREATE_PLANE(@vtl) on the VM fd. Returns 0 or -errno; the handler
 * reports HV_STATUS_INVALID_PARAMETER on failure. Was kvm_init_companion_vm()
 * + hyperv_kvm_init_vsm() (second KVM VM, second memory listener, clock
 * sync).
 */
int hv_plane_create(int vtl);

/*
 * hv_plane_vcpu_create: create the vCPU of VP @vp_index in plane @vtl
 * (HvCallEnableVpVtl).
 *
 * Called by hyperv_hcall_vtl_enable_vp_vtl() from the requesting VP's
 * thread, which may be another VP. Pre: hv_plane_create(@vtl) done, the
 * plane-0 CPUState of @vp_index exists. A CPUState for (@vp_index, @vtl)
 * left over from before a system reset is returned as is (reset state).
 * Post: a realized CPUState whose kvm fd is the plane vCPU, with its
 * own SynIC and VpVsm children (the caller adds them through
 * hyperv_vsm_init_vcpu() during cpu realize), LAPIC in reset state with
 * the sibling's APIC ID (requirement 3), parked until hv_plane_run_vtl()
 * first targets it; the caller then loads the initial VP context and calls
 * cpu_synchronize_post_reset() on it. Maps to KVM_CREATE_VCPU(@vp_index) on
 * the plane fd, issued from the plane-0 sibling's thread (run_on_cpu)
 * because the kvm_run page and the preempt notifier are shared with the
 * sibling. Returns NULL on failure. Was x86_cpu_new(x86ms, ns=vtl,
 * kvm_state[vtl], apic_id) plus the vmstate id, hotplug and SMM-listener
 * workarounds for the second X86CPU.
 */
CPUState *hv_plane_vcpu_create(uint32_t vp_index, int vtl);

/*
 * hv_plane_vcpu_reset: put the plane vCPU @cs through INIT so a new VP
 * context can be loaded (HvCallStartVirtualProcessor).
 *
 * Called by hyperv_hcall_start_virtual_processor() with the BQL held (@cs
 * runs on another thread), @cs stopped. Post: @cs's architectural state is
 * the INIT state, KVM told.
 * Maps to the QEMU reset path on the plane CPUState (do_cpu_init), which
 * ends in KVM_SET_REGS/SREGS/MP_STATE on the plane vCPU fd. Returns 0 or
 * -errno.
 */
int hv_plane_vcpu_reset(CPUState *cs);

/*
 * hv_plane_vcpu_start: let VP @vp_index run, in its highest enabled VTL
 * (HvCallStartVirtualProcessor, after the context load).
 *
 * Called by hyperv_hcall_start_virtual_processor() with the BQL held. Pre:
 * the context of the target VTL was loaded and pushed with
 * cpu_synchronize_post_reset(). Post:
 * the VP's thread runs plane @start_vtl. Maps to cpu_resume() of the VP's
 * thread with plane @start_vtl selected (hv_plane_run_vtl() semantics).
 * Returns 0 or -errno.
 */
int hv_plane_vcpu_start(uint32_t vp_index, int start_vtl);

/*
 * hv_plane_set_memory_attrs: restrict plane @vtl's access to
 * [@addr, @addr + @size) (HvCallModifyVtlProtectionMask).
 *
 * Called by hyperv_set_memory_attrs() once per coalesced GFN range, from
 * the calling VP's thread, @vtl strictly lower than the caller's VTL.
 * @attrs is a mask of KVM_MEMORY_ATTRIBUTE_NR / NW / NX (Paolo's 2026-07
 * names, vsm-kvm-abi-stub.h); 0 restores full access. Post: a plane-@vtl
 * access violating @attrs produces a KVM_EXIT_MEMORY_FAULT with the RWX
 * and PLANE flags on the faulting plane-@vtl vCPU, which kvm.c hands to
 * kvm_hv_handle_fault(). Maps to KVM_SET_PLANE_MEMORY_ATTRIBUTES on the VM
 * fd for plane @vtl. Returns 0 or -errno. Was
 * KVM_SET_MEMORY_ATTRIBUTES with NR/NW/NX on the companion VM fd of @vtl.
 */
int hv_plane_set_memory_attrs(int vtl, hwaddr addr, hwaddr size,
                              uint64_t attrs);

/*
 * hv_plane_export_shared_state / hv_plane_import_shared_state: move the
 * TLFS-shared register state of a VP out of one plane vCPU and into its
 * sibling (TLFS 15.3.1; requirement 2).
 *
 * Called by the plane layer around every switch: export from the plane that
 * stops, import into the plane that runs next, both with that CPUState's
 * register file synchronized (cpu_synchronize_state() before export,
 * cpu_synchronize_post_reset() after import). Implemented by the VSM layer
 * (hyperv-vsm.c) because the field list is Hyper-V semantics:
 *   shared: RAX RBX RCX RDX RSI RDI RBP R8-R15 (not RSP), DR0-DR5, CR2,
 *           XCR0, MTRRs (fixed, variable, default type), MCG_CAP and
 *           MCG_STATUS, HV_X64_MSR_VP_RUNTIME, the FPU/SSE state (x87
 *           registers, control and status, XMM,
 *           MXCSR, XSTATE_BV); VP0 keeps the APIC BSP bit in every plane.
 *   private (stays with the plane vCPU): RIP RSP RFLAGS, CR0 CR3 CR4, DR6
 *           DR7, segment registers, IDTR GDTR LDTR TR, EFER, SYSENTER_*,
 *           STAR LSTAR CSTAR SFMASK, FS/GS base, KERNEL_GS_BASE, TSC_AUX,
 *           PAT, the Hyper-V MSRs (SynIC, STIMER, hypercall, VP assist,
 *           REFERENCE_TSC: the page GPA is per VTL, its content is
 *           partition-wide), the LAPIC.
 * No ioctl: the copy is between the two QEMU register files.
 */
typedef struct HvVtlSharedState HvVtlSharedState;
void hv_plane_export_shared_state(CPUState *cs, HvVtlSharedState *state);
void hv_plane_import_shared_state(CPUState *cs, const HvVtlSharedState *state);

/*
 * Why the VP changes VTL. Carried into the TLFS VTL entry reason by the
 * VSM layer (hyperv_vsm_vtl_switch_state()); the plane layer only routes.
 */
typedef enum HvPlaneSwitchReason {
    HV_PLANE_SWITCH_VTL_CALL,       /* HvCallVtlCall: VTL0 -> VTL1 */
    HV_PLANE_SWITCH_VTL_RETURN,     /* HvCallVtlReturn: VTL1 -> VTL0 */
    HV_PLANE_SWITCH_INTERCEPT,      /* memory intercept posted to VTL1 */
    HV_PLANE_SWITCH_INTERRUPT,      /* interrupt pending in a higher VTL */
} HvPlaneSwitchReason;

/*
 * hv_plane_run_vtl: stop running @cs's VTL and run VP's plane @vtl instead,
 * for @reason. (run_vtl(vcpu, vtl) in worker A's terms.)
 *
 * Called from @cs's own thread, from inside the KVM exit handler, by
 * hyperv_hcall_vtl_call() (vtl = 1), hyperv_hcall_vtl_return() (vtl = 0),
 * kvm_hv_handle_fault() (vtl = 1, INTERCEPT) and hv_plane_vtl_event()
 * (vtl = the plane with the pending interrupt). Pre: hv_plane_vcpu(vp, @vtl)
 * exists. Post: before the target plane runs, the implementation has called
 * hyperv_vsm_vtl_switch_state(@cs, target, @reason), which does the shared
 * state export/import and writes the VP assist page vtl_control; the return
 * value is what kvm_arch_handle_exit() returns (EXCP_HALTED or
 * EXCP_INTERRUPT: leave the run loop for this plane) or -errno.
 * Implementation (D8): KVM_RUN on the plane-0 fd with kvm_run->plane = @vtl
 * and req_exit_planes = planes above @vtl, on the VP's one host thread.
 */
int hv_plane_run_vtl(CPUState *cs, int vtl, HvPlaneSwitchReason reason);

/*
 * hv_plane_vtl_event: KVM reported that a VTL of this VP other than the
 * running one has a pending event. (wait_for_vtl_event() in worker A's
 * terms: the run loop returned because of it.)
 *
 * Called by kvm.c from the KVM exit path of the vCPU that reported it:
 * KVM_EXIT_PLANE_EVENT on the running plane's KVM_RUN, @cs the running
 * plane, the planes in run->plane_event.extra[0] (a req_exit_planes
 * bitmap). Cause LOWER_INTERRUPT: a lower plane's interrupt became pending,
 * VINA notifies @cs and it keeps running. Cause INTERRUPT: the
 * implementation calls
 * hv_plane_run_vtl(@cs, highest such plane, HV_PLANE_SWITCH_INTERRUPT),
 * because a higher VTL's interrupt preempts a lower VTL (TLFS 15.3) and a
 * lower VTL's interrupt waits.
 * Returns what kvm_arch_handle_exit() returns.
 */
int hv_plane_vtl_event(CPUState *cs, struct kvm_run *run);

/*
 * hv_plane_pre_run: called by kvm_arch_pre_run() right before KVM_RUN on a
 * CPUState that has planes (a leader with plane vCPUs, or a plane vCPU).
 * Writes kvm_run->req_exit_planes: the higher planes (their interrupt ends
 * this run, hv_plane_vtl_event() switches) and, when this VTL has VINA
 * armed (hyperv_vsm_vina_armed()), the lower planes (their interrupt is
 * notified with hyperv_vsm_vina_notify(), this plane keeps running).
 * accel/kvm writes kvm_run->plane. No ioctl.
 */
void hv_plane_pre_run(CPUState *cs, struct kvm_run *run);

/*
 * hv_plane_reset: system reset with VTLs enabled. Called by the VSM layer's
 * reset handler with every vCPU paused. KVM planes and plane vCPUs persist
 * (hv_plane_create()/hv_plane_vcpu_create() hand them out again when the
 * guest re-enables the VTLs); the plane vCPUs' registers were reset by
 * their own CPU reset. Post: every VP's thread runs plane 0 next.
 */
void hv_plane_reset(void);

/*
 * hv_plane_translate: walk the page tables of plane vCPU @cs
 * (HvCallTranslateVirtualAddress).
 *
 * Called by hyperv_hcall_translate_virtual_address() for the target VP and
 * VTL. @tr is filled in by the caller (linear_address, flags, access) and
 * returned with physical_address, valid, error_code, set_bits_succeeded.
 * Maps to KVM_TRANSLATE2 on the plane vCPU fd (per-vCPU ioctl, no plane
 * logic). Returns 0 or -errno.
 */
int hv_plane_translate(CPUState *cs, struct kvm_translation2 *tr);

/*
 * hv_plane_set_tlb_flush_inhibit: pin or release the translations of plane
 * vCPU @cs against Hyper-V TLB flush hypercalls from other VPs
 * (requirement 5).
 *
 * Called by hyperv_hcall_translate_virtual_address() (set, when the input
 * has HV_TRANSLATE_GVA_TLB_FLUSH_INHIBIT) and hyperv_hcall_vtl_return()
 * (clear), always on the plane-0 sibling of the caller. Maps to
 * KVM_HYPERV_SET_TLB_FLUSH_INHIBIT on the plane vCPU fd. Returns 0 or
 * -errno.
 */
int hv_plane_set_tlb_flush_inhibit(CPUState *cs, bool inhibit);

#endif /* HW_HYPERV_VSM_PLANE_API_H */

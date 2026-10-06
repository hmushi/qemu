/*
 * QEMU KVM Hyper-V Virtual Secure Mode (VSM) support
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TARGET_I386_KVM_HYPERV_VSM_H
#define TARGET_I386_KVM_HYPERV_VSM_H

#include "cpu.h"
#include "system/kvm.h"
#include "hw/hyperv/hyperv-vsm-proto.h"
#include "hw/hyperv/vsm-plane-api.h"

/* per-vCPU VSM state (VP assist page, hypercall page, VTL config) */
int hyperv_vsm_init_vcpu(X86CPU *cpu);

/* hypercall handlers, called from kvm_hv_handle_exit() */
uint16_t hyperv_hcall_vtl_enable_partition_vtl(CPUState *cs, uint64_t param1,
                                               uint64_t param2, bool fast);
uint16_t hyperv_hcall_vtl_enable_vp_vtl(CPUState *cs, uint64_t param,
                                        bool fast);
int hyperv_hcall_vtl_call(CPUState *cs);
int hyperv_hcall_vtl_return(CPUState *cs);
uint64_t hyperv_hcall_get_set_vp_register(CPUState *cs,
                                          struct kvm_hyperv_exit *exit,
                                          bool set);
uint64_t hyperv_hcall_vtl_protection_mask(CPUState *cs,
                                          struct kvm_hyperv_exit *exit);
uint64_t hyperv_hcall_translate_virtual_address(CPUState *cs,
                                                struct kvm_hyperv_exit *exit);
uint64_t hyperv_hcall_send_ipi(CPUState *cs, int code,
                               struct kvm_hyperv_exit *exit);
uint64_t hyperv_hcall_get_vp_index_from_apic_id(CPUState *cs,
                                                struct kvm_hyperv_exit *exit);
uint64_t hyperv_hcall_start_virtual_processor(CPUState *cs,
                                              struct kvm_hyperv_exit *exit);

/* RWX memory fault on a lower VTL: build and post the GPA intercept */
int kvm_hv_handle_fault(CPUState *cs, uint64_t gpa, uint64_t size,
                        uint64_t flags);

/* hyperv-vsm-insn.c: length of the x86 instruction at @buf, 0 if unknown */
int hyperv_vsm_insn_len(const uint8_t *buf, int len, int mode);

/* TLFS 15.3.1 VTL-shared VP state; see hv_plane_export_shared_state() */
struct HvVtlSharedState {
    target_ulong regs[CPU_NB_EREGS];    /* RSP is not copied */
    target_ulong dr[6];
    target_ulong cr2;
    uint64_t xcr0;
    uint64_t mtrr_fixed[11];
    uint64_t mtrr_deftype;
    MTRRVar mtrr_var[MSR_MTRRcap_VCNT];
    uint64_t mcg_cap;
    uint64_t mcg_status;
    uint64_t msr_hv_tsc;
    uint64_t msr_hv_runtime;
    unsigned int fpstt;
    uint16_t fpus;
    uint16_t fpuc;
    uint8_t fptags[8];
    FPReg fpregs[8];
    uint16_t fpop;
    uint16_t fpcs;
    uint16_t fpds;
    uint64_t fpip;
    uint64_t fpdp;
    uint32_t mxcsr;
    ZMMReg xmm_regs[CPU_NB_EREGS] QEMU_ALIGNED(16);
    uint64_t xstate_bv;
};

/*
 * Called by the plane layer right before it runs @next instead of @prev:
 * moves the VTL-shared register state (export from @prev, import into
 * @next) and writes the VTL entry reason into @next's VP assist page, or on
 * a return restores RAX/RCX from @prev's vtl_control.
 */
void hyperv_vsm_vtl_switch_state(CPUState *prev, CPUState *next,
                                 HvPlaneSwitchReason reason);

#endif /* TARGET_I386_KVM_HYPERV_VSM_H */

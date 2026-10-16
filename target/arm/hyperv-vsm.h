/*
 * Hyper-V VSM on arm64: what target/arm/kvm.c calls into.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TARGET_ARM_HYPERV_VSM_H
#define TARGET_ARM_HYPERV_VSM_H

#include "hw/core/cpu.h"
#include "system/kvm.h"

/*
 * VM init: enables the HVC #2/#3 exits and KVM_CAP_HYPERV_VSM when the
 * host has planes; without them VSM stays off and this returns 0.
 */
int hyperv_vsm_arm_init(KVMState *s);

/* per-vCPU VSM state; registers the reset handler on the first VP */
int hyperv_vsm_arm_init_vcpu(CPUState *cs);

/* true once hyperv_vsm_arm_init() enabled VSM on this VM */
bool hyperv_vsm_arm_enabled(void);

/*
 * KVM_EXIT_HYPERCALL with KVM_HYPERCALL_EXIT_HVC_IMM: HVC #2 is a VTL call,
 * HVC #3 a VTL return (TLFS "On ARM64 Platforms"). Returns 0, EXCP_INTERRUPT
 * when the thread must leave this plane's run loop, or negative on error.
 * A refused switch sets hypercall.ret so the kernel injects an UNDEF.
 */
int hyperv_vsm_arm_handle_hvc_imm(CPUState *cs, struct kvm_run *run);

#endif

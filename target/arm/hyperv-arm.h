/*
 * Hyper-V hypercall front end on arm64: the contract between the dispatcher
 * in target/arm/kvm.c and the VSM layer behind it.
 *
 * Fast calls (TLFS "Hypercall Register Conventions"): x0 control input,
 * x1..x17 fast input block; x0 on return is (reps << 32) | status. KVM has
 * already advanced the PC.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TARGET_ARM_HYPERV_ARM_H
#define TARGET_ARM_HYPERV_ARM_H

#include "hw/core/cpu.h"
#include "system/kvm.h"

/*
 * A hypercall handler: @cs is the calling vCPU, its plane the calling VTL;
 * registers are read through CPUARMState after cpu_synchronize_state().
 * Returns the HV_STATUS_* code, with reps completed at
 * HV_HYPERCALL_REP_COMP_OFFSET for a rep call.
 */
typedef uint64_t (*hv_arm_hcall_fn)(CPUState *cs, struct kvm_run *run);

/*
 * Register @fn for call @code in the dispatcher's table. Called at target
 * init, before any vCPU runs. Re-registering a code is an error.
 */
int hv_arm_register_hcall(uint16_t code, hv_arm_hcall_fn fn);

/* The handler registered for @code, or NULL. */
hv_arm_hcall_fn hv_arm_hcall_handler(uint16_t code);

#endif

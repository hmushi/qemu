/*
 * Hyper-V VSM on arm64: stand-ins for a build without CONFIG_HYPERV.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/log.h"
#include "hw/hyperv/hyperv-proto.h"
#include "hyperv-arm.h"
#include "hyperv-vsm.h"

int hyperv_vsm_arm_init(KVMState *s)
{
    return 0;
}

int hyperv_vsm_arm_init_vcpu(CPUState *cs)
{
    return 0;
}

bool hyperv_vsm_arm_enabled(void)
{
    return false;
}

#ifdef CONFIG_KVM
int hyperv_vsm_arm_handle_hvc_imm(CPUState *cs, struct kvm_run *run)
{
    qemu_log_mask(LOG_UNIMP, "kvm: HVC #%" PRIu64 " exit without VSM support\n",
                  (uint64_t)run->hypercall.nr);
    run->hypercall.ret = 1;
    return 0;
}
#endif

uint16_t hv_arm_vp_register_fallback(bool set, uint32_t vp, int vtl,
                                     uint32_t name, uint64_t value[2])
{
    return HV_STATUS_INVALID_PARAMETER;
}

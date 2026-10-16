/*
 * Hyper-V hypercall handler table on arm64 for the VSM layer.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "hw/hyperv/hyperv-proto.h"
#include "hyperv-arm.h"

#define HV_ARM_HCALL_MAX 32

static struct {
    uint16_t code;
    hv_arm_hcall_fn fn;
} hv_arm_hcalls[HV_ARM_HCALL_MAX];
static unsigned hv_arm_nr_hcalls;

int hv_arm_register_hcall(uint16_t code, hv_arm_hcall_fn fn)
{
    if (hv_arm_hcall_handler(code)) {
        error_report("hyperv: hypercall 0x%x registered twice", code);
        return -EEXIST;
    }
    if (hv_arm_nr_hcalls == HV_ARM_HCALL_MAX) {
        return -ENOSPC;
    }
    hv_arm_hcalls[hv_arm_nr_hcalls].code = code;
    hv_arm_hcalls[hv_arm_nr_hcalls].fn = fn;
    hv_arm_nr_hcalls++;
    return 0;
}

hv_arm_hcall_fn hv_arm_hcall_handler(uint16_t code)
{
    for (unsigned i = 0; i < hv_arm_nr_hcalls; i++) {
        if (hv_arm_hcalls[i].code == code) {
            return hv_arm_hcalls[i].fn;
        }
    }
    return NULL;
}

/*
 * Hyper-V VSM plane API: stand-ins for a target without KVM planes, so the
 * per-VTL SynIC routing in hyperv.c resolves to VTL0 alone.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "system/kvm.h"
#include "hw/core/cpu.h"
#include "hw/hyperv/vsm-plane-api.h"

int hv_plane_active_vtl(CPUState *cs)
{
    return 0;
}

CPUState *hv_plane_vcpu(uint32_t vp_index, int vtl)
{
    return vtl == 0 ? qemu_get_cpu(vp_index) : NULL;
}

KVMState *hv_plane_kvm_state(CPUState *cs)
{
    return kvm_state;
}

bool hv_plane_arch_sint_userspace(void)
{
    return false;
}

int hv_plane_arch_sint_set(CPUState *cs, uint32_t sint, bool level)
{
    return -ENOSYS;
}

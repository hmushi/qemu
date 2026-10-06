/*
 * Stubs for CONFIG_HYPERV=n
 *
 * Copyright (c) 2015-2018 Virtuozzo International GmbH.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "hyperv.h"
#include "hyperv-vsm.h"

#ifdef CONFIG_KVM
int kvm_hv_handle_exit(X86CPU *cpu, struct kvm_hyperv_exit *exit)
{
    switch (exit->type) {
    case KVM_EXIT_HYPERV_SYNIC:
        if (!hyperv_feat_enabled(cpu, HYPERV_FEAT_SYNIC)) {
            return -1;
        }

        /*
         * Tracking the changes in the MSRs is unnecessary as there are no
         * users for them beside save/load, which is handled nicely by the
         * generic MSR save/load code
         */
        return 0;
    case KVM_EXIT_HYPERV_HCALL:
        exit->u.hcall.result = HV_STATUS_INVALID_HYPERCALL_CODE;
        return 0;
    case KVM_EXIT_HYPERV_SYNDBG:
        if (!hyperv_feat_enabled(cpu, HYPERV_FEAT_SYNDBG)) {
            return -1;
        }

        return 0;
    default:
        return -1;
    }
}

int kvm_hv_handle_fault(CPUState *cs, uint64_t gpa, uint64_t size,
                        uint64_t flags)
{
    return -1;
}

int hv_plane_vtl_event(CPUState *cs, struct kvm_run *run)
{
    return -1;
}

void hv_plane_pre_run(CPUState *cs, struct kvm_run *run)
{
}

CPUState *hv_plane_vcpu(uint32_t vp_index, int vtl)
{
    return vtl == 0 ? qemu_get_cpu(vp_index) : NULL;
}

void hv_plane_reset(void)
{
}

int hv_plane_send_msi(CPUState *cs, MSIMessage msg)
{
    return -ENOSYS;
}
#endif

int hyperv_vsm_init_vcpu(X86CPU *cpu)
{
    return -ENOSYS;
}

int hyperv_x86_synic_add(X86CPU *cpu)
{
    return -ENOSYS;
}

void hyperv_x86_synic_reset(X86CPU *cpu)
{
}

void hyperv_x86_synic_update(X86CPU *cpu)
{
}

void hyperv_x86_set_vmbus_recommended_features_enabled(void)
{
}

uint64_t hyperv_syndbg_query_options(void)
{
    return 0;
}

int hyperv_enable_synic(X86CPU *cpu)
{
    return 0;
}

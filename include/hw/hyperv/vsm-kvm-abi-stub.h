/*
 * Hyper-V VSM: KVM ABI the VSM layer needs and the imported linux-headers do
 * not carry yet.
 *
 * linux-headers/ is synced from the planes-vsm-p3 kernel branch (Joerg
 * Roedel's KVM planes series, Paolo Bonzini's memory protection attributes
 * RFC, KVM_SET_PLANE_MEMORY_ATTRIBUTES, KVM_TRANSLATE2, the TLB flush
 * inhibit, MP state on plane vCPUs, the userspace plane switch and the
 * Hyper-V VSM hypercall exits), so the kernel ABI comes from <linux/kvm.h>.
 * What remains here are accessors for the XMM hypercall payload and the RWX
 * fault flag mask.
 *
 * Nothing here may redefine a struct that linux/kvm.h already has.
 */
#ifndef HW_HYPERV_VSM_KVM_ABI_STUB_H
#define HW_HYPERV_VSM_KVM_ABI_STUB_H

#include <linux/kvm.h>

#define KVM_MEMORY_EXIT_FLAG_RWX            (KVM_MEMORY_EXIT_FLAG_READ | \
                                             KVM_MEMORY_EXIT_FLAG_WRITE | \
                                             KVM_MEMORY_EXIT_FLAG_EXEC)
/* XMM0..XMM5 of a fast call travel in u.hcall.xmm[] */
#define HV_HYPERCALL_MAX_XMM_REGISTERS      6

/*
 * KVM_EXIT_HYPERV_HCALL (2) is a fast call without XMM payload or a
 * memory-form call; KVM_EXIT_HYPERV_HCALL_XMM (4) carries XMM0..XMM5 in
 * u.hcall.xmm[] and is used only for fast calls of the codes that take XMM
 * input (ModifyVtlProtectionMask, Get/SetVpRegisters,
 * TranslateVirtualAddress, GetVpIndexFromApicId). Handlers read or write
 * xmm[] only when hv_exit_has_xmm().
 */
static inline bool hv_exit_has_xmm(const struct kvm_hyperv_exit *exit)
{
    return exit->type == KVM_EXIT_HYPERV_HCALL_XMM;
}

static inline struct kvm_hyperv_xmm_reg *
hv_exit_xmm(struct kvm_hyperv_exit *exit)
{
    return exit->u.hcall.xmm;
}

/* 64-bit half @i (0..11) of the XMM payload, low half first */
static inline uint64_t hv_exit_xmm_get(struct kvm_hyperv_exit *exit, int i)
{
    struct kvm_hyperv_xmm_reg *xmm = hv_exit_xmm(exit);

    return (i & 1) ? xmm[i >> 1].high : xmm[i >> 1].low;
}

static inline void hv_exit_xmm_set(struct kvm_hyperv_exit *exit, int i,
                                   uint64_t val)
{
    struct kvm_hyperv_xmm_reg *xmm = hv_exit_xmm(exit);

    if (i & 1) {
        xmm[i >> 1].high = val;
    } else {
        xmm[i >> 1].low = val;
    }
}

#endif /* HW_HYPERV_VSM_KVM_ABI_STUB_H */

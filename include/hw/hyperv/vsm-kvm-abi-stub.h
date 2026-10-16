/*
 * Hyper-V VSM: XMM hypercall payload accessors and the RWX fault flag mask
 * over <linux/kvm.h>. Nothing here may redefine a linux/kvm.h struct.
 */
#ifndef HW_HYPERV_VSM_KVM_ABI_STUB_H
#define HW_HYPERV_VSM_KVM_ABI_STUB_H

#include <linux/kvm.h>

#define KVM_MEMORY_EXIT_FLAG_RWX            (KVM_MEMORY_EXIT_FLAG_READ | \
                                             KVM_MEMORY_EXIT_FLAG_WRITE | \
                                             KVM_MEMORY_EXIT_FLAG_EXEC)
/* XMM0..XMM5 of a fast call travel in u.hcall.xmm[] */
#define HV_HYPERCALL_MAX_XMM_REGISTERS      6

#ifdef KVM_EXIT_HYPERV_HCALL_XMM
/*
 * Only KVM_EXIT_HYPERV_HCALL_XMM, a fast call of a code that takes XMM
 * input, carries a valid u.hcall.xmm[]; handlers touch xmm[] only when
 * hv_exit_has_xmm().
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
#else
/*
 * No XMM payload in this KVM ABI: XMM fast calls are rejected, and arm64
 * passes register-fast input through the hv_vsm_arch_ops register forms.
 */
static inline bool hv_exit_has_xmm(const struct kvm_hyperv_exit *exit)
{
    return false;
}

static inline uint64_t hv_exit_xmm_get(struct kvm_hyperv_exit *exit, int i)
{
    return 0;
}

static inline void hv_exit_xmm_set(struct kvm_hyperv_exit *exit, int i,
                                   uint64_t val)
{
}
#endif

#endif /* HW_HYPERV_VSM_KVM_ABI_STUB_H */

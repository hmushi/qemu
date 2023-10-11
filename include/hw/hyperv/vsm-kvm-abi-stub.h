/*
 * Hyper-V VSM: KVM ABI additions that are not in the imported linux-headers.
 *
 * Each item here is a kernel ABI dependency of the VSM code in hw/hyperv and
 * target/i386/kvm. Names and values follow Nicolas Saenz Julienne's kernel
 * branch vianpl/vsm/next (v6.12-64-g7b4394fa3776e) unless marked otherwise.
 * When the real header provides an item, the kernel copy wins.
 *
 * Do not add anything that redefines a struct already in linux/kvm.h.
 */
#ifndef HW_HYPERV_VSM_KVM_ABI_STUB_H
#define HW_HYPERV_VSM_KVM_ABI_STUB_H

#include <linux/kvm.h>

/* needs kernel ABI: KVM_CAP_HYPERV_XMM_EXIT (242), KVM_EXIT_HYPERV_HCALL_XMM
 * and `struct kvm_hyperv_xmm_reg xmm[6]` after hcall.params[] in
 * struct kvm_hyperv_exit. The imported header has neither. */
#ifndef KVM_EXIT_HYPERV_HCALL_XMM
#define KVM_EXIT_HYPERV_HCALL_XMM      4
#endif
#ifndef HV_HYPERCALL_MAX_XMM_REGISTERS
#define HV_HYPERCALL_MAX_XMM_REGISTERS 6
#endif
#ifndef KVM_CAP_HYPERV_XMM_EXIT
#define KVM_CAP_HYPERV_XMM_EXIT 242
#endif
/*
 * Layout-compatible view of the extended hcall exit payload. The kernel
 * places xmm[6] (low, high pairs) right after params[2]; the union padding
 * in struct kvm_run (256 bytes) covers it. The stock struct ends at
 * params[2], so index past it through this accessor only when the exit
 * type is KVM_EXIT_HYPERV_HCALL_XMM or the hypercall is a fast call on a
 * kernel that advertises KVM_CAP_HYPERV_XMM_EXIT.
 */
static inline __u64 *hv_exit_xmm(struct kvm_hyperv_exit *exit)
{
    return &exit->u.hcall.params[2];
}

/* needs kernel ABI: KVM_MP_STATE_HV_INACTIVE_VTL and the matching
 * KVM_EXIT_SYSTEM_EVENT / KVM_SYSTEM_EVENT_WAKEUP wakeup exit. */
#ifndef KVM_MP_STATE_HV_INACTIVE_VTL
#define KVM_MP_STATE_HV_INACTIVE_VTL   11
#endif
#ifndef KVM_SYSTEM_EVENT_WAKEUP
#define KVM_SYSTEM_EVENT_WAKEUP        4
#endif

/* needs kernel ABI: RWX memory attributes (NR/NW/NX bits 0-2) on
 * KVM_SET_MEMORY_ATTRIBUTES. Planes v7.2-rc5 uses NO_WRITE/NO_EXEC/NO_READ
 * at bits 4-6 instead; see W3 in the note. */
#ifndef KVM_MEMORY_ATTRIBUTE_NR
#define KVM_MEMORY_ATTRIBUTE_NR        (1ULL << 0)
#define KVM_MEMORY_ATTRIBUTE_NW        (1ULL << 1)
#define KVM_MEMORY_ATTRIBUTE_NX        (1ULL << 2)
#endif

/* needs kernel ABI: RWX flags and instruction length on KVM_EXIT_MEMORY_FAULT
 * (KVM_CAP_HYPERV_HCALL_FAULT_EXIT 241, KVM_CAP_FAULT_EXIT_INSN_LEN 243).
 * The stock exit carries only KVM_MEMORY_EXIT_FLAG_PRIVATE and no insn_len. */
#ifndef KVM_MEMORY_EXIT_FLAG_READ
#define KVM_MEMORY_EXIT_FLAG_READ      (1ULL << 0)
#define KVM_MEMORY_EXIT_FLAG_WRITE     (1ULL << 1)
#define KVM_MEMORY_EXIT_FLAG_EXECUTE   (1ULL << 2)
#endif
#ifndef KVM_CAP_HYPERV_HCALL_FAULT_EXIT
#define KVM_CAP_HYPERV_HCALL_FAULT_EXIT 241
#define KVM_CAP_FAULT_EXIT_INSN_LEN     243
#endif
/* The kernel appends `__u8 insn_len` after memory_fault.size; the stock
 * struct has no such field, so read it through this accessor. */
static inline uint8_t hv_memory_fault_insn_len(struct kvm_run *run)
{
    return *((uint8_t *)&run->memory_fault.size + sizeof(run->memory_fault.size));
}

/* needs kernel ABI: KVM_TRANSLATE2 (KVM_CAP_TRANSLATE2 239). */
#ifndef KVM_TRANSLATE2
struct kvm_translation2 {
    /* in */
    __u64 linear_address;
#define KVM_TRANSLATE_FLAGS_SET_ACCESSED        (1 << 0)
#define KVM_TRANSLATE_FLAGS_SET_DIRTY           (1 << 1)
#define KVM_TRANSLATE_FLAGS_FORCE_SET_ACCESSED  (1 << 2)
    __u16 flags;
#define KVM_TRANSLATE_ACCESS_WRITE      (1 << 0)
#define KVM_TRANSLATE_ACCESS_USER       (1 << 1)
#define KVM_TRANSLATE_ACCESS_EXEC       (1 << 2)
#define KVM_TRANSLATE_ACCESS_ALL      \
    (KVM_TRANSLATE_ACCESS_WRITE | \
    KVM_TRANSLATE_ACCESS_USER |   \
    KVM_TRANSLATE_ACCESS_EXEC)
    __u16 access;
    __u8  padding[4];

    /* out */
    __u64 physical_address;
    __u8  valid;
#define KVM_TRANSLATE_FAULT_NOT_PRESENT         1
#define KVM_TRANSLATE_FAULT_PRIVILEGE_VIOLATION 2
#define KVM_TRANSLATE_FAULT_RESERVED_BITS       3
#define KVM_TRANSLATE_FAULT_INVALID_GVA         4
#define KVM_TRANSLATE_FAULT_INVALID_GPA         5
    __u16 error_code;
    __u8  set_bits_succeeded;
    __u8  padding2[4];
};
#define KVM_TRANSLATE2            _IOWR(KVMIO, 0x87, struct kvm_translation2)
#define KVM_CAP_TRANSLATE2 239
#endif

/* needs kernel ABI: KVM_HYPERV_SET_TLB_FLUSH_INHIBIT
 * (KVM_CAP_HYPERV_TLB_FLUSH_INHIBIT 240) and the suspended vCPU state. */
#ifndef KVM_HYPERV_SET_TLB_FLUSH_INHIBIT
struct kvm_hyperv_tlb_flush_inhibit {
    /* in */
    __u16 flags;
#define KVM_HYPERV_UNINHIBIT_TLB_FLUSH 0
#define KVM_HYPERV_INHIBIT_TLB_FLUSH 1
    __u8  inhibit;
    __u8  reserved[5];
};
#define KVM_HYPERV_SET_TLB_FLUSH_INHIBIT \
    _IOW(KVMIO,  0xd6, struct kvm_hyperv_tlb_flush_inhibit)
#define KVM_CAP_HYPERV_TLB_FLUSH_INHIBIT 240
#endif

#endif /* HW_HYPERV_VSM_KVM_ABI_STUB_H */

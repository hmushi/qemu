/*
 * Hyper-V VSM: KVM ABI the VSM layer needs and the imported linux-headers do
 * not carry yet.
 *
 * Replace every block by a linux-headers sync when the kernel work lands.
 * Sources, in order of how settled they are:
 *  - "posted v7": Joerg Roedel's KVM planes series (2026-06-08), the P2 base;
 *  - "Paolo 2026-07": Paolo Bonzini's "introduce memory protection
 *    attributes" RFC (2026-07-16), the P2 memory layer;
 *  - "P3": Nicolas Saenz Julienne's vianpl/linux vsm/next blocks that P3
 *    ports (hyperv.c VSM exits with XMM payload, insn_len, KVM_TRANSLATE2,
 *    TLB flush inhibit);
 *  - "PROPOSED (D8)": the userspace-visible plane switch. It exists in no
 *    posted tree (only in Paolo's 2025-04 RFC); worker D is adding it as a
 *    separate RFC patch and publishes the chosen form. Shapes below follow
 *    the 2025-04 RFC until then.
 * Where Nicolas's QEMU headers and his kernel tree disagree, the kernel
 * layout wins (params[2] plus xmm[6], memory_fault plus insn_len).
 *
 * KVM_CAP_* values are placeholders: upstream has reassigned 239-250 since
 * those trees were cut. Nothing may pass them to KVM_CHECK_EXTENSION before
 * the sync.
 *
 * Nothing here may redefine a struct that linux/kvm.h already has.
 */
#ifndef HW_HYPERV_VSM_KVM_ABI_STUB_H
#define HW_HYPERV_VSM_KVM_ABI_STUB_H

#include <linux/kvm.h>

/*
 * posted v7: planes. KVM_CREATE_PLANE(id) on the VM fd returns a plane fd;
 * KVM_CREATE_VCPU on the plane fd creates the sibling of the plane-0 vCPU
 * with the same id (shares the kvm_run page and the preempt notifier, so
 * issue it from the sibling's thread); KVM_SIGNAL_MSI and KVM_SET_GSI_ROUTING
 * are accepted on the plane fd. KVM_EXIT_PLANE_EVENT in v7 carries only
 * KVM_PLANE_EVENT_CREATE_VCPU.
 */
#ifndef KVM_CAP_PLANES
#define KVM_CAP_PLANES              249 /* posted v7 value; placeholder */
#define KVM_MAX_PLANES              16
#define KVM_CREATE_PLANE            _IO(KVMIO, 0xe4)
#define KVM_EXIT_PLANE_EVENT        44

struct kvm_plane_event_exit {
#define KVM_PLANE_EVENT_CREATE_VCPU 1
/* PROPOSED (D8): not in any posted tree; value to be taken from D8 */
#define KVM_PLANE_EVENT_INTERRUPT   2
    __u32 cause;
    __u32 plane;
    __u64 extra[8];
};
#endif /* KVM_CAP_PLANES */

static inline struct kvm_plane_event_exit *
kvm_run_plane_event(struct kvm_run *run)
{
    QEMU_BUILD_BUG_ON(sizeof(struct kvm_plane_event_exit) >
                      sizeof(run->padding));
    return (struct kvm_plane_event_exit *)run->padding;
}

/*
 * PROPOSED (D8): userspace-driven plane switch. Not in any posted tree.
 * Paolo's 2025-04 RFC shape: KVM_RUN on the plane-0 vCPU fd with
 * kvm_run->plane selecting the plane to run, req_exit_planes a bitmap of
 * planes whose pending interrupt must end KVM_RUN with KVM_EXIT_PLANE_EVENT
 * cause INTERRUPT instead of running on. D8 may instead allow KVM_RUN on the
 * plane vCPU fd; the plane API (vsm-plane-api.h) is written so either form
 * fits. The fields sit in the padding after immediate_exit (padding1[6]).
 */
struct kvm_run_planes {
    __u8 plane;             /* in/out */
    __u8 padding;
    __u16 suspended_planes; /* in/out */
    __u16 req_exit_planes;  /* in */
};

static inline struct kvm_run_planes *kvm_run_planes(struct kvm_run *run)
{
    QEMU_BUILD_BUG_ON(sizeof(struct kvm_run_planes) > sizeof(run->padding1));
    return (struct kvm_run_planes *)run->padding1;
}

/*
 * Paolo 2026-07: memory protection attributes and the matching fault exit
 * flags, VM-wide. Per-plane application (the attributes on a plane fd) is in
 * no tree yet and is a P2 item; the bit values stay these.
 */
#ifndef KVM_MEMORY_ATTRIBUTE_NR
#define KVM_MEMORY_ATTRIBUTE_NR             (1ULL << 0)
#define KVM_MEMORY_ATTRIBUTE_NW             (1ULL << 1)
#define KVM_MEMORY_ATTRIBUTE_NX             (1ULL << 2)
#endif
#ifndef KVM_MEMORY_EXIT_FLAG_READ
#define KVM_MEMORY_EXIT_FLAG_READ           (1ULL << 0)
#define KVM_MEMORY_EXIT_FLAG_WRITE          (1ULL << 1)
#define KVM_MEMORY_EXIT_FLAG_EXEC           (1ULL << 2)
#endif
#ifndef KVM_CAP_HYPERV_HCALL_FAULT_EXIT
#define KVM_CAP_HYPERV_HCALL_FAULT_EXIT     250 /* RFC value; placeholder */
#endif
#define KVM_MEMORY_EXIT_FLAG_RWX            (KVM_MEMORY_EXIT_FLAG_READ | \
                                             KVM_MEMORY_EXIT_FLAG_WRITE | \
                                             KVM_MEMORY_EXIT_FLAG_EXEC)

/*
 * P3: instruction length on KVM_EXIT_MEMORY_FAULT, appended after size
 * (vsm/next: memory_fault { flags, gpa, size, __u8 insn_len }).
 */
#ifndef KVM_CAP_FAULT_EXIT_INSN_LEN
#define KVM_CAP_FAULT_EXIT_INSN_LEN         251 /* placeholder */
#endif

/* replace by run->memory_fault.insn_len once the header has the field */
static inline uint8_t kvm_run_memory_fault_insn_len(struct kvm_run *run)
{
    return *((uint8_t *)&run->memory_fault + sizeof(run->memory_fault));
}

/*
 * P3: VSM hypercall exits with XMM payload. Kernel layout (vsm/next):
 * hcall { input, result, params[2], struct kvm_hyperv_xmm_reg xmm[6] }.
 * The stock struct stops at params[2]; the kvm_run union padding covers the
 * extra 96 bytes.
 *
 * P3 keeps KVM_EXIT_HYPERV_HCALL (2) for fast calls without XMM payload and
 * reports KVM_EXIT_HYPERV_HCALL_XMM (4) only when XMM registers carry input
 * or may carry output and userspace enabled KVM_CAP_HYPERV_XMM_EXIT.
 * (Nicolas's kernel reported every fast call as type 4, which stock QEMU
 * rejects.) Handlers read or write xmm[] only when hv_exit_has_xmm().
 * Once the header has xmm[], hv_exit_xmm() becomes &exit->u.hcall.xmm[0].
 */
#ifndef KVM_EXIT_HYPERV_HCALL_XMM
#define KVM_EXIT_HYPERV_HCALL_XMM           4
#define KVM_CAP_HYPERV_XMM_EXIT             252 /* placeholder */
#define HV_HYPERCALL_MAX_XMM_REGISTERS      6

struct kvm_hyperv_xmm_reg {
    __u64 low;
    __u64 high;
};
#endif /* KVM_EXIT_HYPERV_HCALL_XMM */

static inline bool hv_exit_has_xmm(const struct kvm_hyperv_exit *exit)
{
    return exit->type == KVM_EXIT_HYPERV_HCALL_XMM;
}

static inline struct kvm_hyperv_xmm_reg *
hv_exit_xmm(struct kvm_hyperv_exit *exit)
{
    return (struct kvm_hyperv_xmm_reg *)&exit->u.hcall.params[2];
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

/*
 * P3: KVM_TRANSLATE2. Per-vCPU ioctl, so it applies to a plane vCPU fd
 * unchanged.
 */
#ifndef KVM_TRANSLATE2
#define KVM_CAP_TRANSLATE2                  253 /* placeholder */

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
#define KVM_TRANSLATE_ACCESS_ALL \
    (KVM_TRANSLATE_ACCESS_WRITE | KVM_TRANSLATE_ACCESS_USER | \
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
#define KVM_TRANSLATE2  _IOWR(KVMIO, 0x87, struct kvm_translation2)
#endif /* KVM_TRANSLATE2 */

/*
 * P3: KVM_HYPERV_SET_TLB_FLUSH_INHIBIT and the suspended vCPU state behind
 * it. Per-vCPU ioctl, issued on the plane-0 vCPU.
 */
#ifndef KVM_HYPERV_SET_TLB_FLUSH_INHIBIT
#define KVM_CAP_HYPERV_TLB_FLUSH_INHIBIT    254 /* placeholder */

struct kvm_hyperv_tlb_flush_inhibit {
    /* in */
    __u16 flags;
#define KVM_HYPERV_UNINHIBIT_TLB_FLUSH  0
#define KVM_HYPERV_INHIBIT_TLB_FLUSH    1
    __u8  inhibit;
    __u8  reserved[5];
};
#define KVM_HYPERV_SET_TLB_FLUSH_INHIBIT \
    _IOW(KVMIO, 0xd6, struct kvm_hyperv_tlb_flush_inhibit)
#endif /* KVM_HYPERV_SET_TLB_FLUSH_INHIBIT */

/*
 * Nicolas's inactive-VTL parking: KVM_MP_STATE_HV_INACTIVE_VTL, reported
 * through the stock KVM_SYSTEM_EVENT_WAKEUP exit (an arm64 PSCI event
 * upstream, reused on x86 by vsm/next). Not part of the planes design; the
 * D8 switch replaces it. Kept only for the current VTL switch implementation
 * in target/i386/kvm/hyperv-vsm-plane.c, which class B removes together
 * with this block.
 */
#ifndef KVM_MP_STATE_HV_INACTIVE_VTL
#define KVM_MP_STATE_HV_INACTIVE_VTL    11
#endif

#endif /* HW_HYPERV_VSM_KVM_ABI_STUB_H */

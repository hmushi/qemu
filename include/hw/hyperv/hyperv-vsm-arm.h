/*
 * Hyper-V VSM on arm64: the SGI a VTL's synthetic interrupts arrive on.
 *
 * KVM has no SynIC on arm64, so QEMU owns each VTL's SynIC and VINA
 * registers and injects their virtual SGIs.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_HYPERV_HYPERV_VSM_ARM_H
#define HW_HYPERV_HYPERV_VSM_ARM_H

#include "hw/intc/arm_gic_common.h"
#include "hw/hyperv/hyperv-vsm-proto.h"

/* TLFS 11.8 SynIC register fields */
#define HV_SYNIC_ENABLE                 (1u << 0)
#define HV_SIMP_ENABLE                  (1u << 0)
#define HV_SIEFP_ENABLE                 (1u << 0)
#define HV_SINT_MASKED                  (1u << 16)
#define HV_SINT_AUTO_EOI                (1u << 17)
#define HV_SINT_VECTOR_MASK             0xff
#define HV_SYNIC_VERSION                1

/*
 * The low byte of SINTx or HvRegisterVsmVina is the raw GIC INTID. Windows
 * enables SGIs 0 through 6 and indexes its handler table with ICC_IAR1_EL1.
 */
static inline int hv_arm_vector_sgi_intid(uint64_t reg)
{
    unsigned intid = reg & HV_SINT_VECTOR_MASK;

    return intid < GIC_NR_SGIS ? intid : -EINVAL;
}

/* -ENOENT: a raised, masked SINT holds its message until it is unmasked */
static inline int hv_arm_sint_sgi_intid(uint64_t sint, bool level)
{
    if (level && (sint & HV_SINT_MASKED)) {
        return -ENOENT;
    }
    return hv_arm_vector_sgi_intid(sint);
}

/* What raising or lowering a SINTx does */
typedef enum {
    /* drive *@intid in this VTL's GIC */
    HV_ARM_SINT_RAISE,
    /* masked while raised: hold the message in its slot, drive nothing */
    HV_ARM_SINT_HOLD,
    /* the vector field names no SGI: *@intid is the errno */
    HV_ARM_SINT_INVALID,
} HvArmSintAction;

/*
 * A masked SINT is held rather than refused, because TLFS 11.8.4 leaves the
 * message in its slot until the guest unmasks it. Lowering is never held, so
 * a line cannot be left asserted by masking the SINT that drives it.
 */
static inline HvArmSintAction hv_arm_sint_action(uint64_t sint, bool level,
                                                 int *intid)
{
    int ret = hv_arm_sint_sgi_intid(sint, level);

    *intid = ret;
    if (ret == -ENOENT) {
        return HV_ARM_SINT_HOLD;
    }
    return ret < 0 ? HV_ARM_SINT_INVALID : HV_ARM_SINT_RAISE;
}

/*
 * Fast hypercall input word @i is x(1 + i), after the control word in x0.
 * Output words are right-anchored on x16: one word is x16, two are x15/x16.
 */
#define HV_ARM_HCALL_FAST_IN_BASE   1
#define HV_ARM_HCALL_FAST_OUT_LAST  16
#define HV_ARM_HCALL_FAST_IN_MAX    17

/* the x-register fast input word @i arrives in, or -EINVAL past the block */
static inline int hv_arm_fast_in_reg(unsigned int i)
{
    if (i >= HV_ARM_HCALL_FAST_IN_MAX) {
        return -EINVAL;
    }
    return HV_ARM_HCALL_FAST_IN_BASE + (int)i;
}

/*
 * The x-register fast output word @i of an @n-word block is written to, or
 * -EINVAL if @i is outside the block or @n is a width not served.
 */
static inline int hv_arm_fast_out_reg(unsigned int i, unsigned int n)
{
    if (n == 0 || n > 2 || i >= n) {
        return -EINVAL;
    }
    return HV_ARM_HCALL_FAST_OUT_LAST - (int)(n - 1 - i);
}

/*
 * The fields of an hvdef HvArm64MemoryInterceptMessage. @pc, @cpsr, @cpl
 * and @vtl are the faulting lower VTL's, not the secure VTL's.
 * KVM_EXIT_MEMORY_FAULT carries no virtual address, so @gva_valid is false
 * on that path.
 */
typedef struct HvArmMemoryIntercept {
    uint32_t vp_index;
    uint8_t vtl;                /* the faulting, lower VTL */
    uint8_t cpl;
    uint8_t access_type;        /* enum hv_x64_intercept_access_type */
    uint8_t insn_count;         /* 0 when no bytes were fetched */
    uint8_t insn_bytes[4];
    bool gva_valid;
    uint64_t pc;
    uint64_t cpsr;
    uint64_t gpa;
    uint64_t gva;               /* read only when @gva_valid */
    uint64_t syndrome;
} HvArmMemoryIntercept;

/*
 * Lay @f out as a GPA intercept message in @msg. Both valid bits follow
 * @gva_valid: the GPA is always known when the GVA is.
 */
static inline void hv_arm_build_memory_intercept(const HvArmMemoryIntercept *f,
                                                 struct hyperv_message *msg)
{
    struct hv_arm64_memory_intercept_message *icpt = (void *)msg->payload;
    struct hv_arm64_intercept_message_header *hdr = &icpt->header;

    QEMU_BUILD_BUG_ON(sizeof(*icpt) > sizeof(msg->payload));

    memset(msg, 0, sizeof(*msg));
    msg->header.message_type = HV_MESSAGE_GPA_INTERCEPT;
    msg->header.payload_size = sizeof(*icpt);

    hdr->vp_index = f->vp_index;
    hdr->instruction_length = 4;        /* every A64 instruction */
    hdr->intercept_access_type = f->access_type;
    hdr->execution_state.cpl = f->cpl;
    hdr->execution_state.vtl = f->vtl;
    hdr->pc = f->pc;
    hdr->cpsr = f->cpsr;

    icpt->cache_type = HV_CACHE_TYPE_WRITE_BACK;
    icpt->instruction_byte_count = f->insn_count;
    memcpy(icpt->instruction_bytes, f->insn_bytes, sizeof(f->insn_bytes));
    icpt->memory_access_info.gva_valid = f->gva_valid;
    icpt->memory_access_info.gva_gpa_valid = f->gva_valid;
    icpt->guest_virtual_address = f->gva_valid ? f->gva : 0;
    icpt->guest_physical_address = f->gpa;
    icpt->syndrome = f->syndrome;
}

/*
 * Fast HVC #1 output is right-anchored at x16, not left-anchored as in the
 * TLFS: the Windows call stub stores M output pairs through the tail of an
 * stp ladder ending at x15/x16, so pair 0 lands in x(17 - 2M). x17 is the
 * stub's scratch.
 */
#define HV_ARM_FAST_OUT_PAIRS_MAX 8

/* First register of output pair 0, or 0 if @pairs does not fit x1 to x16. */
static inline unsigned hv_arm_fast_out_first(unsigned pairs)
{
    if (pairs == 0 || pairs > HV_ARM_FAST_OUT_PAIRS_MAX) {
        return 0;
    }
    return 17 - 2 * pairs;
}

/*
 * Write @pairs output pairs from @val into @xregs, pair 0 first. Registers
 * outside the window keep their values, as the TLFS volatile-register rule
 * requires. Returns false and writes nothing if the pairs do not fit.
 */
static inline bool hv_arm_fast_out(uint64_t *xregs, const uint64_t *val,
                                   unsigned pairs)
{
    unsigned first = hv_arm_fast_out_first(pairs);
    unsigned i;

    if (first == 0) {
        return false;
    }
    for (i = 0; i < pairs * 2; i++) {
        xregs[first + i] = val[i];
    }
    return true;
}

#endif /* HW_HYPERV_HYPERV_VSM_ARM_H */

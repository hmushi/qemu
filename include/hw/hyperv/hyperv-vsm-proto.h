/*
 * Hyper-V Virtual Secure Mode (VSM) guest ABI
 *
 * Definitions from the Hypervisor Top Level Functional Specification (TLFS)
 * chapter 15 "Virtual Secure Mode" and from the hvdef headers that the
 * MSHV import (hvgdk_mini.h, hvhdk.h, hvhdk_mini.h) does not carry. Anything
 * those headers do provide is used from there and not repeated here.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_HYPERV_HYPERV_VSM_PROTO_H
#define HW_HYPERV_HYPERV_VSM_PROTO_H

#include "qemu/bitops.h"
#include "hw/hyperv/hyperv-proto.h"
#include "hw/hyperv/hvgdk_mini.h"
#include "hw/hyperv/hvhdk_mini.h"
#include "hw/hyperv/hvhdk.h"

/* TLFS 15.2: two VTLs are implemented; the architecture allows 16 */
#define HV_NUM_VTLS                 2
#define HV_INVALID_VTL              ((uint8_t)-1)

/* TLFS 3.4 partition and VP identifiers */
#define HV_PARTITION_ID_SELF        ((uint64_t)-1)
#define HV_VP_INDEX_SELF            ((uint32_t)-2)
#define HV_ANY_VP                   ((uint32_t)-1)

/* TLFS 3.6 hypercall status codes not in hyperv-proto.h */
#define HV_STATUS_ACCESS_DENIED                 6
#define HV_STATUS_INVALID_PARTITION_ID          13
#define HV_STATUS_INVALID_VP_INDEX              14
#define HV_STATUS_INVALID_VP_STATE              21

/* TLFS 3.7 hypercall input value and result value bit fields */
#define HV_HYPERCALL_VARHEAD_OFFSET             17
#define HV_HYPERCALL_VARHEAD_MASK \
    MAKE_64BIT_MASK(HV_HYPERCALL_VARHEAD_OFFSET, 9)
#define HV_HYPERCALL_REP_COMP_OFFSET            32
#define HV_HYPERCALL_REP_START_OFFSET           48

/* TLFS appendix A hypercall codes used by VSM; others come from hvgdk_mini.h */
#define HVCALL_SEND_IPI                         0x000b
#define HVCALL_MODIFY_VTL_PROTECTION_MASK       0x000c
#define HVCALL_ENABLE_PARTITION_VTL             0x000d
#define HVCALL_ENABLE_VP_VTL                    0x000f
#define HVCALL_VTL_CALL                         0x0011
#define HVCALL_VTL_RETURN                       0x0012
#define HVCALL_SEND_IPI_EX                      0x0015
#define HVCALL_START_VIRTUAL_PROCESSOR          0x0099
#define HVCALL_GET_VP_INDEX_FROM_APIC_ID        0x009a

/* TLFS 15.6 VSM registers (hvdef HvRegisterVsm*) and x64 names not in hvdef */
#define HV_X64_REGISTER_DR6                                 0x00050004
#define HV_X64_REGISTER_DR7                                 0x00050005
#define HV_REGISTER_VP_ASSIST_PAGE                          0x00090013
#define HV_REGISTER_VSM_CODE_PAGE_OFFSETS                   0x000D0002
#define HV_REGISTER_VSM_VP_STATUS                           0x000D0003
#define HV_REGISTER_VSM_PARTITION_STATUS                    0x000D0004
#define HV_REGISTER_VSM_VINA                                0x000D0005
#define HV_REGISTER_VSM_CAPABILITIES                        0x000D0006
#define HV_REGISTER_VSM_PARTITION_CONFIG                    0x000D0007
#define HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0               0x000D0010
#define HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL14              0x000D001E
#define HV_X64_REGISTER_CR_INTERCEPT_CONTROL                0x000E0000
#define HV_X64_REGISTER_CR_INTERCEPT_CR0_MASK               0x000E0001
#define HV_X64_REGISTER_CR_INTERCEPT_CR4_MASK               0x000E0002
#define HV_X64_REGISTER_CR_INTERCEPT_IA32_MISC_ENABLE_MASK  0x000E0003

/*
 * TLFS 15.13.4: the accesses of the next lower VTL that the configuring VTL
 * intercepts.
 */
union hv_register_cr_intercept_control {
    uint64_t as_uint64;
    struct {
        uint64_t cr0_write:1;
        uint64_t cr4_write:1;
        uint64_t xcr0_write:1;
        uint64_t ia32_misc_enable_read:1;
        uint64_t ia32_misc_enable_write:1;
        uint64_t msr_lstar_read:1;
        uint64_t msr_lstar_write:1;
        uint64_t msr_star_read:1;
        uint64_t msr_star_write:1;
        uint64_t msr_cstar_read:1;
        uint64_t msr_cstar_write:1;
        uint64_t apic_base_msr_read:1;
        uint64_t apic_base_msr_write:1;
        uint64_t msr_efer_read:1;
        uint64_t msr_efer_write:1;
        uint64_t gdtr_write:1;
        uint64_t idtr_write:1;
        uint64_t ldtr_write:1;
        uint64_t tr_write:1;
        uint64_t msr_sysenter_cs_write:1;
        uint64_t msr_sysenter_eip_write:1;
        uint64_t msr_sysenter_esp_write:1;
        uint64_t msr_sfmask_write:1;
        uint64_t msr_tsc_aux_write:1;
        uint64_t msr_sgx_launch_control_write:1;
        uint64_t reserved:39;
    };
};

/*
 * TLFS 11.10.2 register intercept message type. hvgdk_mini.h names this
 * value HVMSG_X64_IOMMU_PRQ; the TLFS value is the one Windows consumes.
 */
#define HV_MESSAGE_X64_REGISTER_INTERCEPT 0x80010006

/*
 * TLFS 11.10.2 register intercept message, posted on SINT0 of the
 * configuring VTL.
 */
struct hv_vsm_register_intercept_message {
    struct hv_x64_intercept_message_header header;
    uint8_t is_memory_op:1;
    uint8_t reserved:7;
    uint8_t reserved_0;
    uint16_t reserved_1;
    uint32_t reg_name;
    union {
        struct hv_u128 reg128;
        uint64_t reg64;
        uint16_t reg16;
        struct hv_x64_table_register table;
    } source_value;
} QEMU_PACKED;

/* TLFS 15.6.1 HvRegisterVsmCodePageOffsets */
union hv_register_vsm_code_page_offsets {
    uint64_t as_uint64;
    struct {
        uint64_t vtl_call_offset:12;
        uint64_t vtl_return_offset:12;
        uint64_t reserved:40;
    };
};

/* TLFS 15.6.2 HvRegisterVsmCapabilities */
union hv_register_vsm_capabilities {
    uint64_t as_uint64;
    struct {
        uint64_t dr6_shared:1;
        uint64_t mbec_vtl_mask:16;
        uint64_t deny_lower_vtl_startup:1;
        uint64_t supervisor_shadow_stack:1;
        uint64_t hardware_hvpt_available:1;
        uint64_t software_hvpt_available:1;
        uint64_t hardware_hvpt_range_bits:6;
        uint64_t intercept_page_available:1;
        uint64_t return_action_available:1;
        uint64_t reserved:35;
    };
};

/* TLFS 15.6.3 HvRegisterVsmPartitionConfig */
union hv_register_vsm_partition_config {
    uint64_t as_uint64;
    struct {
        uint64_t enable_vtl_protection:1;
        uint64_t default_vtl_protection_mask:4;
        uint64_t zero_memory_on_reset:1;
        uint64_t deny_lower_vtl_startup:1;
        uint64_t intercept_acceptance:1;
        uint64_t intercept_enable_vtl_protection:1;
        uint64_t intercept_vp_startup:1;
        uint64_t intercept_cpuid_unimplemented:1;
        uint64_t intercept_unrecoverable_exception:1;
        uint64_t intercept_page:1;
        uint64_t reserved:51;
    };
};

/* TLFS 15.6.4 HvRegisterVsmPartitionStatus */
union hv_register_vsm_partition_status {
    uint64_t as_uint64;
    struct {
        uint64_t enabled_vtl_set:16;
        uint64_t maximum_vtl:4;
        uint64_t mbec_enabled_vtl_set:16;
        uint64_t reserved:28;
    };
};

/* TLFS 15.6.5 HvRegisterVsmVpStatus */
union hv_register_vsm_vp_status {
    uint64_t as_uint64;
    struct {
        uint64_t active_vtl:4;
        uint64_t active_mbec_enabled:1;
        uint64_t reserved0:11;
        uint64_t enabled_vtl_set:16;
        uint64_t reserved1:32;
    };
};

/* TLFS 15.6.6 HvRegisterVsmVpSecureVtlConfig */
/* TLFS 15.6.6 HvRegisterVsmVpSecureConfigVtlN */
union hv_register_vsm_vp_secure_vtl_config {
    uint64_t as_uint64;
    struct {
        uint64_t mbec_enabled:1;
        uint64_t tlb_locked:1;
        uint64_t supervisor_shadow_stack_enabled:1;
        uint64_t hardware_hvpt_enabled:1;
        uint64_t reserved0:60;
    };
};

/* TLFS 15.6.5 HvRegisterVsmVina */
union hv_register_vsm_vina {
    uint64_t as_uint64;
    struct {
        uint64_t vector:8;
        uint64_t enabled:1;
        uint64_t auto_reset:1;
        uint64_t auto_eoi:1;
        uint64_t reserved:53;
    };
};

/* TLFS 15.6 HvRegisterPendingEvent0 event type field */
enum hv_x64_pending_event_type {
    HV_X64_PENDING_EVENT_EXCEPTION = 0,
    HV_X64_PENDING_EVENT_MEMORY_INTERCEPT = 1,
    HV_X64_PENDING_EVENT_NESTED_MEMORY_INTERCEPT = 2,
    HV_X64_PENDING_EVENT_VIRTUALIZATION_FAULT = 3,
    HV_X64_PENDING_EVENT_HYPERCALL_OUTPUT = 4,
    HV_X64_PENDING_EXT_INT = 5,
    HV_X64_PENDING_EVENT_SHADOW_IPT = 6,
};

/* TLFS 9.5 HV_X64_MSR_HYPERCALL layout */
#define HV_X64_MSR_HYPERCALL_ENABLE             0x00000001
#define HV_X64_MSR_HYPERCALL_PAGE_ADDRESS_SHIFT 12
#define HV_X64_MSR_HYPERCALL_PAGE_ADDRESS_MASK  \
        (~((1ull << HV_X64_MSR_HYPERCALL_PAGE_ADDRESS_SHIFT) - 1))

/* TLFS 15.12 HV_X64_MSR_VP_ASSIST_PAGE layout */
#define HV_X64_MSR_VP_ASSIST_PAGE_ENABLE        0x00000001
#define HV_X64_MSR_VP_ASSIST_PAGE_ADDRESS_SHIFT 12
#define HV_X64_MSR_VP_ASSIST_PAGE_ADDRESS_MASK  \
        (~((1ull << HV_X64_MSR_VP_ASSIST_PAGE_ADDRESS_SHIFT) - 1))

/* TLFS 15.12.1 VP assist page: VTL control */
enum hv_vtl_entry_reason {
    HV_VTL_ENTRY_RESERVED = 0,
    HV_VTL_ENTRY_VTL_CALL = 1,
    HV_VTL_ENTRY_INTERRUPT = 2,
};

struct hv_vp_vtl_control {
    uint32_t vtl_entry_reason;
    union {
        uint8_t as_uint8;
        struct {
            uint8_t vina_asserted:1;
            uint8_t reserved0:7;
        };
    };
    uint8_t reserved1[3];
    union {
        struct {
            uint64_t vtl_ret_x64rax;
            uint64_t vtl_ret_x64rcx;
        };
        struct {
            uint32_t vtl_return_x86_eax;
            uint32_t vtl_return_x86_ecx;
            uint32_t vtl_return_x86_edx;
            uint32_t reserved2;
        };
    };
};

/* TLFS 16.5 nested enlightenments control (part of the VP assist page) */
struct hv_nested_enlightenments_control {
    struct {
        uint32_t directhypercall:1;
        uint32_t reserved:31;
    } features;
    struct {
        uint32_t inter_partition_comm:1;
        uint32_t reserved:31;
    } hypercall_controls;
} QEMU_PACKED;

/* TLFS 15.12 VP assist page */
struct hv_vp_assist_page {
    uint32_t apic_assist;
    uint32_t reserved1;
    struct hv_vp_vtl_control vtl_control;
    struct hv_nested_enlightenments_control nested_control;
    uint8_t enlighten_vmentry;
    uint8_t reserved2[7];
    uint64_t current_nested_vmcs;
    uint8_t synthetic_time_unhalted_timer_expired;
    uint8_t reserved3[7];
    uint8_t virtualization_fault_information[40];
    uint8_t reserved4[8];
    uint8_t intercept_message[256];
    uint8_t vtl_ret_actions[256];
} QEMU_PACKED;

/* TLFS 15.5.1 HvCallEnablePartitionVtl input (fast call, two registers) */
union hv_enable_partition_vtl_flags {
    uint8_t as_uint8;
    struct {
        uint8_t enable_mbec:1;
        uint8_t reserved:7;
    };
};

union hv_enable_partition_vtl {
    uint64_t as_uint64[2];
    struct {
        uint64_t target_partition_id;
        uint8_t target_vtl;
        union hv_enable_partition_vtl_flags flags;
        uint8_t reserved[6];
    } QEMU_PACKED;
};

/* TLFS 15.5.2 HV_INITIAL_VP_CONTEXT */
struct hv_init_vp_context {
    uint64_t rip;
    uint64_t rsp;
    uint64_t rflags;

    struct hv_x64_segment_register cs;
    struct hv_x64_segment_register ds;
    struct hv_x64_segment_register es;
    struct hv_x64_segment_register fs;
    struct hv_x64_segment_register gs;
    struct hv_x64_segment_register ss;
    struct hv_x64_segment_register tr;
    struct hv_x64_segment_register ldtr;

    struct hv_x64_table_register idtr;
    struct hv_x64_table_register gdtr;

    uint64_t efer;
    uint64_t cr0;
    uint64_t cr3;
    uint64_t cr4;
    uint64_t msr_cr_pat;
} QEMU_PACKED;

/*
 * The initial context is guest ABI, and the privileged level depends on us
 * entirely for its descriptor tables: it carries no table-load instruction,
 * so it has no fallback if a field moves here and we program a garbage base.
 * That failure would be silent and fatal, so pin the layout. These offsets
 * were checked field for field against the MS-derived hvgdk_mini.h in the
 * kernel tree, not against this file.
 */
QEMU_BUILD_BUG_ON(sizeof(struct hv_x64_table_register) != 16);
QEMU_BUILD_BUG_ON(offsetof(struct hv_x64_table_register, limit) != 6);
QEMU_BUILD_BUG_ON(offsetof(struct hv_x64_table_register, base) != 8);

QEMU_BUILD_BUG_ON(sizeof(struct hv_x64_segment_register) != 16);
QEMU_BUILD_BUG_ON(offsetof(struct hv_x64_segment_register, base) != 0);
QEMU_BUILD_BUG_ON(offsetof(struct hv_x64_segment_register, limit) != 8);
QEMU_BUILD_BUG_ON(offsetof(struct hv_x64_segment_register, selector) != 12);
QEMU_BUILD_BUG_ON(offsetof(struct hv_x64_segment_register, attributes) != 14);

QEMU_BUILD_BUG_ON(sizeof(struct hv_init_vp_context) != 224);
QEMU_BUILD_BUG_ON(offsetof(struct hv_init_vp_context, rip) != 0);
QEMU_BUILD_BUG_ON(offsetof(struct hv_init_vp_context, rsp) != 8);
QEMU_BUILD_BUG_ON(offsetof(struct hv_init_vp_context, rflags) != 16);
QEMU_BUILD_BUG_ON(offsetof(struct hv_init_vp_context, cs) != 24);
QEMU_BUILD_BUG_ON(offsetof(struct hv_init_vp_context, ldtr) != 136);
QEMU_BUILD_BUG_ON(offsetof(struct hv_init_vp_context, idtr) != 152);
QEMU_BUILD_BUG_ON(offsetof(struct hv_init_vp_context, gdtr) != 168);
QEMU_BUILD_BUG_ON(offsetof(struct hv_init_vp_context, efer) != 184);
QEMU_BUILD_BUG_ON(offsetof(struct hv_init_vp_context, cr0) != 192);
QEMU_BUILD_BUG_ON(offsetof(struct hv_init_vp_context, cr3) != 200);
QEMU_BUILD_BUG_ON(offsetof(struct hv_init_vp_context, cr4) != 208);
QEMU_BUILD_BUG_ON(offsetof(struct hv_init_vp_context, msr_cr_pat) != 216);

/* TLFS 15.5.2 HvCallEnableVpVtl input; also HvCallStartVirtualProcessor */
struct hv_enable_vp_vtl {
    uint64_t partition_id;
    uint32_t vp_index;
    uint8_t target_vtl;
    uint8_t mbz0;
    uint16_t mbz1;
    struct hv_init_vp_context vp_context;
} QEMU_PACKED;

/* TLFS 15.5.5 HvCallModifyVtlProtectionMask input header (fast: 2 regs) */
union hv_modify_vtl_protection_mask {
    uint64_t as_uint64[2];
    struct {
        uint64_t target_partition_id;
        uint32_t map_flags;         /* HV_MAP_GPA_* from hvhdk_mini.h */
        union hv_input_vtl input_vtl;
        uint8_t reserved[3];
    } QEMU_PACKED;
};

/*
 * TLFS 15.5.3 HvCallGetVpRegisters / HvCallSetVpRegisters.
 * The input header is struct hv_input_get_vp_registers from hvgdk_mini.h
 * (sizeof == 16, the names[] member is flexible). Register values are 128
 * bits, struct hv_u128 from the same header.
 *
 * The handler reads SetVpRegisters input as the names[] array followed by
 * 16-byte aligned values; the hvdef hv_input_set_vp_registers layout is an
 * array of hv_register_assoc (32 bytes each). The conformance run (P5)
 * decides which one the kvm-unit-tests and Windows use.
 */

/* TLFS 15.5.4 HvCallTranslateVirtualAddress control flags beyond VALIDATE_* */
#define HV_TRANSLATE_GVA_PRIVILEGE_EXEMPT       (0x0008)
#define HV_TRANSLATE_GVA_SET_PAGE_TABLE_BITS    (0x0010)
#define HV_TRANSLATE_GVA_TLB_FLUSH_INHIBIT      (0x0020)
#define HV_TRANSLATE_GVA_FLAGS_MASK             0x3f
/* the input VTL rides in the top byte of control_flags */
#define HV_TRANSLATE_GVA_INPUT_VTL_SHIFT        56

/* TLFS 5.3 HV_CACHE_TYPE */
enum hv_cache_type {
    HV_CACHE_TYPE_UNCACHED = 0,
    HV_CACHE_TYPE_WRITE_COMBINING = 1,
    HV_CACHE_TYPE_WRITE_THROUGH = 4,
    HV_CACHE_TYPE_WRITE_PROTECTED = 5,
    HV_CACHE_TYPE_WRITE_BACK = 6,
};

/*
 * TLFS 15.10.2 memory intercept message. hvgdk_mini.h carries the hvdef
 * prefix (struct hv_x64_memory_intercept_message, up to instruction_bytes);
 * the TLFS message continues with DS, SS and the GPRs.
 */
struct hv_vsm_memory_intercept_message {
    struct hv_x64_memory_intercept_message msg;
    struct hv_x64_segment_register ds;
    struct hv_x64_segment_register ss;
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
} QEMU_PACKED;

/* TLFS 11.11.1 HvCallSendSyntheticClusterIpi */
#define HV_IPI_LOW_VECTOR           0x10
#define HV_IPI_HIGH_VECTOR          0xff

struct hv_send_ipi {
    uint32_t vector;
    union hv_input_vtl in_vtl;
    uint8_t reserved[3];
    uint64_t cpu_mask;
} QEMU_PACKED;

/* TLFS 7.8.7.3 HV_VPSET; format is enum hv_generic_set_format */
struct hv_vpset {
    uint64_t format;
    uint64_t valid_bank_mask;
    uint64_t bank_contents[];
} QEMU_PACKED;

#define HV_MAX_SPARSE_VCPU_BANKS    64
#define HV_VCPUS_PER_SPARSE_BANK    64

/* TLFS 11.11.2 HvCallSendSyntheticClusterIpiEx */
struct hv_send_ipi_ex {
    uint32_t vector;
    union hv_input_vtl in_vtl;
    uint8_t reserved[3];
    struct hv_vpset vp_set;
} QEMU_PACKED;

/* TLFS 15.5.6 HvCallGetVpIndexFromApicId input header (followed by apic ids) */
struct hv_get_vp_index_from_apic_id_input {
    uint64_t partition_id;
    uint8_t target_vtl;
    uint8_t reserved[7];
} QEMU_PACKED;

#endif /* HW_HYPERV_HYPERV_VSM_PROTO_H */

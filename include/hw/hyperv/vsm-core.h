/*
 * Hyper-V Virtual Secure Mode (VSM): target-neutral core
 *
 * Partition and per-VP VTL state, the VSM hypercalls that need only that
 * state and VINA. The target supplies its
 * register file and VP assist page through HvVsmArchOps.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_HYPERV_VSM_CORE_H
#define HW_HYPERV_VSM_CORE_H

#include "hw/core/cpu.h"
#include "hw/core/qdev.h"
#include "exec/hwaddr.h"
#include "system/memory.h"
#include "hw/hyperv/hyperv.h"
#include "hw/hyperv/hyperv-vsm-proto.h"
#include "hw/hyperv/vsm-plane-api.h"

/* Partition-wide VSM state */
typedef struct HvVsmState {
    GHashTable *prots[HV_NUM_VTLS];
    /* bit N set: VTL N is enabled on at least one VP */
    uint16_t vtl_enabled_for_vps;
    union hv_register_vsm_code_page_offsets code_page_offsets;
    union hv_register_vsm_partition_status partition_status;
    union hv_register_vsm_capabilities capabilities;
    union hv_register_vsm_partition_config partition_config[HV_NUM_VTLS];
    /* HV_X64_MSR_HYPERCALL is partition-wide (TLFS 3.13): one per VTL */
    uint64_t hypercall[HV_NUM_VTLS];
} HvVsmState;

extern HvVsmState hv_vsm;

/* Per-VP, per-VTL state (child "vp-vsm" of the CPUState of that VTL) */
struct VpVsmState {
    DeviceState parent_obj;

    CPUState *cs;
    union hv_register_vsm_vp_status vp_status;
    union hv_register_vsm_vp_secure_vtl_config vtl_config[HV_NUM_VTLS];
    uint64_t msr_hv_vp_assist;
    /* HvRegisterPendingEvent0: stored only, not injected into a lower VTL */
    uint64_t pending_event0[2];
    /* HvRegisterVpConfig, stored only */
    uint64_t vp_config;
    /* the register at 0x00090005, stored only */
    uint64_t undocumented_90005;
    /* HvRegisterReferenceTsc: last written GPA|enable; live page GPA or 0 */
    uint64_t msr_hv_tsc;
    uint64_t ref_tsc_gpa;
    HvSintRoute *intercept_route;
    /* a start is queued on this processor's thread and has not run yet */
    bool start_pending;
    /* this processor's own start has completed, so it is running */
    bool started;
    /* bumped at every system reset, so a queued start can tell it is stale */
    unsigned reset_gen;
    struct hyperv_message intercept_msg;
    /* HvRegisterVsmVina (TLFS 15.6.5) */
    union hv_register_vsm_vina vina;
    /*
     * TLFS 15.13.4 secure register intercepts this VTL configured for the
     * next lower VTL. Only the descriptor-table write bits are enforced.
     */
    union hv_register_cr_intercept_control cr_intercept_control;
    uint64_t cr_intercept_cr0_mask;
    uint64_t cr_intercept_cr4_mask;
    uint64_t cr_intercept_misc_enable_mask;
    /* intercepts posted while the previous one was unacknowledged, in a row */
    uint64_t intercepts_unposted;
    /*
     * intercept_msg is held until the target VTL's SynIC can take it; the
     * lower VTL stays stopped at the faulting instruction meanwhile.
     */
    bool intercept_pending;
    /* SynIC registers of a VTL whose SynIC QEMU models (arm64) */
    uint64_t synic_sctl;
    uint64_t synic_simp;
    uint64_t synic_siefp;
    uint64_t synic_sint[HV_SINT_COUNT];
    /* the VINA PPI is asserted in this VTL's GIC (arm64) */
    bool vina_line;
    /* Hyper-V synthetic timers (arm64; KVM arm64 has no SynIC/stimer) */
    uint64_t stimer_config[4];
    uint64_t stimer_count[4];
    void *stimer_qt[4]; /* QEMUTimer* */
};

#define TYPE_VP_VSM "hyperv-vp-vsm"
OBJECT_DECLARE_SIMPLE_TYPE(VpVsmState, VP_VSM)

VpVsmState *get_vp_vsm(CPUState *cs);
/*
 * A start is queued on VP @vp_index and has not loaded its context yet, so
 * its registers are not the ones the start supplied.
 */
bool vp_start_pending(uint32_t vp_index);
int active_vtl(CPUState *cs);
CPUState *sibling(CPUState *cs, int vtl);
bool input_vtl_targets(union hv_input_vtl in_vtl);
MemTxResult vsm_physmem_write(CPUState *cs, hwaddr addr, const void *buf,
                              hwaddr len);
MemTxResult vsm_physmem_read(CPUState *cs, hwaddr addr, void *buf,
                             hwaddr len);
int highest_vtl(uint16_t set);

/* system reset: scrub guest RAM */
void hyperv_vsm_zero_memory(void);

/* HvRegisterVsmVina and the vina_asserted flag of the VTL control page */
void set_vina(CPUState *cs, uint64_t data);
bool vina_asserted(CPUState *cs);
void set_vina_asserted(CPUState *cs, bool asserted);
void write_vtl_control(CPUState *cs, const struct hv_vp_vtl_control *ctl);
void read_vtl_control(CPUState *cs, struct hv_vp_vtl_control *ctl);

void set_tlb_flush_inhibit(CPUState *vtl0, bool inhibit);
bool get_vp_secure_vtl_config(CPUState *cs, uint32_t reg, struct hv_u128 *val);
bool set_vp_secure_vtl_config(CPUState *cs, uint32_t reg, uint64_t data);
/* HvRegisterVsmPartitionConfig of @vtl: the write-once fields are kept */
void set_vsm_partition_config(uint8_t vtl, uint64_t data);
uint32_t translate_result_code(const struct kvm_translation2 *tr,
                               uint64_t control_flags);
struct hv_input_translate_virtual_address;
struct hv_output_translate_virtual_address;
/*
 * HvCallTranslateVirtualAddress (TLFS 10.8.3) on @in, already marshalled
 * from the caller. @out is written only on HV_STATUS_SUCCESS; a failed
 * translation is a success with a failure result_code. Other statuses mean
 * a malformed or unroutable call.
 */
uint16_t hyperv_vsm_translate_gva(
        CPUState *cs,
        const struct hv_input_translate_virtual_address *in,
        struct hv_output_translate_virtual_address *out);

/* hypercall handlers, called from kvm_hv_handle_exit() */
uint16_t hyperv_hcall_vtl_enable_partition_vtl(CPUState *cs, uint64_t param1,
                                               uint64_t param2, bool fast);
uint16_t hyperv_hcall_vtl_enable_vp_vtl(CPUState *cs, uint64_t param,
                                        bool fast);
/*
 * A VTL switch has no result of its own: it hands RAX and RCX over through
 * the VTL control page. @status carries a refusal instead.
 */
int hyperv_hcall_vtl_call(CPUState *cs, uint64_t *status);
int hyperv_hcall_vtl_return(CPUState *cs, uint64_t *status);
uint64_t hyperv_hcall_get_set_vp_register(CPUState *cs,
                                          struct kvm_hyperv_exit *exit,
                                          bool set);

/* @cs's VTL has VINA (TLFS 15.2.3) enabled and not yet asserted */
bool hyperv_vsm_vina_armed(CPUState *cs);

/*
 * Target hooks: the VP assist page, the register file behind
 * Get/SetVpRegisters and the VP start context.
 */
typedef struct HvVsmArchOps {
    /* GPA of the VP assist page's vtl_control; the page is enabled */
    hwaddr (*vtl_control_gpa)(CPUState *cs);
    bool (*vp_assist_enabled)(CPUState *cs);
    /* load an HV_INITIAL_VP_CONTEXT (TLFS 15.5.2) into @cs, BQL held */
    void (*load_vp_context)(CPUState *cs, const struct hv_init_vp_context *c,
                            bool enable_spiv, hwaddr input_gpa);
    /* a register the core does not know; @target_vcpu's state is in sync */
    uint16_t (*get_vp_register)(uint32_t name, struct hv_u128 *val,
                                CPUState *target_vcpu);
    uint16_t (*set_vp_register)(uint32_t name, const struct hv_u128 *val,
                                CPUState *target_vcpu, bool *dirty);
    /*
     * Walk @target_vcpu's tables for @gva_page under @flags. Returns an
     * enum hv_translate_gva_result_code; on success *@gpa_page is the frame
     * and *@overlay says whether it is a hypervisor overlay page. Optional:
     * x86 leaves it NULL and serves the hypercall with KVM_TRANSLATE2.
     */
    uint32_t (*translate_gva)(CPUState *target_vcpu, uint64_t gva_page,
                              uint64_t flags, uint64_t *gpa_page,
                              bool *overlay);
} HvVsmArchOps;

extern const HvVsmArchOps hv_vsm_arch_ops;

#endif /* HW_HYPERV_VSM_CORE_H */

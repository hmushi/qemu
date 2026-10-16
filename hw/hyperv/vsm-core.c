/*
 * QEMU KVM Hyper-V Virtual Secure Mode (VSM): target-neutral core
 *
 * Partition and per-VP VTL state, the VSM hypercalls (TLFS chapter 15) and
 * VINA. KVM is reached only through the plane API, the target's register
 * file only through hv_vsm_arch_ops.
 *
 * Based on the VSM series by Nicolas Saenz Julienne.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "qapi/error.h"
#include "system/address-spaces.h"
#include "system/cpus.h"
#include "system/hw_accel.h"
#include "system/kvm.h"
#include "system/memory.h"
#include "system/ramblock.h"
#include "system/ramlist.h"
#include "hw/core/boards.h"
#include "hw/core/cpu.h"
#include "hw/hyperv/hyperv.h"
#include "hw/hyperv/vsm-core.h"
#include "trace.h"

HvVsmState hv_vsm = {
    .vtl_enabled_for_vps = BIT(0),
    .partition_status = {
        .enabled_vtl_set = BIT(0),
        .maximum_vtl = HV_NUM_VTLS - 1,
    },
    .capabilities = { .dr6_shared = 1 },
};

VpVsmState *get_vp_vsm(CPUState *cs)
{
    return VP_VSM(object_resolve_path_component(OBJECT(cs), "vp-vsm"));
}

bool vp_start_pending(uint32_t vp_index)
{
    CPUState *cs = hv_plane_vcpu(vp_index, 0);
    VpVsmState *vpvsm = cs ? get_vp_vsm(cs) : NULL;

    return vpvsm && vpvsm->start_pending;
}

int active_vtl(CPUState *cs)
{
    return hv_plane_active_vtl(cs);
}

CPUState *sibling(CPUState *cs, int vtl)
{
    return hv_plane_vcpu(hyperv_vp_index(cs), vtl);
}

/* HV_INPUT_VTL names a target VTL; 0xff means the caller's */
bool input_vtl_targets(union hv_input_vtl in_vtl)
{
    return in_vtl.use_target_vtl && in_vtl.as_uint8 != 0xff;
}

MemTxResult vsm_physmem_write(CPUState *cs, hwaddr addr,
                                     const void *buf, hwaddr len)
{
    return address_space_write(cs->as, addr, MEMTXATTRS_UNSPECIFIED, buf, len);
}

MemTxResult vsm_physmem_read(CPUState *cs, hwaddr addr,
                                    void *buf, hwaddr len)
{
    return address_space_read(cs->as, addr, MEMTXATTRS_UNSPECIFIED, buf, len);
}

static void vp_vsm_realize(DeviceState *dev, Error **errp)
{
    VpVsmState *vpvsm = VP_VSM(dev);

    vpvsm->vp_status.enabled_vtl_set = BIT(0);
    vpvsm->vp_status.active_vtl = active_vtl(vpvsm->cs);
}

static void vp_vsm_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = vp_vsm_realize;
    dc->user_creatable = false;
}

static const TypeInfo vp_vsm_type_info = {
    .name = TYPE_VP_VSM,
    .parent = TYPE_DEVICE,
    .instance_size = sizeof(VpVsmState),
    .class_init = vp_vsm_class_init,
};

static void vp_vsm_register_types(void)
{
    type_register_static(&vp_vsm_type_info);
}

type_init(vp_vsm_register_types)

/* guest RAM only: ROMs (firmware, option ROMs) and ROM devices stay */
static int zero_ram_block(RAMBlock *rb, void *opaque)
{
    void *host = qemu_ram_get_host_addr(rb);

    if (!host || !rb->mr || !memory_region_is_ram(rb->mr) ||
        memory_region_is_rom(rb->mr) || memory_region_is_romd(rb->mr)) {
        return 0;
    }
    memset(host, 0, qemu_ram_get_used_length(rb));
    return 0;
}

void hyperv_vsm_zero_memory(void)
{
    qemu_ram_foreach_block(zero_ram_block, NULL);
}

void write_vtl_control(CPUState *cs, const struct hv_vp_vtl_control *ctl)
{
    if (address_space_write(cs->as, hv_vsm_arch_ops.vtl_control_gpa(cs),
                            MEMTXATTRS_UNSPECIFIED, ctl,
                            sizeof(*ctl)) != MEMTX_OK) {
        error_report("hyperv-vsm: VP %u VTL%d: cannot write vtl_control",
                     hyperv_vp_index(cs), active_vtl(cs));
    }
}

void read_vtl_control(CPUState *cs, struct hv_vp_vtl_control *ctl)
{
    if (address_space_read(cs->as, hv_vsm_arch_ops.vtl_control_gpa(cs),
                           MEMTXATTRS_UNSPECIFIED, ctl,
                           sizeof(*ctl)) != MEMTX_OK) {
        error_report("hyperv-vsm: VP %u VTL%d: cannot read vtl_control",
                     hyperv_vp_index(cs), active_vtl(cs));
        memset(ctl, 0, sizeof(*ctl));
    }
}

/*
 * VINA auto_eoi: the guest's VINA handler never EOIs the vector, so
 * KVM_HYPERV_SET_AUTO_EOI keeps it out of the in-service register. The
 * mark exists only while a VTL has auto_eoi enabled.
 */
static void set_vina_auto_eoi(CPUState *cs, uint8_t vector, bool set)
{
#ifdef KVM_HYPERV_SET_AUTO_EOI
    struct kvm_hyperv_auto_eoi arg = {
        .vector = vector,
        .set = set ? KVM_HYPERV_AUTO_EOI_SET : KVM_HYPERV_AUTO_EOI_CLEAR,
    };
    int ret = kvm_vcpu_ioctl(cs, KVM_HYPERV_SET_AUTO_EOI, &arg);

    if (ret < 0) {
        error_report("hyperv-vsm: VP %u VTL%d: %s auto-EOI for vector 0x%x: "
                     "%s", hyperv_vp_index(cs), active_vtl(cs),
                     set ? "set" : "clear", vector, strerror(-ret));
    }
#endif
    /* an SGI edge (arm64) needs no acknowledgement mark */
}

void set_vina(CPUState *cs, uint64_t data)
{
    VpVsmState *vpvsm = get_vp_vsm(cs);
    union hv_register_vsm_vina old = vpvsm->vina;
    union hv_register_vsm_vina new = { .as_uint64 = data };
    bool old_mark = old.enabled && old.auto_eoi;
    bool new_mark = new.enabled && new.auto_eoi;

    vpvsm->vina = new;
    trace_hyperv_vsm_vina_config(hyperv_vp_index(cs), active_vtl(cs), data);

    if (old_mark && (!new_mark || old.vector != new.vector)) {
        set_vina_auto_eoi(cs, old.vector, false);
    }
    if (new_mark && (!old_mark || old.vector != new.vector)) {
        set_vina_auto_eoi(cs, new.vector, true);
    }
}

/*
 * VINA (TLFS 15.2.3): a lower VTL's pending interrupt asserts vina.vector in
 * this VTL and sets vina_asserted in its VP assist page. Nothing is notified
 * again until vina_asserted is clear, by the guest or by auto_reset.
 */
bool vina_asserted(CPUState *cs)
{
    struct hv_vp_vtl_control ctl;

    if (!hv_vsm_arch_ops.vp_assist_enabled(cs)) {
        return false;
    }
    read_vtl_control(cs, &ctl);
    return ctl.vina_asserted;
}

void set_vina_asserted(CPUState *cs, bool asserted)
{
    struct hv_vp_vtl_control ctl;

    if (!hv_vsm_arch_ops.vp_assist_enabled(cs)) {
        return;
    }
    read_vtl_control(cs, &ctl);
    ctl.vina_asserted = asserted;
    write_vtl_control(cs, &ctl);
}

bool hyperv_vsm_vina_armed(CPUState *cs)
{
    VpVsmState *vpvsm = get_vp_vsm(cs);

    return vpvsm && vpvsm->vina.enabled && !vina_asserted(cs);
}

int highest_vtl(uint16_t set)
{
    return 31 - clz32(set);
}

uint16_t hyperv_hcall_vtl_enable_partition_vtl(CPUState *cs, uint64_t param1,
                                               uint64_t param2, bool fast)
{
    union hv_enable_partition_vtl input;

    /* TLFS 15.5.1: fast call only */
    if (!fast) {
        return HV_STATUS_INVALID_HYPERCALL_INPUT;
    }

    input.as_uint64[0] = param1;
    input.as_uint64[1] = param2;

    trace_hyperv_vsm_hcall_enable_partition_vtl(input.target_partition_id,
                                                input.target_vtl,
                                                input.flags.as_uint8);

    if (input.target_partition_id != HV_PARTITION_ID_SELF) {
        return HV_STATUS_INVALID_PARTITION_ID;
    }

    /* MBEC is not advertised */
    if (input.flags.enable_mbec) {
        return HV_STATUS_INVALID_PARAMETER;
    }

    if (input.target_vtl > hv_vsm.partition_status.maximum_vtl) {
        return HV_STATUS_INVALID_PARAMETER;
    }

    if (hv_vsm.partition_status.enabled_vtl_set & BIT(input.target_vtl)) {
        return HV_STATUS_INVALID_PARAMETER;
    }

    /*
     * The caller runs at a VTL at least as high as the new one, or at the
     * highest VTL enabled so far when the new one is higher than that.
     */
    if (active_vtl(cs) < input.target_vtl &&
        active_vtl(cs) !=
        highest_vtl(hv_vsm.partition_status.enabled_vtl_set)) {
        return HV_STATUS_INVALID_PARAMETER;
    }

    if (hv_plane_create(input.target_vtl)) {
        return HV_STATUS_INVALID_PARAMETER;
    }

    hv_vsm.partition_status.enabled_vtl_set |= BIT(input.target_vtl);
    return HV_STATUS_SUCCESS;
}

uint16_t hyperv_hcall_vtl_enable_vp_vtl(CPUState *cs, uint64_t param, bool fast)
{
    CPUState *target_vcpu, *vtl_cpu;
    struct hv_enable_vp_vtl input;
    VpVsmState *vpvsm;

    /* TLFS 15.5.2: neither fast nor rep */
    if (fast) {
        return HV_STATUS_INVALID_HYPERCALL_INPUT;
    }

    if (vsm_physmem_read(cs, param, &input, sizeof(input)) != MEMTX_OK) {
        return HV_STATUS_INVALID_HYPERCALL_INPUT;
    }

    trace_hyperv_vsm_hcall_enable_vp_vtl(input.partition_id, input.vp_index,
                                         input.target_vtl);

    if (input.partition_id != HV_PARTITION_ID_SELF) {
        return HV_STATUS_INVALID_PARTITION_ID;
    }

    if (input.vp_index == HV_VP_INDEX_SELF) {
        input.vp_index = hyperv_vp_index(cs);
    }

    target_vcpu = hv_plane_vcpu(input.vp_index, 0);
    if (!target_vcpu) {
        trace_hyperv_vsm_enable_vp_vtl_reject("no such VP", input.vp_index,
                                              input.target_vtl);
        return HV_STATUS_INVALID_VP_INDEX;
    }
    vpvsm = get_vp_vsm(target_vcpu);

    if (input.target_vtl > hv_vsm.partition_status.maximum_vtl) {
        trace_hyperv_vsm_enable_vp_vtl_reject("VTL above maximum",
                                              input.vp_index, input.target_vtl);
        return HV_STATUS_INVALID_PARAMETER;
    }

    if (!(hv_vsm.partition_status.enabled_vtl_set & BIT(input.target_vtl))) {
        trace_hyperv_vsm_enable_vp_vtl_reject("VTL not enabled for partition",
                                              input.vp_index, input.target_vtl);
        return HV_STATUS_INVALID_PARAMETER;
    }

    if (vpvsm->vp_status.enabled_vtl_set & BIT(input.target_vtl)) {
        trace_hyperv_vsm_enable_vp_vtl_reject("VTL already enabled for VP",
                                              input.vp_index, input.target_vtl);
        return HV_STATUS_INVALID_PARAMETER;
    }

    /*
     * The caller runs at a VTL at least as high as the new one, or at the
     * highest VTL any VP has enabled.
     */
    if (active_vtl(cs) < input.target_vtl &&
        active_vtl(cs) != highest_vtl(hv_vsm.vtl_enabled_for_vps)) {
        return HV_STATUS_INVALID_PARAMETER;
    }

    vtl_cpu = hv_plane_vcpu_create(input.vp_index, input.target_vtl);
    if (!vtl_cpu) {
        return HV_STATUS_INVALID_PARAMETER;
    }

    bql_lock();
    if (vp_start_pending(input.vp_index)) {
        bql_unlock();
        return HV_STATUS_INVALID_VP_STATE;
    }
    hv_vsm_arch_ops.load_vp_context(vtl_cpu, &input.vp_context, true, param);
    cpu_synchronize_post_reset(vtl_cpu);
    bql_unlock();

    /* a VP's enabled VTL set lives in its VTL0 VpVsmState */
    vpvsm->vp_status.enabled_vtl_set |= BIT(input.target_vtl);
    hv_vsm.vtl_enabled_for_vps |= BIT(input.target_vtl);

    return HV_STATUS_SUCCESS;
}

/* TLB lock on the plane-0 vCPU (TLFS 15.5.4 TlbFlushInhibit) */
void set_tlb_flush_inhibit(CPUState *vtl0, bool inhibit)
{
    int ret;

    if (!vtl0) {
        return;
    }
    ret = hv_plane_set_tlb_flush_inhibit(vtl0, inhibit);
    if (ret) {
        qemu_log_mask(LOG_UNIMP, "hyperv-vsm: TLB flush inhibit %d failed: "
                      "%d\n", inhibit, ret);
    }
}

int hyperv_hcall_vtl_call(CPUState *cs, uint64_t *status)
{
    int vtl = active_vtl(cs);

    trace_hyperv_vsm_hcall_vtl_call(hyperv_vp_index(cs), vtl);

    /* TLFS 15.5.7: only a VP's lowest VTL may call up */
    if (vtl != 0) {
        *status = HV_STATUS_ACCESS_DENIED;
        return 0;
    }
    /* the VTL to enter is not enabled on this VP */
    if (!sibling(cs, 1)) {
        *status = HV_STATUS_INVALID_VP_STATE;
        return 0;
    }

    *status = HV_STATUS_SUCCESS;
    return hv_plane_run_vtl(cs, 1, HV_PLANE_SWITCH_VTL_CALL);
}

int hyperv_hcall_vtl_return(CPUState *cs, uint64_t *status)
{
    int vtl = active_vtl(cs);
    CPUState *vtl0;

    trace_hyperv_vsm_hcall_vtl_return(hyperv_vp_index(cs), vtl);

    /* TLFS 15.5.8: a VP's lowest VTL has nowhere to return to */
    if (vtl != 1) {
        *status = HV_STATUS_ACCESS_DENIED;
        return 0;
    }

    vtl0 = sibling(cs, 0);
    if (!vtl0) {
        *status = HV_STATUS_INVALID_VP_STATE;
        return 0;
    }
    set_tlb_flush_inhibit(vtl0, false);

    *status = HV_STATUS_SUCCESS;
    return hv_plane_run_vtl(cs, 0, HV_PLANE_SWITCH_VTL_RETURN);
}

bool get_vp_secure_vtl_config(CPUState *cs, uint32_t reg,
                                     struct hv_u128 *val)
{
    int reg_vtl = reg - HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0;
    int target_vtl = active_vtl(cs);

    /* the register describes a VTL below the one it is read from */
    if (target_vtl == 0 || reg_vtl >= target_vtl) {
        return false;
    }

    val->low_part = get_vp_vsm(cs)->vtl_config[reg_vtl].as_uint64;
    return true;
}

bool set_vp_secure_vtl_config(CPUState *cs, uint32_t reg, uint64_t data)
{
    union hv_register_vsm_vp_secure_vtl_config new_val = { .as_uint64 = data };
    int reg_vtl = reg - HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0;
    int target_vtl = active_vtl(cs);

    if (target_vtl == 0 || reg_vtl >= target_vtl) {
        return false;
    }

    if (new_val.mbec_enabled &&
        !(hv_vsm.capabilities.mbec_vtl_mask & BIT(reg_vtl))) {
        qemu_log_mask(LOG_UNIMP, "hyperv-vsm: MBEC requested for VTL%d, "
                      "ignored\n", reg_vtl);
    }

    get_vp_vsm(cs)->vtl_config[reg_vtl] = new_val;
    return true;
}

void set_vsm_partition_config(uint8_t vtl, uint64_t data)
{
    union hv_register_vsm_partition_config new_val = { .as_uint64 = data };
    union hv_register_vsm_partition_config *cur = &hv_vsm.partition_config[vtl];

    /* enable_vtl_protection and the default mask are write-once */
    if (cur->enable_vtl_protection) {
        new_val.enable_vtl_protection = cur->enable_vtl_protection;
        new_val.default_vtl_protection_mask = cur->default_vtl_protection_mask;
    }

    if (new_val.deny_lower_vtl_startup || new_val.intercept_acceptance ||
        new_val.intercept_enable_vtl_protection ||
        new_val.intercept_vp_startup || new_val.intercept_cpuid_unimplemented ||
        new_val.intercept_unrecoverable_exception || new_val.intercept_page) {
        qemu_log_mask(LOG_UNIMP, "hyperv-vsm: VTL%d partition config 0x%"
                      PRIx64 ": startup deny and intercept bits are not "
                      "advertised, stored only\n", vtl, data);
    }

    /*
     * TLFS 15.6.3: the default mask covers lower-VTL memory with no
     * ModifyVtlProtectionMask entry. Plane attributes default to RWX; any
     * other default would need attributes on every guest page.
     */
    if (new_val.enable_vtl_protection && !cur->enable_vtl_protection &&
        (new_val.default_vtl_protection_mask & HV_MAP_GPA_PERMISSIONS_MASK) !=
        (HV_MAP_GPA_READABLE | HV_MAP_GPA_WRITABLE | HV_MAP_GPA_EXECUTABLE)) {
        qemu_log_mask(LOG_UNIMP, "hyperv-vsm: VTL%d default protection mask "
                      "0x%x not applied, lower VTLs keep full access\n", vtl,
                      (unsigned)new_val.default_vtl_protection_mask);
    }

    *cur = new_val;
}

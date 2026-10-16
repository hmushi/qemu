/*
 * QEMU KVM Hyper-V Virtual Secure Mode (VSM): target-neutral core
 *
 * Partition and per-VP VTL state, the VSM hypercalls (TLFS chapter 15), VINA
 * and lower-VTL memory protections. KVM is reached only through the plane
 * API, the target's register file only through hv_vsm_arch_ops.
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

/* registers handled per call; bounds the stack use, not a TLFS limit */
#define VP_REGISTER_LIST_SIZE 16u

/* a rejected call applies no register; the trace is its only record */
static uint64_t reject_vp_register_hcall(CPUState *cs, const char *why,
                                         uint16_t rep_cnt, uint16_t rep_idx,
                                         bool fast, bool set, uint64_t status)
{
    trace_hyperv_vsm_vp_register_hcall_reject(why, rep_cnt, rep_idx, fast, set,
                                              hyperv_vp_index(cs),
                                              active_vtl(cs), status);
    return status;
}

uint64_t hyperv_hcall_get_set_vp_register(CPUState *cs,
                                          struct kvm_hyperv_exit *exit,
                                          bool set)
{
    uint64_t in = exit->u.hcall.input;
    uint16_t rep_cnt = (in >> HV_HYPERCALL_REP_COMP_OFFSET) & 0xfff;
    uint16_t rep_idx = (in >> HV_HYPERCALL_REP_START_OFFSET) & 0xfff;
    bool fast = exit->u.hcall.input & HV_HYPERCALL_FAST;
    MachineState *ms = MACHINE(qdev_get_machine());
    struct hv_u128 vals[VP_REGISTER_LIST_SIZE];
    uint32_t names[VP_REGISTER_LIST_SIZE];
    struct hv_input_get_vp_registers input;
    uint16_t xmm_index = 0;
    CPUState *target_vcpu;
    bool dirty = false;
    uint16_t status = HV_STATUS_SUCCESS;
    uint16_t nregs;
    uint8_t vtl;
    int i;

    if (rep_idx >= rep_cnt) {
        return reject_vp_register_hcall(cs, "rep_idx past rep_cnt",
                                        rep_cnt, rep_idx, fast, set,
                                        HV_STATUS_INVALID_HYPERCALL_INPUT);
    }
    nregs = MIN(rep_cnt - rep_idx, VP_REGISTER_LIST_SIZE);

    if (fast) {
        /* names (and values) travel in XMM registers */
        if (!hv_exit_has_xmm(exit)) {
            return reject_vp_register_hcall(cs, "fast call without XMM",
                                            rep_cnt, rep_idx, fast, set,
                                            HV_STATUS_INVALID_HYPERCALL_INPUT);
        }
        input.partition_id = exit->u.hcall.params[0];
        input.vp_index = exit->u.hcall.params[1] & 0xffffffff;
        input.input_vtl.as_uint8 = (exit->u.hcall.params[1] >> 32) & 0xff;

        /* everything is returned at once, so no continuation */
        if (rep_idx != 0) {
            return reject_vp_register_hcall(cs, "fast call with rep_idx",
                                            rep_cnt, rep_idx, fast, set,
                                            HV_STATUS_INVALID_HYPERCALL_INPUT);
        }

        /* 6 XMM registers hold at most 4 names plus 4 values */
        if (nregs > 4) {
            return reject_vp_register_hcall(cs, "fast call over 4 registers",
                                            rep_cnt, rep_idx, fast, set,
                                            HV_STATUS_INVALID_HYPERCALL_INPUT);
        }

        for (i = 0; i < nregs; i += 4, xmm_index += 2) {
            names[i] = hv_exit_xmm_get(exit, xmm_index);
            names[i + 1] = hv_exit_xmm_get(exit, xmm_index) >> 32;
            names[i + 2] = hv_exit_xmm_get(exit, xmm_index + 1);
            names[i + 3] = hv_exit_xmm_get(exit, xmm_index + 1) >> 32;
        }

        if (set) {
            for (i = 0; i < nregs; i++, xmm_index += 2) {
                vals[i].low_part = hv_exit_xmm_get(exit, xmm_index);
                vals[i].high_part = hv_exit_xmm_get(exit, xmm_index + 1);
            }
        }
    } else {
        uint64_t ingpa = exit->u.hcall.params[0];

        if (vsm_physmem_read(cs, ingpa, &input, sizeof(input)) != MEMTX_OK) {
            return reject_vp_register_hcall(cs, "input header unreadable",
                                            rep_cnt, rep_idx, fast, set,
                                            HV_STATUS_INVALID_HYPERCALL_INPUT);
        }

        if (set) {
            /* a set carries the name and the value of each register together */
            hv_register_assoc elements[VP_REGISTER_LIST_SIZE];

            ingpa += sizeof(input) + rep_idx * sizeof(*elements);
            if (vsm_physmem_read(cs, ingpa, elements,
                                 nregs * sizeof(*elements)) != MEMTX_OK) {
                return reject_vp_register_hcall(
                    cs, "element list unreadable", rep_cnt, rep_idx, fast, set,
                    HV_STATUS_INVALID_HYPERCALL_INPUT);
            }

            for (i = 0; i < nregs; i++) {
                names[i] = elements[i].name;
                vals[i] = elements[i].value.reg128;
            }
        } else {
            ingpa += sizeof(input) + rep_idx * sizeof(*names);
            if (vsm_physmem_read(cs, ingpa, names,
                                 nregs * sizeof(*names)) != MEMTX_OK) {
                return reject_vp_register_hcall(cs, "name list unreadable",
                                                rep_cnt, rep_idx, fast, set,
                                                HV_STATUS_INVALID_HYPERCALL_INPUT);
            }
        }
    }

    if (input.partition_id != HV_PARTITION_ID_SELF) {
        return reject_vp_register_hcall(cs, "partition not self",
                                        rep_cnt, rep_idx, fast, set,
                                        HV_STATUS_INVALID_PARTITION_ID);
    }

    if (input_vtl_targets(input.input_vtl)) {
        vtl = input.input_vtl.target_vtl;
        if (vtl >= HV_NUM_VTLS) {
            return reject_vp_register_hcall(cs, "target VTL out of range",
                                            rep_cnt, rep_idx, fast, set,
                                            HV_STATUS_INVALID_HYPERCALL_INPUT);
        }
        if (vtl > active_vtl(cs)) {
            return reject_vp_register_hcall(cs, "target VTL above caller",
                                            rep_cnt, rep_idx, fast, set,
                                            HV_STATUS_ACCESS_DENIED);
        }
    } else {
        vtl = active_vtl(cs);
    }

    if (input.vp_index == HV_VP_INDEX_SELF) {
        input.vp_index = hyperv_vp_index(cs);
    } else if (input.vp_index >= ms->smp.max_cpus) {
        return reject_vp_register_hcall(cs, "VP index out of range",
                                        rep_cnt, rep_idx, fast, set,
                                        HV_STATUS_INVALID_VP_INDEX);
    }

    target_vcpu = hv_plane_vcpu(input.vp_index, vtl);
    if (!target_vcpu) {
        return reject_vp_register_hcall(cs, "no vCPU for VP and VTL",
                                        rep_cnt, rep_idx, fast, set,
                                        HV_STATUS_INVALID_VP_INDEX);
    }

    trace_hyperv_vsm_hcall_get_set_vp_registers(input.partition_id,
                                                input.vp_index, vtl,
                                                active_vtl(cs), nregs, set,
                                                hyperv_vp_index(cs));

    bql_lock();
    if (vp_start_pending(input.vp_index)) {
        bql_unlock();
        return reject_vp_register_hcall(cs, "start in flight on the VP",
                                        rep_cnt, rep_idx, fast, set,
                                        HV_STATUS_INVALID_VP_STATE);
    }
    cpu_synchronize_state(target_vcpu);
    for (i = 0; i < nregs; i++) {
        status = set ?
                 hv_vsm_arch_ops.set_vp_register(names[i], &vals[i],
                                                 target_vcpu, &dirty) :
                 hv_vsm_arch_ops.get_vp_register(names[i], &vals[i],
                                                 target_vcpu);
        if (status != HV_STATUS_SUCCESS) {
            break;
        }
    }
    if (dirty) {
        cpu_synchronize_post_reset(target_vcpu);
    }
    bql_unlock();

    /*
     * Repeats before a failure stay applied. Report how many (@i) with the
     * status, so the guest can resume (TLFS 3.9).
     */
    if (!set && i > 0) {
        if (fast) {
            int j;

            for (j = 0; j < i; j++, xmm_index += 2) {
                hv_exit_xmm_set(exit, xmm_index, vals[j].low_part);
                hv_exit_xmm_set(exit, xmm_index + 1, vals[j].high_part);
            }
        } else {
            uint64_t outgpa = exit->u.hcall.params[1] + rep_idx * sizeof(*vals);

            vsm_physmem_write(cs, outgpa, vals, sizeof(*vals) * i);
        }
    }

    return (uint64_t)status |
           ((uint64_t)i << HV_HYPERCALL_REP_COMP_OFFSET);
}

uint32_t translate_result_code(const struct kvm_translation2 *tr,
                                      uint64_t control_flags)
{
    switch (tr->error_code) {
    case KVM_TRANSLATE_FAULT_NOT_PRESENT:
    case KVM_TRANSLATE_FAULT_INVALID_GVA:
        return HV_TRANSLATE_GVA_PAGE_NOT_PRESENT;
    case KVM_TRANSLATE_FAULT_PRIVILEGE_VIOLATION:
        return HV_TRANSLATE_GVA_PRIVILEGE_VIOLATION;
    case KVM_TRANSLATE_FAULT_RESERVED_BITS:
        return HV_TRANSLATE_GVA_INVALIDE_PAGE_TABLE_FLAGS;
    case KVM_TRANSLATE_FAULT_INVALID_GPA:
        return HV_TRANSLATE_GVA_GPA_UNMAPPED;
    default:
        if (!tr->set_bits_succeeded &&
            (control_flags & HV_TRANSLATE_GVA_SET_PAGE_TABLE_BITS)) {
            return HV_TRANSLATE_GVA_GPA_NO_WRITE_ACCESS;
        }
        qemu_log_mask(LOG_UNIMP, "hyperv-vsm: KVM_TRANSLATE2 error code %u "
                      "not mapped\n", tr->error_code);
        return HV_TRANSLATE_GVA_PRIVILEGE_VIOLATION;
    }
}

uint16_t hyperv_vsm_translate_gva(
        CPUState *cs,
        const struct hv_input_translate_virtual_address *in,
        struct hv_output_translate_virtual_address *out)
{
    uint64_t flags = in->control_flags & HV_TRANSLATE_GVA_FLAGS_MASK;
    uint32_t vp_index = in->vp_index;
    CPUState *target_vcpu;
    union hv_input_vtl in_vtl;
    uint64_t gpa_page = 0;
    uint8_t target_vtl;
    bool overlay = false;
    uint32_t result;

    if (!hv_vsm_arch_ops.translate_gva) {
        return HV_STATUS_INVALID_HYPERCALL_CODE;
    }
    if (in->partition_id != HV_PARTITION_ID_SELF) {
        return HV_STATUS_INVALID_PARTITION_ID;
    }

    /*
     * The target VTL rides in the top byte of the control word and the
     * flags in its low six bits, so neither can reach the other.
     */
    in_vtl.as_uint8 = in->control_flags >> HV_TRANSLATE_GVA_INPUT_VTL_SHIFT;
    if (input_vtl_targets(in_vtl)) {
        target_vtl = in_vtl.target_vtl;
        /* a VTL may translate for itself and below, never above */
        if (target_vtl > active_vtl(cs)) {
            return HV_STATUS_INVALID_VP_STATE;
        }
    } else {
        target_vtl = active_vtl(cs);
    }

    if (vp_index == HV_ANY_VP) {
        return HV_STATUS_INVALID_VP_INDEX;
    }
    if (vp_index == HV_VP_INDEX_SELF) {
        vp_index = hyperv_vp_index(cs);
    }
    target_vcpu = hv_plane_vcpu(vp_index, target_vtl);
    if (!target_vcpu) {
        return HV_STATUS_INVALID_VP_INDEX;
    }
    /* a VP whose start packet has not been applied has no tables to walk */
    if (vp_start_pending(vp_index)) {
        return HV_STATUS_INVALID_VP_STATE;
    }

    result = hv_vsm_arch_ops.translate_gva(target_vcpu, in->gva_page, flags,
                                           &gpa_page, &overlay);

    memset(out, 0, sizeof(*out));
    out->translation_result.result_code = result;
    if (result == HV_TRANSLATE_GVA_SUCCESS) {
        out->gpa_page = gpa_page;
        out->translation_result.cache_type = HV_CACHE_TYPE_WRITE_BACK;
        out->translation_result.overlay_page = overlay;
        if (flags & HV_TRANSLATE_GVA_TLB_FLUSH_INHIBIT) {
            set_tlb_flush_inhibit(sibling(cs, 0), true);
        }
    }

    trace_hyperv_vsm_translate_gva(hyperv_vp_index(cs), active_vtl(cs),
                                   vp_index, target_vtl, in->control_flags,
                                   in->gva_page, out->gpa_page,
                                   out->translation_result.overlay_page,
                                   result);
    return HV_STATUS_SUCCESS;
}

/* the guest acknowledged the message that kept the slot busy: post again */
static void intercept_repost_bh(void *data)
{
    VpVsmState *vpvsm = data;
    int ret;

    if (!vpvsm->intercept_route) {
        return;
    }
    ret = hyperv_post_msg(vpvsm->intercept_route, &vpvsm->intercept_msg);
    if (ret) {
        /* the staging area is still busy: keep the message for the next try */
        vpvsm->intercept_pending = true;
        qemu_log_mask(LOG_GUEST_ERROR, "hyperv-vsm: VP %u VTL%d intercept "
                      "message could not be reposted, status %d\n",
                      hyperv_vp_index(vpvsm->cs), active_vtl(vpvsm->cs), ret);
    }
}

/*
 * Keep a message that did not reach the slot: the lower VTL repeats the
 * faulting instruction, so waiting loses nothing and dropping loses the fault.
 */
static void intercept_hold(VpVsmState *vpvsm, int status, const char *why)
{
    vpvsm->intercept_pending = true;
    qemu_log_mask(LOG_UNIMP, "hyperv-vsm: VP %u VTL%d intercept message held,"
                  " %s (status %d)\n", hyperv_vp_index(vpvsm->cs),
                  active_vtl(vpvsm->cs), why, status);
}

/*
 * @cs's SynIC can deliver now. Post the held intercept from the main loop,
 * because the caller may be a vCPU thread mid-hypercall.
 */
void hyperv_vsm_intercept_retry(CPUState *cs)
{
    VpVsmState *vpvsm = get_vp_vsm(cs);

    if (!vpvsm || !vpvsm->intercept_pending || !vpvsm->intercept_route) {
        return;
    }
    vpvsm->intercept_pending = false;
    aio_bh_schedule_oneshot(qemu_get_aio_context(), intercept_repost_bh,
                            vpvsm);
}

/*
 * Completion of an intercept post, @status as cpu_post_msg() reports it. No
 * status drops the message.
 */
void intercept_cb(void *data, int status)
{
    VpVsmState *vpvsm = data;

    switch (status) {
    case 0:
        /*
         * In the slot. A synchronous intercept needs no SINT line: the VTL
         * switch after the fault is the notification.
         */
        vpvsm->intercept_pending = false;
        return;

    case -EAGAIN:
        /*
         * The slot is busy and flagged pending, so the guest's EOM completes
         * this route. The staging slot is not free yet, so a post from here
         * would fail: repost from the main loop.
         */
        aio_bh_schedule_oneshot(qemu_get_aio_context(), intercept_repost_bh,
                                vpvsm);
        return;

    case -ENXIO:
        /*
         * The target VTL has not enabled its message page. Hold the message
         * until it does; hyperv_vsm_intercept_retry() posts it then.
         */
        intercept_hold(vpvsm, status, "the target VTL has no message page");
        return;

    default:
        /* the SINT line could not be raised, or an unmodelled refusal */
        intercept_hold(vpvsm, status, "the SynIC did not take the message");
        return;
    }
}

int kvm_hv_handle_fault(CPUState *cs, uint64_t gpa, uint64_t size,
                        uint64_t flags)
{
    int vtl = active_vtl(cs);
    GHashTable *prots = hv_vsm.prots[vtl];
    uint64_t gfn = gpa >> HV_HYP_PAGE_SHIFT;
    struct hyperv_message msg = {};
    CPUState *next;
    uint64_t prot;

    if (!prots || !g_hash_table_contains(prots, GUINT_TO_POINTER(gfn))) {
        qemu_log_mask(LOG_GUEST_ERROR, "hyperv-vsm: unexpected memory fault on "
                      "VP %u VTL%d gpa 0x%" PRIx64 " size 0x%" PRIx64
                      " flags 0x%" PRIx64 "\n", hyperv_vp_index(cs), vtl, gpa,
                      size, flags);
        return -1;
    }

    prot = GPOINTER_TO_UINT(g_hash_table_lookup(prots, GUINT_TO_POINTER(gfn)));
    trace_hyperv_vsm_handle_fault(hyperv_vp_index(cs), vtl, gpa, size, flags,
                                  prot);

    next = sibling(cs, vtl + 1);
    if (!next) {
        return -1;
    }

    cpu_synchronize_state(cs);
    hv_vsm_arch_ops.build_memory_intercept(cs, &msg, gpa, flags);
    if (hv_vsm_arch_ops.deliver_memory_intercept(next, &msg)) {
        return -1;
    }

    return hv_plane_run_vtl(cs, vtl + 1, HV_PLANE_SWITCH_INTERCEPT);
}

/* HV_MAP_GPA_* permissions to plane access restrictions */
static uint64_t map_flags_to_memattrs(uint32_t flags)
{
    uint64_t attrs = KVM_MEMORY_ATTRIBUTE_NR | KVM_MEMORY_ATTRIBUTE_NW |
                     KVM_MEMORY_ATTRIBUTE_NX;

    if (flags & HV_MAP_GPA_READABLE) {
        attrs &= ~KVM_MEMORY_ATTRIBUTE_NR;
    }
    if (flags & HV_MAP_GPA_WRITABLE) {
        attrs &= ~KVM_MEMORY_ATTRIBUTE_NW;
    }
    if (flags & HV_MAP_GPA_EXECUTABLE) {
        attrs &= ~KVM_MEMORY_ATTRIBUTE_NX;
    }

    return attrs;
}

int set_memory_attrs_range(uint8_t vtl, uint64_t start, uint64_t end,
                                  uint64_t attrs)
{
    hwaddr addr = start << HV_HYP_PAGE_SHIFT;
    hwaddr size = (end - start) << HV_HYP_PAGE_SHIFT;
    int ret;

    trace_hyperv_vsm_set_memory_attrs(vtl, addr, size, attrs);
    ret = hv_plane_set_memory_attrs(vtl, addr, size, attrs);
    if (ret) {
        qemu_log_mask(LOG_UNIMP, "hyperv-vsm: cannot set attrs 0x%" PRIx64
                      " on VTL%d [0x%" HWADDR_PRIx ", 0x%" HWADDR_PRIx
                      "): %d\n", attrs, vtl, addr, addr + size, ret);
    }
    return ret;
}

/* Apply @flags to the sorted @gfn_list for @vtl, coalescing contiguous GFNs */
static int set_memory_attrs(uint8_t vtl, uint32_t flags, uint16_t count,
                            const uint64_t *gfn_list)
{
    uint64_t attrs = map_flags_to_memattrs(flags);
    uint64_t start, end;
    int i, ret;

    if (!hv_vsm.prots[vtl]) {
        hv_vsm.prots[vtl] = g_hash_table_new(g_direct_hash, g_direct_equal);
    }

    start = gfn_list[0];
    end = start + 1;
    for (i = 1; i < count; i++) {
        if (gfn_list[i] == end) {
            end++;
            continue;
        }
        ret = set_memory_attrs_range(vtl, start, end, attrs);
        if (ret) {
            return ret;
        }
        start = gfn_list[i];
        end = start + 1;
    }
    ret = set_memory_attrs_range(vtl, start, end, attrs);
    if (ret) {
        return ret;
    }

    for (i = 0; i < count; i++) {
        g_hash_table_insert(hv_vsm.prots[vtl], GUINT_TO_POINTER(gfn_list[i]),
                            GUINT_TO_POINTER(flags));
    }

    return 0;
}

/* Shared tail of both input forms: @count GFNs of @gfn_list under @input */
static uint64_t
vtl_protection_mask_apply(CPUState *cs,
                          const union hv_modify_vtl_protection_mask *input,
                          uint16_t count, const uint64_t *gfn_list)
{
    uint8_t target_vtl;

    trace_hyperv_vsm_hcall_vtl_protection_mask(input->target_partition_id,
                                               input->map_flags,
                                               input->input_vtl.target_vtl,
                                               count);

    if (input->target_partition_id != HV_PARTITION_ID_SELF) {
        return HV_STATUS_INVALID_PARTITION_ID;
    }

    /* protections apply to a lower VTL; default is the one right below */
    if (input_vtl_targets(input->input_vtl)) {
        target_vtl = input->input_vtl.target_vtl;
        if (target_vtl >= active_vtl(cs)) {
            return HV_STATUS_ACCESS_DENIED;
        }
    } else {
        if (active_vtl(cs) == 0) {
            return HV_STATUS_INVALID_PARAMETER;
        }
        target_vtl = active_vtl(cs) - 1;
    }

    if (target_vtl >= HV_NUM_VTLS) {
        return HV_STATUS_INVALID_PARAMETER;
    }

    if (set_memory_attrs(target_vtl, input->map_flags, count, gfn_list)) {
        return HV_STATUS_INVALID_PARAMETER;
    }

    return (uint64_t)count << HV_HYPERCALL_REP_COMP_OFFSET;
}

/*
 * Rep start and reps completed mean what they do in the memory form: the
 * GFN list is indexed by rep.
 */
uint64_t hyperv_hcall_vtl_protection_mask_regs(CPUState *cs, uint64_t control,
                                               const uint64_t *regs,
                                               unsigned nregs)
{
    const unsigned hdr = sizeof(union hv_modify_vtl_protection_mask) /
                         sizeof(uint64_t);
    union hv_modify_vtl_protection_mask input;
    unsigned first;
    uint16_t count;

    /* the list is not in memory, so a window too short is a refusal */
    if (!hv_hcall_rep_regs_window(control, nregs, hdr, &first, &count)) {
        return HV_STATUS_INVALID_HYPERCALL_INPUT;
    }

    input.as_uint64[0] = regs[0];
    input.as_uint64[1] = regs[1];

    return vtl_protection_mask_apply(cs, &input, count, regs + first);
}

uint64_t hyperv_hcall_vtl_protection_mask_mem(CPUState *cs, uint64_t control,
                                              uint64_t ingpa)
{
    uint16_t rep_cnt = (control >> HV_HYPERCALL_REP_COMP_OFFSET) & 0xfff;
    uint16_t rep_idx = (control >> HV_HYPERCALL_REP_START_OFFSET) & 0xfff;
    union hv_modify_vtl_protection_mask input;
    g_autofree uint64_t *gfn_list = NULL;
    uint16_t count;

    if (rep_idx >= rep_cnt) {
        return HV_STATUS_INVALID_HYPERCALL_INPUT;
    }
    count = rep_cnt - rep_idx;

    if (vsm_physmem_read(cs, ingpa, &input, sizeof(input)) != MEMTX_OK) {
        return HV_STATUS_INVALID_HYPERCALL_INPUT;
    }

    gfn_list = g_new0(uint64_t, count);
    ingpa += sizeof(input) + rep_idx * sizeof(*gfn_list);
    if (vsm_physmem_read(cs, ingpa, gfn_list,
                         count * sizeof(*gfn_list)) != MEMTX_OK) {
        return HV_STATUS_INVALID_HYPERCALL_INPUT;
    }

    return vtl_protection_mask_apply(cs, &input, count, gfn_list);
}

uint64_t hyperv_hcall_vtl_protection_mask(CPUState *cs,
                                          struct kvm_hyperv_exit *exit)
{
    uint64_t in = exit->u.hcall.input;
    uint16_t rep_cnt = (in >> HV_HYPERCALL_REP_COMP_OFFSET) & 0xfff;
    uint16_t rep_idx = (in >> HV_HYPERCALL_REP_START_OFFSET) & 0xfff;
    union hv_modify_vtl_protection_mask input;
    g_autofree uint64_t *gfn_list = NULL;
    uint16_t count, i;

    if (!(in & HV_HYPERCALL_FAST)) {
        return hyperv_hcall_vtl_protection_mask_mem(cs, in,
                                                    exit->u.hcall.params[0]);
    }

    if (rep_idx >= rep_cnt) {
        return HV_STATUS_INVALID_HYPERCALL_INPUT;
    }
    count = rep_cnt - rep_idx;

    input.as_uint64[0] = exit->u.hcall.params[0];
    input.as_uint64[1] = exit->u.hcall.params[1];

    /* GFNs travel in XMM; everything is consumed at once */
    if (!hv_exit_has_xmm(exit) || rep_idx != 0 ||
        count > 2 * HV_HYPERCALL_MAX_XMM_REGISTERS) {
        return HV_STATUS_INVALID_HYPERCALL_INPUT;
    }

    gfn_list = g_new0(uint64_t, count);
    for (i = 0; i < count; i++) {
        gfn_list[i] = hv_exit_xmm_get(exit, i);
    }

    return vtl_protection_mask_apply(cs, &input, count, gfn_list);
}

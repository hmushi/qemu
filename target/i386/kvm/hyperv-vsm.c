/*
 * QEMU KVM Hyper-V Virtual Secure Mode (VSM) support
 *
 * Hypercall handlers, per-VP VTL state and the GPA intercept builder for
 * TLFS chapter 15. Everything that touches KVM goes through the plane API
 * (include/hw/hyperv/vsm-plane-api.h).
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
#include "exec/target_page.h"
#include "system/address-spaces.h"
#include "system/cpus.h"
#include "system/reset.h"
#include "system/hw_accel.h"
#include "system/memory.h"
#include "system/ramblock.h"
#include "system/ramlist.h"
#include "hw/core/boards.h"
#include "hw/core/cpu.h"
#include "hw/i386/apic_internal.h"
#include "hw/i386/apic-msidef.h"
#include "hw/pci/msi.h"
#include "hw/hyperv/hyperv.h"
#include "cpu.h"
#include "kvm_i386.h"
#include "hyperv-vsm.h"
#include "trace.h"

/* Partition-wide VSM state */
static struct {
    GHashTable *prots[HV_NUM_VTLS];
    /* bit N set: VTL N is enabled on at least one VP */
    uint16_t vtl_enabled_for_vps;
    union hv_register_vsm_code_page_offsets code_page_offsets;
    union hv_register_vsm_partition_status partition_status;
    union hv_register_vsm_capabilities capabilities;
    union hv_register_vsm_partition_config partition_config[HV_NUM_VTLS];
    /* HV_X64_MSR_HYPERCALL is partition-wide (TLFS 3.13): one per VTL */
    uint64_t hypercall[HV_NUM_VTLS];
} hv_vsm = {
    .vtl_enabled_for_vps = BIT(0),
    .partition_status = {
        .enabled_vtl_set = BIT(0),
        .maximum_vtl = HV_NUM_VTLS - 1,
    },
    .capabilities = { .dr6_shared = 0 },
};

/* Per-VP, per-VTL state (child "vp-vsm" of the CPUState of that VTL) */
struct VpVsmState {
    DeviceState parent_obj;

    CPUState *cs;
    union hv_register_vsm_vp_status vp_status;
    union hv_register_vsm_vp_secure_vtl_config vtl_config[HV_NUM_VTLS];
    uint64_t msr_hv_vp_assist;
    HvSintRoute *intercept_route;
    struct hyperv_message intercept_msg;
    /* HvRegisterVsmVina (TLFS 15.6.5) */
    union hv_register_vsm_vina vina;
};

#define TYPE_VP_VSM "hyperv-vp-vsm"
OBJECT_DECLARE_SIMPLE_TYPE(VpVsmState, VP_VSM)

static VpVsmState *get_vp_vsm(CPUState *cs)
{
    return VP_VSM(object_resolve_path_component(OBJECT(cs), "vp-vsm"));
}

static int active_vtl(CPUState *cs)
{
    return hv_plane_active_vtl(cs);
}

static CPUState *sibling(CPUState *cs, int vtl)
{
    return hv_plane_vcpu(hyperv_vp_index(cs), vtl);
}

/* HV_INPUT_VTL names a target VTL; 0xff (securekernel) means the caller's */
static bool input_vtl_targets(union hv_input_vtl in_vtl)
{
    return in_vtl.use_target_vtl && in_vtl.as_uint8 != 0xff;
}

static MemTxResult vsm_physmem_write(CPUState *cs, hwaddr addr,
                                     const void *buf, hwaddr len)
{
    return address_space_write(cs->as, addr, MEMTXATTRS_UNSPECIFIED, buf, len);
}

static MemTxResult vsm_physmem_read(CPUState *cs, hwaddr addr,
                                    void *buf, hwaddr len)
{
    return address_space_read(cs->as, addr, MEMTXATTRS_UNSPECIFIED, buf, len);
}

/*
 * Hypercall page: VMCALL/VMMCALL stub plus the VTL call/return entry stubs.
 * Written by any VP of the VTL, in effect for all of them. Two VTLs may
 * enable the same page: each write puts the same stubs there. A disable
 * writes nothing, as the guest may still be returning through the page.
 */
static void setup_hypercall_page(CPUState *cs, uint64_t data)
{
    hwaddr gpa = data & HV_X64_MSR_HYPERCALL_PAGE_ADDRESS_MASK;
    bool enable = !!(data & HV_X64_MSR_HYPERCALL_ENABLE);
    int vtl = active_vtl(cs);
    uint32_t ebx = 0, ecx = 0, edx = 0;
    char vendor[CPUID_VENDOR_SZ + 1];
    uint8_t insn[0x30] = {};
    int i = 0;

    if (!get_vp_vsm(cs)) {
        return;
    }
    trace_hyperv_vsm_setup_hypercall_page(hyperv_vp_index(cs), vtl, enable,
                                          gpa);

    hv_vsm.hypercall[vtl] = data;

    if (!enable) {
        return;
    }

    /* Intel VMCALL or AMD VMMCALL, then ret */
    host_cpuid(0, 0, NULL, &ebx, &ecx, &edx);
    x86_cpu_vendor_words2str(vendor, ebx, edx, ecx);
    insn[i++] = 0x0f;
    insn[i++] = 0x01;
    insn[i++] = !strcmp(vendor, "GenuineIntel") ? 0xc1 : 0xd9;
    insn[i++] = 0xc3;

    /* 64-bit only; 32-bit guests need their own stubs (TLFS 15.5.7) */
    i = 22;
    /* VTL call: mov %rcx,%rax; mov $0x11,%ecx; jmp 0 */
    hv_vsm.code_page_offsets.vtl_call_offset = i;
    insn[i++] = 0x48;
    insn[i++] = 0x89;
    insn[i++] = 0xc8;
    insn[i++] = 0xb9;
    insn[i++] = HVCALL_VTL_CALL;
    insn[i++] = 0x00;
    insn[i++] = 0x00;
    insn[i++] = 0x00;
    insn[i++] = 0xeb;
    insn[i++] = 0xe0;
    /* VTL return: mov %rcx,%rax; mov $0x12,%ecx; jmp 0 */
    hv_vsm.code_page_offsets.vtl_return_offset = i;
    insn[i++] = 0x48;
    insn[i++] = 0x89;
    insn[i++] = 0xc8;
    insn[i++] = 0xb9;
    insn[i++] = HVCALL_VTL_RETURN;
    insn[i++] = 0x00;
    insn[i++] = 0x00;
    insn[i++] = 0x00;
    insn[i++] = 0xeb;
    insn[i++] = 0xd6;

    if (address_space_write(cs->as, gpa, MEMTXATTRS_UNSPECIFIED, insn, i)
        != MEMTX_OK) {
        error_report("hyperv-vsm: cannot write the hypercall page at 0x%"
                     HWADDR_PRIx, gpa);
    }
}

static bool hypercall_page_wrmsr(X86CPU *cpu, uint32_t msr, uint64_t val)
{
    if (msr != HV_X64_MSR_HYPERCALL) {
        return false;
    }

    setup_hypercall_page(CPU(cpu), val);
    return true;
}

/* the write never reaches KVM, so the read is served from the VTL's copy */
static bool hypercall_page_rdmsr(X86CPU *cpu, uint32_t msr, uint64_t *val)
{
    if (msr != HV_X64_MSR_HYPERCALL) {
        return false;
    }

    *val = hv_vsm.hypercall[active_vtl(CPU(cpu))];
    trace_hyperv_vsm_hypercall_msr_read(hyperv_vp_index(CPU(cpu)),
                                        active_vtl(CPU(cpu)), *val);
    return true;
}

/*
 * The VTL1 secure kernel leaves reserved high bits set in HV_X64_MSR_EOI;
 * clear them before KVM sees the write. VTL0 writes pass through unchanged.
 */
static bool msr_eoi_wrmsr(X86CPU *cpu, uint32_t msr, uint64_t val)
{
    CPUState *cs = CPU(cpu);
    int ret;

    if (msr != HV_X64_MSR_EOI) {
        return false;
    }

    if (active_vtl(cs) == 1) {
        trace_hyperv_vsm_msr_eoi_fixup(hyperv_vp_index(cs), val);
        val &= 0xffffffff;
    }

    ret = kvm_put_one_msr(cpu, HV_X64_MSR_EOI, val);
    if (ret < 0) {
        error_report("hyperv-vsm: HV_X64_MSR_EOI write failed: %d", ret);
        return false;
    }

    return true;
}

/* KVM clears apic_assist on the write; the rest of the page is the guest's */
static void setup_vp_assist(CPUState *cs, uint64_t data)
{
    hwaddr gpa = data & HV_X64_MSR_VP_ASSIST_PAGE_ADDRESS_MASK;
    bool enable = !!(data & HV_X64_MSR_VP_ASSIST_PAGE_ENABLE);
    VpVsmState *vpvsm = get_vp_vsm(cs);

    trace_hyperv_vsm_setup_vp_assist_page(hyperv_vp_index(cs), active_vtl(cs),
                                          enable, gpa);
    if (vpvsm) {
        vpvsm->msr_hv_vp_assist = data;
    }
}

static bool vp_assist_page_wrmsr(X86CPU *cpu, uint32_t msr, uint64_t val)
{
    if (msr != HV_X64_MSR_APIC_ASSIST_PAGE) {
        return false;
    }

    setup_vp_assist(CPU(cpu), val);
    kvm_put_hv_vp_assist(cpu, val);
    return true;
}

static bool vp_assist_page_rdmsr(X86CPU *cpu, uint32_t msr, uint64_t *val)
{
    if (msr != HV_X64_MSR_APIC_ASSIST_PAGE) {
        return false;
    }

    *val = get_vp_vsm(CPU(cpu))->msr_hv_vp_assist;
    return true;
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

static int set_memory_attrs_range(uint8_t vtl, uint64_t start, uint64_t end,
                                  uint64_t attrs);

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

static void hyperv_vsm_zero_memory(void)
{
    qemu_ram_foreach_block(zero_ram_block, NULL);
}

/*
 * System reset with VSM enabled: the guest starts over in VTL0 with no VTL
 * enabled. The KVM planes and plane vCPUs persist (the kernel cannot
 * destroy them); the CPU reset handlers put the plane vCPUs in reset state
 * and the plane layer makes every VP run plane 0 again. Here the per-VP and
 * partition-wide VSM state goes back to its initial values and the lower
 * VTLs' memory protections are lifted.
 */
static void set_vina(CPUState *cs, uint64_t data);

static void hyperv_vsm_reset(void *opaque)
{
    CPUState *cs;
    int vtl;

    CPU_FOREACH(cs) {
        VpVsmState *vpvsm = get_vp_vsm(cs);

        if (!vpvsm) {
            continue;
        }
        setup_hypercall_page(cs, 0);
        setup_vp_assist(cs, 0);
        if (vpvsm->intercept_route) {
            hyperv_sint_route_unref(vpvsm->intercept_route);
            vpvsm->intercept_route = NULL;
        }
        memset(vpvsm->vtl_config, 0, sizeof(vpvsm->vtl_config));
        set_vina(cs, 0);
        vpvsm->vp_status.as_uint64 = 0;
        vpvsm->vp_status.enabled_vtl_set = BIT(0);
        vpvsm->vp_status.active_vtl = active_vtl(cs);
    }

    for (vtl = 0; vtl < HV_NUM_VTLS; vtl++) {
        GHashTableIter it;
        gpointer gfn;

        if (!hv_vsm.prots[vtl]) {
            continue;
        }
        g_hash_table_iter_init(&it, hv_vsm.prots[vtl]);
        while (g_hash_table_iter_next(&it, &gfn, NULL)) {
            uint64_t g = GPOINTER_TO_UINT(gfn);

            set_memory_attrs_range(vtl, g, g + 1, 0);
        }
        g_hash_table_destroy(hv_vsm.prots[vtl]);
        hv_vsm.prots[vtl] = NULL;
    }

    /*
     * TLFS 15.6.3 zero_memory_on_reset: the higher VTL asks for guest memory
     * to be scrubbed on a partition reset so its secrets do not survive into
     * the next VTL0. Scrub all RAM when any enabled VTL set it.
     */
    for (vtl = 1; vtl < HV_NUM_VTLS; vtl++) {
        if (hv_vsm.partition_config[vtl].zero_memory_on_reset) {
            hyperv_vsm_zero_memory();
            break;
        }
    }

    hv_vsm.vtl_enabled_for_vps = BIT(0);
    hv_vsm.partition_status.enabled_vtl_set = BIT(0);
    memset(hv_vsm.partition_config, 0, sizeof(hv_vsm.partition_config));

    hv_plane_reset();
}

/*
 * MSR filters are VM-wide (KVM_X86_SET_MSR_FILTER): install the VP assist
 * and hypercall page filters once, from VP0 of VTL0, and the EOI fixup once
 * the first VTL1 vCPU exists. The filter then also exits for VTL0 EOIs,
 * which msr_eoi_wrmsr() passes through; a per-plane filter would avoid that
 * cost (P2 open point).
 */
int hyperv_vsm_init_vcpu(X86CPU *cpu)
{
    CPUState *cs = CPU(cpu);
    KVMState *s = hv_plane_kvm_state(cs);
    VpVsmState *vpvsm;
    Object *obj;
    int vtl = active_vtl(cs);

    if (hyperv_vp_index(cs) == 0 && vtl == 0) {
        /* the VSM hypercalls exit to userspace only with the cap on */
        if (kvm_vm_enable_cap(s, KVM_CAP_HYPERV_VSM, 0, 0) < 0) {
            error_report("hyperv-vsm: KVM_CAP_HYPERV_VSM is not supported by "
                         "the kernel");
            return -1;
        }
        qemu_register_reset(hyperv_vsm_reset, NULL);
        if (kvm_filter_msr(s, HV_X64_MSR_APIC_ASSIST_PAGE,
                           vp_assist_page_rdmsr, vp_assist_page_wrmsr) < 0 ||
            kvm_filter_msr(s, HV_X64_MSR_HYPERCALL,
                           hypercall_page_rdmsr, hypercall_page_wrmsr) < 0) {
            error_report("hyperv-vsm: cannot install VSM MSR filters");
            return -1;
        }
    }

    if (hyperv_vp_index(cs) == 0 && vtl == 1) {
        if (kvm_filter_msr(s, HV_X64_MSR_EOI, NULL, msr_eoi_wrmsr) < 0) {
            error_report("hyperv-vsm: cannot install HV_X64_MSR_EOI filter");
            return -1;
        }
    }

    obj = object_new(TYPE_VP_VSM);
    vpvsm = VP_VSM(obj);
    vpvsm->cs = cs;
    object_property_add_child(OBJECT(cs), "vp-vsm", obj);
    object_unref(obj);
    qdev_realize(DEVICE(obj), NULL, &error_abort);

    return 0;
}

static void set_seg(SegmentCache *lhs,
                    const struct hv_x64_segment_register *rhs)
{
    lhs->selector = rhs->selector;
    lhs->base = rhs->base;
    lhs->limit = rhs->limit;
    lhs->flags = (rhs->segment_type << DESC_TYPE_SHIFT) |
                 (rhs->present * DESC_P_MASK) |
                 (rhs->descriptor_privilege_level << DESC_DPL_SHIFT) |
                 (rhs->_default << DESC_B_SHIFT) |
                 (rhs->non_system_segment * DESC_S_MASK) |
                 (rhs->_long << DESC_L_SHIFT) |
                 (rhs->granularity * DESC_G_MASK) |
                 (rhs->available * DESC_AVL_MASK);
}

static void get_seg(const SegmentCache *lhs,
                    struct hv_x64_segment_register *rhs)
{
    unsigned flags = lhs->flags;

    rhs->selector = lhs->selector;
    rhs->base = lhs->base;
    rhs->limit = lhs->limit;
    rhs->segment_type = (flags >> DESC_TYPE_SHIFT) & 15;
    rhs->non_system_segment = (flags & DESC_S_MASK) != 0;
    rhs->descriptor_privilege_level = (flags >> DESC_DPL_SHIFT) & 3;
    rhs->present = (flags & DESC_P_MASK) != 0;
    rhs->reserved = 0;
    rhs->available = (flags & DESC_AVL_MASK) != 0;
    rhs->_long = (flags >> DESC_L_SHIFT) & 1;
    rhs->_default = (flags >> DESC_B_SHIFT) & 1;
    rhs->granularity = (flags & DESC_G_MASK) != 0;
}

/*
 * Windows Server 2019 expects a VTL1+ APIC to be software-enabled without
 * ever writing SPIV; enable it on its behalf.
 */
static void apic_force_enable_spiv(CPUState *cs)
{
    APICCommonState *apic_state = APIC_COMMON(X86_CPU(cs)->apic_state);
    APICCommonClass *apic_class = APIC_COMMON_GET_CLASS(apic_state);

    assert(bql_locked());
    apic_state->spurious_vec = 0x1ff;
    apic_class->reset(apic_state);
}

/* Load an HV_INITIAL_VP_CONTEXT (TLFS 15.5.2) into @cs */
static void load_vp_context(CPUState *cs, const struct hv_init_vp_context *c,
                            bool enable_spiv)
{
    CPUX86State *env = &X86_CPU(cs)->env;

    trace_hyperv_vsm_vp_context(hyperv_vp_index(cs), active_vtl(cs), c->rip,
                                c->rsp, c->cr3, c->efer);

    env->regs[R_ESP] = c->rsp;
    env->eip = c->rip;
    env->eflags = c->rflags;

    set_seg(&env->segs[R_CS], &c->cs);
    set_seg(&env->segs[R_DS], &c->ds);
    set_seg(&env->segs[R_ES], &c->es);
    set_seg(&env->segs[R_FS], &c->fs);
    set_seg(&env->segs[R_GS], &c->gs);
    set_seg(&env->segs[R_SS], &c->ss);
    set_seg(&env->tr, &c->tr);
    set_seg(&env->ldt, &c->ldtr);

    env->idt.limit = c->idtr.limit;
    env->idt.base = c->idtr.base;
    env->gdt.limit = c->gdtr.limit;
    env->gdt.base = c->gdtr.base;

    env->efer = c->efer;
    env->cr[0] = c->cr0;
    env->cr[3] = c->cr3;
    env->cr[4] = c->cr4;
    env->pat = c->msr_cr_pat;

    env->mp_state = KVM_MP_STATE_RUNNABLE;

    /* FS/GS base are per-VTL MSRs without their own context fields */
    env->gsbase = c->gs.base;
    env->fsbase = c->fs.base;

    if (enable_spiv) {
        apic_force_enable_spiv(cs);
    }
}

static bool vp_assist_enabled(CPUState *cs)
{
    VpVsmState *vpvsm = get_vp_vsm(cs);

    return vpvsm &&
           (vpvsm->msr_hv_vp_assist & HV_X64_MSR_VP_ASSIST_PAGE_ENABLE);
}

static hwaddr vtl_control_gpa(CPUState *cs)
{
    return (get_vp_vsm(cs)->msr_hv_vp_assist &
            HV_X64_MSR_VP_ASSIST_PAGE_ADDRESS_MASK) +
           offsetof(struct hv_vp_assist_page, vtl_control);
}

static void write_vtl_control(CPUState *cs, const struct hv_vp_vtl_control *ctl)
{
    if (address_space_write(cs->as, vtl_control_gpa(cs),
                            MEMTXATTRS_UNSPECIFIED, ctl,
                            sizeof(*ctl)) != MEMTX_OK) {
        error_report("hyperv-vsm: VP %u VTL%d: cannot write vtl_control",
                     hyperv_vp_index(cs), active_vtl(cs));
    }
}

static void read_vtl_control(CPUState *cs, struct hv_vp_vtl_control *ctl)
{
    if (address_space_read(cs->as, vtl_control_gpa(cs), MEMTXATTRS_UNSPECIFIED,
                           ctl, sizeof(*ctl)) != MEMTX_OK) {
        error_report("hyperv-vsm: VP %u VTL%d: cannot read vtl_control",
                     hyperv_vp_index(cs), active_vtl(cs));
        memset(ctl, 0, sizeof(*ctl));
    }
}

void hv_plane_export_shared_state(CPUState *cs, HvVtlSharedState *st)
{
    CPUX86State *env = &X86_CPU(cs)->env;

    memcpy(st->regs, env->regs, sizeof(st->regs));
    memcpy(st->dr, env->dr, sizeof(st->dr));
    st->cr2 = env->cr[2];
    st->xcr0 = env->xcr0;
    memcpy(st->mtrr_fixed, env->mtrr_fixed, sizeof(st->mtrr_fixed));
    st->mtrr_deftype = env->mtrr_deftype;
    memcpy(st->mtrr_var, env->mtrr_var, sizeof(st->mtrr_var));
    st->mcg_cap = env->mcg_cap;
    st->mcg_status = env->mcg_status;
    st->msr_hv_runtime = env->msr_hv_runtime;

    st->fpstt = env->fpstt;
    st->fpus = env->fpus;
    st->fpuc = env->fpuc;
    memcpy(st->fptags, env->fptags, sizeof(st->fptags));
    memcpy(st->fpregs, env->fpregs, sizeof(st->fpregs));
    st->fpop = env->fpop;
    st->fpcs = env->fpcs;
    st->fpds = env->fpds;
    st->fpip = env->fpip;
    st->fpdp = env->fpdp;
    st->mxcsr = env->mxcsr;
    memcpy(st->xmm_regs, env->xmm_regs, sizeof(st->xmm_regs));
    st->xstate_bv = env->xstate_bv;
}

void hv_plane_import_shared_state(CPUState *cs, const HvVtlSharedState *st)
{
    CPUX86State *env = &X86_CPU(cs)->env;
    target_ulong rsp = env->regs[R_ESP];
    uint64_t val;

    memcpy(env->regs, st->regs, sizeof(env->regs));
    env->regs[R_ESP] = rsp;
    memcpy(env->dr, st->dr, sizeof(st->dr));
    env->cr[2] = st->cr2;
    env->xcr0 = st->xcr0;
    memcpy(env->mtrr_fixed, st->mtrr_fixed, sizeof(env->mtrr_fixed));
    env->mtrr_deftype = st->mtrr_deftype;
    memcpy(env->mtrr_var, st->mtrr_var, sizeof(env->mtrr_var));
    env->mcg_cap = st->mcg_cap;
    env->mcg_status = st->mcg_status;
    env->msr_hv_runtime = st->msr_hv_runtime;

    env->fpstt = st->fpstt;
    env->fpus = st->fpus;
    env->fpuc = st->fpuc;
    memcpy(env->fptags, st->fptags, sizeof(env->fptags));
    memcpy(env->fpregs, st->fpregs, sizeof(env->fpregs));
    env->fpop = st->fpop;
    env->fpcs = st->fpcs;
    env->fpds = st->fpds;
    env->fpip = st->fpip;
    env->fpdp = st->fpdp;
    env->mxcsr = st->mxcsr;
    memcpy(env->xmm_regs, st->xmm_regs, sizeof(env->xmm_regs));
    env->xstate_bv = st->xstate_bv;

    /* the BSP bit belongs to VP0 in every VTL */
    if (!hyperv_vp_index(cs)) {
        val = cpu_get_apic_base(X86_CPU(cs)->apic_state);
        val |= MSR_IA32_APICBASE_BSP;
        cpu_set_apic_base(X86_CPU(cs)->apic_state, val);
    }
}

/*
 * auto_eoi: the guest asks the hypervisor to acknowledge the VINA vector
 * for it, and the secure kernel's handler never touches its LAPIC. Nothing
 * in the architecture acknowledges a vector by itself, so the mark is the
 * mechanism: KVM_HYPERV_SET_AUTO_EOI keeps the marked vector out of the
 * in-service register. The mark follows the register, so it exists only
 * while a VTL asks for it.
 */
static void set_vina_auto_eoi(CPUState *cs, uint8_t vector, bool set)
{
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
}

static void set_vina(CPUState *cs, uint64_t data)
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
 * VINA (TLFS 15.2.3): while a VTL with VINA enabled runs, a lower VTL's
 * pending interrupt is notified to it by asserting vina.vector in its own
 * LAPIC and setting vina_asserted in its VP assist page. Nothing is
 * notified again until vina_asserted is clear: the guest clears it, or
 * auto_reset clears it when the VINA interrupt is delivered (which this
 * implementation takes as the moment the vector is injected).
 */
static bool vina_asserted(CPUState *cs)
{
    struct hv_vp_vtl_control ctl;

    if (!vp_assist_enabled(cs)) {
        return false;
    }
    read_vtl_control(cs, &ctl);
    return ctl.vina_asserted;
}

static void set_vina_asserted(CPUState *cs, bool asserted)
{
    struct hv_vp_vtl_control ctl;

    if (!vp_assist_enabled(cs)) {
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

int hyperv_vsm_vina_notify(CPUState *cs)
{
    VpVsmState *vpvsm = get_vp_vsm(cs);
    MSIMessage msg;
    int ret;

    if (!vpvsm || !vpvsm->vina.enabled || vina_asserted(cs)) {
        return 0;
    }

    trace_hyperv_vsm_vina_notify(hyperv_vp_index(cs), active_vtl(cs),
                                 vpvsm->vina.vector);
    msg = (MSIMessage) {
        .address = APIC_DEFAULT_ADDRESS |
                   cs->cc->get_arch_id(cs) << MSI_ADDR_DEST_ID_SHIFT,
        .data = vpvsm->vina.vector,
    };
    /* the handler reads vina_asserted, so it is set before the vector */
    set_vina_asserted(cs, true);
    ret = hv_plane_send_msi(cs, msg);
    if (ret < 0) {
        set_vina_asserted(cs, false);
        return ret;
    }
    return 0;
}

void hyperv_vsm_vtl_switch_state(CPUState *prev, CPUState *next,
                                 HvPlaneSwitchReason reason)
{
    CPUX86State *prev_env = &X86_CPU(prev)->env;
    CPUX86State *next_env = &X86_CPU(next)->env;
    struct hv_vp_vtl_control ctl;
    HvVtlSharedState shared;

    trace_hyperv_vsm_vtl_switch_state(hyperv_vp_index(prev), active_vtl(prev),
                                      active_vtl(next), reason);

    hv_plane_export_shared_state(prev, &shared);
    hv_plane_import_shared_state(next, &shared);

    if (reason == HV_PLANE_SWITCH_VTL_RETURN) {
        /* TLFS 15.5.8: VtlReturn hands RAX/RCX back through vtl_control */
        if (vp_assist_enabled(prev)) {
            read_vtl_control(prev, &ctl);
            next_env->regs[R_EAX] = ctl.vtl_ret_x64rax;
            next_env->regs[R_ECX] = ctl.vtl_ret_x64rcx;
            /* auto_reset: the VINA is consumed by the return it caused */
            if (ctl.vina_asserted && get_vp_vsm(prev)->vina.auto_reset) {
                ctl.vina_asserted = 0;
                write_vtl_control(prev, &ctl);
            }
        }
        return;
    }

    if (vp_assist_enabled(next)) {
        ctl = (struct hv_vp_vtl_control) {
            .vtl_entry_reason = reason == HV_PLANE_SWITCH_VTL_CALL ?
                                HV_VTL_ENTRY_VTL_CALL : HV_VTL_ENTRY_INTERRUPT,
            .vtl_ret_x64rax = prev_env->regs[R_EAX],
            .vtl_ret_x64rcx = prev_env->regs[R_ECX],
        };
        write_vtl_control(next, &ctl);
    }
}

static int highest_vtl(uint16_t set)
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
        return HV_STATUS_INVALID_VP_INDEX;
    }
    vpvsm = get_vp_vsm(target_vcpu);

    if (input.target_vtl > hv_vsm.partition_status.maximum_vtl) {
        return HV_STATUS_INVALID_PARAMETER;
    }

    if (!(hv_vsm.partition_status.enabled_vtl_set & BIT(input.target_vtl))) {
        return HV_STATUS_INVALID_PARAMETER;
    }

    if (vpvsm->vp_status.enabled_vtl_set & BIT(input.target_vtl)) {
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
    load_vp_context(vtl_cpu, &input.vp_context, true);
    cpu_synchronize_post_reset(vtl_cpu);
    bql_unlock();

    /* VTL2+: the enabled set would have to live with the VTL0 VpVsmState */
    vpvsm->vp_status.enabled_vtl_set |= BIT(input.target_vtl);
    hv_vsm.vtl_enabled_for_vps |= BIT(input.target_vtl);

    return HV_STATUS_SUCCESS;
}

/* TLB lock on the plane-0 vCPU (TLFS 15.5.4 TlbFlushInhibit) */
static void set_tlb_flush_inhibit(CPUState *vtl0, bool inhibit)
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

int hyperv_hcall_vtl_call(CPUState *cs)
{
    int vtl = active_vtl(cs);

    trace_hyperv_vsm_hcall_vtl_call(hyperv_vp_index(cs), vtl);

    /* VTL0 <-> VTL1 only */
    if (vtl != 0 || !sibling(cs, 1)) {
        return -EINVAL;
    }

    return hv_plane_run_vtl(cs, 1, HV_PLANE_SWITCH_VTL_CALL);
}

int hyperv_hcall_vtl_return(CPUState *cs)
{
    int vtl = active_vtl(cs);
    CPUState *vtl0;

    trace_hyperv_vsm_hcall_vtl_return(hyperv_vp_index(cs), vtl);

    if (vtl != 1) {
        return -EINVAL;
    }

    vtl0 = sibling(cs, 0);
    if (!vtl0) {
        return -EINVAL;
    }
    set_tlb_flush_inhibit(vtl0, false);

    return hv_plane_run_vtl(cs, 0, HV_PLANE_SWITCH_VTL_RETURN);
}

static bool get_vp_secure_vtl_config(CPUState *cs, uint32_t reg,
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

static bool set_vp_secure_vtl_config(CPUState *cs, uint32_t reg, uint64_t data)
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

static void set_vsm_partition_config(uint8_t vtl, uint64_t data)
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
     * TLFS 15.6.3: the default mask is the protection of lower-VTL memory
     * without an explicit ModifyVtlProtectionMask entry. Full access (RWX)
     * is what the plane attributes give by default; a restrictive default
     * would need attributes on every guest page. The Windows secure kernel
     * and the kvm-unit-tests suite set RWX.
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

static uint16_t get_vp_register(uint32_t name, struct hv_u128 *val,
                                CPUState *target_vcpu)
{
    VpVsmState *vpvsm = get_vp_vsm(target_vcpu);
    X86CPU *cpu = X86_CPU(target_vcpu);
    CPUX86State *env = &cpu->env;
    struct hv_x64_segment_register seg;
    struct hv_x64_table_register tr;

    val->low_part = val->high_part = 0;

    switch (name) {
    case HV_X64_REGISTER_RSP:
        val->low_part = env->regs[R_ESP];
        break;
    case HV_X64_REGISTER_RIP:
        val->low_part = env->eip;
        break;
    case HV_X64_REGISTER_RFLAGS:
        val->low_part = env->eflags;
        break;
    case HV_X64_REGISTER_CR0:
        val->low_part = env->cr[0];
        break;
    case HV_X64_REGISTER_CR3:
        val->low_part = env->cr[3];
        break;
    case HV_X64_REGISTER_CR4:
        val->low_part = env->cr[4];
        break;
    case HV_X64_REGISTER_CR8:
        val->low_part = cpu_get_apic_tpr(cpu->apic_state);
        break;
    case HV_X64_REGISTER_DR7:
        val->low_part = env->dr[7];
        break;
    case HV_X64_REGISTER_LDTR:
        get_seg(&env->ldt, &seg);
        memcpy(val, &seg, sizeof(seg));
        break;
    case HV_X64_REGISTER_TR:
        get_seg(&env->tr, &seg);
        memcpy(val, &seg, sizeof(seg));
        break;
    case HV_X64_REGISTER_IDTR:
        tr = (struct hv_x64_table_register) {
            .limit = env->idt.limit, .base = env->idt.base,
        };
        memcpy(val, &tr, sizeof(tr));
        break;
    case HV_X64_REGISTER_GDTR:
        tr = (struct hv_x64_table_register) {
            .limit = env->gdt.limit, .base = env->gdt.base,
        };
        memcpy(val, &tr, sizeof(tr));
        break;
    case HV_X64_REGISTER_EFER:
        val->low_part = env->efer;
        break;
    case HV_X64_REGISTER_SYSENTER_CS:
        val->low_part = env->sysenter_cs;
        break;
    case HV_X64_REGISTER_SYSENTER_EIP:
        val->low_part = env->sysenter_eip;
        break;
    case HV_X64_REGISTER_SYSENTER_ESP:
        val->low_part = env->sysenter_esp;
        break;
    case HV_X64_REGISTER_STAR:
        val->low_part = env->star;
        break;
#ifdef TARGET_X86_64
    case HV_X64_REGISTER_LSTAR:
        val->low_part = env->lstar;
        break;
    case HV_X64_REGISTER_CSTAR:
        val->low_part = env->cstar;
        break;
    case HV_X64_REGISTER_SFMASK:
        val->low_part = env->fmask;
        break;
#endif
    case HV_X64_REGISTER_TSC_AUX:
        val->low_part = env->tsc_aux;
        break;
    case HV_X64_REGISTER_APIC_BASE:
        val->low_part = cpu_get_apic_base(cpu->apic_state);
        break;
    case HV_REGISTER_VSM_CAPABILITIES:
        val->low_part = hv_vsm.capabilities.as_uint64;
        break;
    case HV_REGISTER_VSM_PARTITION_STATUS:
        val->low_part = hv_vsm.partition_status.as_uint64;
        break;
    case HV_REGISTER_VSM_VP_STATUS:
        val->low_part = vpvsm->vp_status.as_uint64;
        break;
    case HV_REGISTER_VSM_PARTITION_CONFIG:
        /* partition-wide per VTL; relies on 64-bit store atomicity */
        val->low_part =
            hv_vsm.partition_config[active_vtl(target_vcpu)].as_uint64;
        break;
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0 ...
         HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL14:
        if (!get_vp_secure_vtl_config(target_vcpu, name, val)) {
            return HV_STATUS_INVALID_PARAMETER;
        }
        break;
    case HV_REGISTER_VP_ASSIST_PAGE:
        val->low_part = vpvsm->msr_hv_vp_assist;
        break;
    case HV_REGISTER_VSM_CODE_PAGE_OFFSETS:
        val->low_part = hv_vsm.code_page_offsets.as_uint64;
        break;
    case HV_REGISTER_VSM_VINA:
        /* VINA is not delivered; the register reads back as written */
        val->low_part = vpvsm->vina.as_uint64;
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "hyperv-vsm: GetVpRegisters: unknown "
                      "register 0x%x\n", name);
        return HV_STATUS_INVALID_PARAMETER;
    }

    trace_hyperv_vsm_vp_register(false, name, val->low_part, val->high_part);
    return HV_STATUS_SUCCESS;
}

static uint16_t set_vp_register(uint32_t name, const struct hv_u128 *val,
                                CPUState *target_vcpu, bool *dirty)
{
    X86CPU *cpu = X86_CPU(target_vcpu);
    CPUX86State *env = &cpu->env;
    struct hv_x64_segment_register seg;
    struct hv_x64_table_register tr;

    trace_hyperv_vsm_vp_register(true, name, val->low_part, val->high_part);

    switch (name) {
    case HV_X64_REGISTER_RSP:
        env->regs[R_ESP] = val->low_part;
        break;
    case HV_X64_REGISTER_RIP:
        env->eip = val->low_part;
        break;
    case HV_X64_REGISTER_RFLAGS:
        env->eflags = val->low_part;
        break;
    case HV_X64_REGISTER_CR0:
        env->cr[0] = val->low_part;
        break;
    case HV_X64_REGISTER_CR3:
        env->cr[3] = val->low_part;
        break;
    case HV_X64_REGISTER_CR4:
        env->cr[4] = val->low_part;
        break;
    case HV_X64_REGISTER_CR8:
        cpu_set_apic_tpr(cpu->apic_state, val->low_part);
        break;
    case HV_X64_REGISTER_DR7:
        env->dr[7] = val->low_part;
        break;
    case HV_X64_REGISTER_LDTR:
        memcpy(&seg, val, sizeof(seg));
        set_seg(&env->ldt, &seg);
        break;
    case HV_X64_REGISTER_TR:
        memcpy(&seg, val, sizeof(seg));
        set_seg(&env->tr, &seg);
        break;
    case HV_X64_REGISTER_IDTR:
        memcpy(&tr, val, sizeof(tr));
        env->idt.base = tr.base;
        env->idt.limit = tr.limit;
        break;
    case HV_X64_REGISTER_GDTR:
        memcpy(&tr, val, sizeof(tr));
        env->gdt.base = tr.base;
        env->gdt.limit = tr.limit;
        break;
    case HV_X64_REGISTER_EFER:
        env->efer = val->low_part;
        break;
    case HV_X64_REGISTER_SYSENTER_CS:
        env->sysenter_cs = val->low_part;
        break;
    case HV_X64_REGISTER_SYSENTER_EIP:
        env->sysenter_eip = val->low_part;
        break;
    case HV_X64_REGISTER_SYSENTER_ESP:
        env->sysenter_esp = val->low_part;
        break;
    case HV_X64_REGISTER_STAR:
        env->star = val->low_part;
        break;
#ifdef TARGET_X86_64
    case HV_X64_REGISTER_LSTAR:
        env->lstar = val->low_part;
        break;
    case HV_X64_REGISTER_CSTAR:
        env->cstar = val->low_part;
        break;
    case HV_X64_REGISTER_SFMASK:
        env->fmask = val->low_part;
        break;
#endif
    case HV_X64_REGISTER_TSC_AUX:
        env->tsc_aux = val->low_part;
        break;
    case HV_REGISTER_VSM_PARTITION_CONFIG:
        set_vsm_partition_config(active_vtl(target_vcpu), val->low_part);
        break;
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0 ...
         HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL14:
        if (!set_vp_secure_vtl_config(target_vcpu, name, val->low_part)) {
            return HV_STATUS_INVALID_PARAMETER;
        }
        break;
    case HV_REGISTER_PENDING_EVENT0: {
        union hv_x64_pending_exception_event event = {
            .as_uint64[0] = val->low_part,
            .as_uint64[1] = val->high_part,
        };

        if (!event.event_pending) {
            break;
        }

        if (event.event_type != HV_X64_PENDING_EVENT_EXCEPTION) {
            qemu_log_mask(LOG_UNIMP, "hyperv-vsm: pending event type %d not "
                          "supported\n", event.event_type);
            break;
        }

        kvm_queue_exception(env, event.vector, event.deliver_error_code,
                            event.error_code, false, 0);
        break;
    }
    case HV_REGISTER_VP_ASSIST_PAGE:
        env->msr_hv_vapic = val->low_part;
        setup_vp_assist(target_vcpu, val->low_part);
        break;
    case HV_REGISTER_VSM_VINA:
        set_vina(target_vcpu, val->low_part);
        break;
    case HV_X64_REGISTER_CR_INTERCEPT_CONTROL:
    case HV_X64_REGISTER_CR_INTERCEPT_CR0_MASK:
    case HV_X64_REGISTER_CR_INTERCEPT_CR4_MASK:
    case HV_X64_REGISTER_CR_INTERCEPT_IA32_MISC_ENABLE_MASK:
        qemu_log_mask(LOG_UNIMP, "hyperv-vsm: SetVpRegisters: register 0x%x "
                      "accepted but not implemented\n", name);
        return HV_STATUS_SUCCESS;
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "hyperv-vsm: SetVpRegisters: unknown "
                      "register 0x%x\n", name);
        return HV_STATUS_INVALID_PARAMETER;
    }

    *dirty = true;
    return HV_STATUS_SUCCESS;
}

/* registers handled per call; bounds the stack use, not a TLFS limit */
#define VP_REGISTER_LIST_SIZE 16u

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
        return HV_STATUS_INVALID_HYPERCALL_INPUT;
    }
    nregs = MIN(rep_cnt - rep_idx, VP_REGISTER_LIST_SIZE);

    if (fast) {
        /* names (and values) travel in XMM registers */
        if (!hv_exit_has_xmm(exit)) {
            return HV_STATUS_INVALID_HYPERCALL_INPUT;
        }
        input.partition_id = exit->u.hcall.params[0];
        input.vp_index = exit->u.hcall.params[1] & 0xffffffff;
        input.input_vtl.as_uint8 = (exit->u.hcall.params[1] >> 32) & 0xff;

        /* everything is returned at once, so no continuation */
        if (rep_idx != 0) {
            return HV_STATUS_INVALID_HYPERCALL_INPUT;
        }

        /* 6 XMM registers hold at most 4 names plus 4 values */
        if (nregs > 4) {
            return HV_STATUS_INVALID_HYPERCALL_INPUT;
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
            return HV_STATUS_INVALID_HYPERCALL_INPUT;
        }

        ingpa += sizeof(input) + rep_idx * sizeof(*names);
        if (vsm_physmem_read(cs, ingpa, names,
                             nregs * sizeof(*names)) != MEMTX_OK) {
            return HV_STATUS_INVALID_HYPERCALL_INPUT;
        }

        if (set) {
            /* values start 16-byte aligned after all rep_cnt names */
            ingpa = ROUND_UP(exit->u.hcall.params[0] + sizeof(input) +
                             rep_cnt * sizeof(*names), 16) +
                    rep_idx * sizeof(*vals);
            if (vsm_physmem_read(cs, ingpa, vals,
                                 nregs * sizeof(*vals)) != MEMTX_OK) {
                return HV_STATUS_INVALID_HYPERCALL_INPUT;
            }
        }
    }

    if (input.partition_id != HV_PARTITION_ID_SELF) {
        return HV_STATUS_INVALID_PARTITION_ID;
    }

    if (input_vtl_targets(input.input_vtl)) {
        vtl = input.input_vtl.target_vtl;
        if (vtl >= HV_NUM_VTLS) {
            return HV_STATUS_INVALID_HYPERCALL_INPUT;
        }
        if (vtl > active_vtl(cs)) {
            return HV_STATUS_ACCESS_DENIED;
        }
    } else {
        vtl = active_vtl(cs);
    }

    if (input.vp_index == HV_VP_INDEX_SELF) {
        input.vp_index = hyperv_vp_index(cs);
    } else if (input.vp_index >= ms->smp.max_cpus) {
        return HV_STATUS_INVALID_VP_INDEX;
    }

    target_vcpu = hv_plane_vcpu(input.vp_index, vtl);
    if (!target_vcpu) {
        return HV_STATUS_INVALID_VP_INDEX;
    }

    trace_hyperv_vsm_hcall_get_set_vp_registers(input.partition_id,
                                                input.vp_index, vtl,
                                                active_vtl(cs), nregs, set);

    bql_lock();
    cpu_synchronize_state(target_vcpu);
    for (i = 0; i < nregs; i++) {
        status = set ?
                 set_vp_register(names[i], &vals[i], target_vcpu, &dirty) :
                 get_vp_register(names[i], &vals[i], target_vcpu);
        if (status != HV_STATUS_SUCCESS) {
            break;
        }
    }
    if (dirty) {
        cpu_synchronize_post_reset(target_vcpu);
    }
    bql_unlock();

    if (status != HV_STATUS_SUCCESS) {
        return status;
    }

    if (!set) {
        if (fast) {
            for (i = 0; i < nregs; i++, xmm_index += 2) {
                hv_exit_xmm_set(exit, xmm_index, vals[i].low_part);
                hv_exit_xmm_set(exit, xmm_index + 1, vals[i].high_part);
            }
        } else {
            uint64_t outgpa = exit->u.hcall.params[1] + rep_idx * sizeof(*vals);

            vsm_physmem_write(cs, outgpa, vals, sizeof(*vals) * nregs);
        }
    }

    return (uint64_t)HV_STATUS_SUCCESS |
           ((uint64_t)nregs << HV_HYPERCALL_REP_COMP_OFFSET);
}

static bool gpa_is_overlay(CPUState *cs, uint64_t gpa)
{
    VpVsmState *vpvsm = get_vp_vsm(cs);

    uint64_t hcall = hv_vsm.hypercall[active_vtl(cs)] &
                     HV_X64_MSR_HYPERCALL_PAGE_ADDRESS_MASK;
    uint64_t assist = vpvsm->msr_hv_vp_assist &
                      HV_X64_MSR_VP_ASSIST_PAGE_ADDRESS_MASK;

    return hcall == gpa || assist == gpa;
}

static uint32_t translate_result_code(const struct kvm_translation2 *tr,
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

uint64_t hyperv_hcall_translate_virtual_address(CPUState *cs,
                                                struct kvm_hyperv_exit *exit)
{
    bool fast = exit->u.hcall.input & HV_HYPERCALL_FAST;
    struct hv_output_translate_virtual_address output = {};
    struct hv_input_translate_virtual_address input;
    struct kvm_translation2 tr = {};
    union hv_input_vtl in_vtl;
    CPUState *target_vcpu;
    uint64_t flags;
    uint8_t target_vtl;
    int ret;

    if (fast) {
        if (!hv_exit_has_xmm(exit)) {
            return HV_STATUS_INVALID_HYPERCALL_INPUT;
        }
        input.partition_id = exit->u.hcall.params[0];
        input.vp_index = exit->u.hcall.params[1] & 0xffffffff;
        input.control_flags = hv_exit_xmm_get(exit, 0);
        input.gva_page = hv_exit_xmm_get(exit, 1);
    } else if (vsm_physmem_read(cs, exit->u.hcall.params[0], &input,
                                sizeof(input)) != MEMTX_OK) {
        return HV_STATUS_INVALID_HYPERCALL_INPUT;
    }

    if (input.partition_id != HV_PARTITION_ID_SELF) {
        return HV_STATUS_INVALID_PARTITION_ID;
    }

    in_vtl.as_uint8 = input.control_flags >> HV_TRANSLATE_GVA_INPUT_VTL_SHIFT;
    flags = input.control_flags & HV_TRANSLATE_GVA_FLAGS_MASK;
    if (input_vtl_targets(in_vtl)) {
        target_vtl = in_vtl.target_vtl;
        if (target_vtl > active_vtl(cs)) {
            return HV_STATUS_INVALID_VP_STATE;
        }
    } else {
        target_vtl = active_vtl(cs);
    }

    if (input.vp_index == HV_ANY_VP) {
        return HV_STATUS_INVALID_VP_INDEX;
    }
    if (input.vp_index == HV_VP_INDEX_SELF) {
        input.vp_index = hyperv_vp_index(cs);
    }

    target_vcpu = hv_plane_vcpu(input.vp_index, target_vtl);
    if (!target_vcpu) {
        return HV_STATUS_INVALID_VP_INDEX;
    }

    tr.linear_address = input.gva_page << HV_HYP_PAGE_SHIFT;
    if (flags & HV_TRANSLATE_GVA_VALIDATE_WRITE) {
        tr.access |= KVM_TRANSLATE_ACCESS_WRITE;
    }
    if (flags & HV_TRANSLATE_GVA_VALIDATE_EXECUTE) {
        tr.access |= KVM_TRANSLATE_ACCESS_EXEC;
    }
    if (!(flags & HV_TRANSLATE_GVA_PRIVILEGE_EXEMPT) &&
        (X86_CPU(target_vcpu)->env.hflags & HF_CPL_MASK)) {
        tr.access |= KVM_TRANSLATE_ACCESS_USER;
    }
    if (flags & HV_TRANSLATE_GVA_SET_PAGE_TABLE_BITS) {
        tr.flags = KVM_TRANSLATE_FLAGS_SET_ACCESSED |
                   KVM_TRANSLATE_FLAGS_FORCE_SET_ACCESSED;
        if (tr.access & KVM_TRANSLATE_ACCESS_WRITE) {
            tr.flags |= KVM_TRANSLATE_FLAGS_SET_DIRTY;
        }
    }

    ret = hv_plane_translate(target_vcpu, &tr);
    if (ret < 0) {
        qemu_log_mask(LOG_UNIMP, "hyperv-vsm: KVM_TRANSLATE2 failed: %d\n",
                      ret);
        tr.valid = false;
    }

    output.gpa_page = tr.physical_address >> HV_HYP_PAGE_SHIFT;
    if (tr.valid) {
        output.translation_result.result_code = HV_TRANSLATE_GVA_SUCCESS;
        output.translation_result.cache_type = HV_CACHE_TYPE_WRITE_BACK;
        output.translation_result.overlay_page =
            gpa_is_overlay(target_vcpu, tr.physical_address);

        if (flags & HV_TRANSLATE_GVA_TLB_FLUSH_INHIBIT) {
            set_tlb_flush_inhibit(sibling(cs, 0), true);
        }
    } else {
        output.translation_result.result_code =
            translate_result_code(&tr, flags);
    }

    trace_hyperv_vsm_hcall_translate_virtual_address(input.partition_id,
            input.vp_index, target_vtl, input.control_flags, input.gva_page,
            output.gpa_page, output.translation_result.overlay_page,
            output.translation_result.result_code);

    if (fast) {
        hv_exit_xmm_set(exit, 2, output.translation_result.as_uint64);
        hv_exit_xmm_set(exit, 3, output.gpa_page);
    } else {
        vsm_physmem_write(cs, exit->u.hcall.params[1], &output, sizeof(output));
    }

    return HV_STATUS_SUCCESS;
}

static uint8_t intercept_access_type(uint64_t flags)
{
    if (flags & KVM_MEMORY_EXIT_FLAG_READ) {
        return HV_X64_INTERCEPT_ACCESS_TYPE_READ;
    }
    if (flags & KVM_MEMORY_EXIT_FLAG_WRITE) {
        return HV_X64_INTERCEPT_ACCESS_TYPE_WRITE;
    }
    return HV_X64_INTERCEPT_ACCESS_TYPE_EXECUTE;
}

/* Code segment mode of @env for the instruction length decoder */
static int cs_mode(CPUX86State *env)
{
    if (env->hflags & HF_CS64_MASK) {
        return 64;
    }
    return env->hflags & HF_CS32_MASK ? 32 : 16;
}

/*
 * The instruction bytes at RIP and their decoded length. KVM's memory fault
 * exit carries no instruction length (Paolo Bonzini's memory protection
 * attributes RFC), so it is decoded here. Returns the decoded length, with
 * @insn holding exactly that many bytes (zero after); 0 when RIP cannot be
 * read or the bytes do not decode, @insn then all zero.
 */
static int read_faulting_insn(CPUState *cs, uint8_t *insn, int size)
{
    CPUX86State *env = &X86_CPU(cs)->env;
    int n;

    /* RIP is a guest virtual address: walk the faulting VTL's tables */
    if (cpu_memory_rw_debug(cs, env->eip, insn, size, false)) {
        memset(insn, 0, size);
        return 0;
    }
    n = hyperv_vsm_insn_len(insn, size, cs_mode(env));
    if (n <= 0) {
        qemu_log_mask(LOG_UNIMP, "hyperv-vsm: cannot decode the instruction "
                      "at rip 0x%" PRIx64 " on VP %u\n", (uint64_t)env->eip,
                      hyperv_vp_index(cs));
        n = 0;
    }
    memset(insn + n, 0, size - n);
    return n;
}

/* TLFS 15.10.2: build the GPA intercept message for a lower-VTL fault */
static void build_memory_intercept(CPUState *cs, struct hyperv_message *msg,
                                   uint64_t gpa, uint64_t flags)
{
    struct hv_vsm_memory_intercept_message *icpt = (void *)msg->payload;
    struct hv_x64_intercept_message_header *hdr = &icpt->msg.header;
    CPUX86State *env = &X86_CPU(cs)->env;
    struct hv_x64_segment_register seg;

    QEMU_BUILD_BUG_ON(sizeof(*icpt) > sizeof(msg->payload));

    msg->header.message_type = HV_MESSAGE_GPA_INTERCEPT;
    msg->header.payload_size = sizeof(*icpt);

    hdr->vp_index = hyperv_vp_index(cs);
    hdr->intercept_access_type = intercept_access_type(flags);
    get_seg(&env->segs[R_CS], &hdr->cs_segment);
    get_seg(&env->segs[R_SS], &seg);
    hdr->execution_state.cpl = seg.descriptor_privilege_level;
    hdr->execution_state.cr0_pe = !!(env->cr[0] & CR0_PE_MASK);
    hdr->execution_state.cr0_am = !!(env->cr[0] & CR0_AM_MASK);
    hdr->execution_state.efer_lma = !!(env->efer & MSR_EFER_LMA);
    hdr->execution_state.vtl = active_vtl(cs);
    hdr->rip = env->eip;
    hdr->rflags = env->eflags;

    /*
     * The length is always reported; the bytes only for a data access. On
     * an execute fault they are the fetch target itself and Hyper-V leaves
     * them empty. The length reported for a fetch intercept is that of the
     * instruction at RIP (the fetch target); what Hyper-V reports there is
     * unverified (no trace yet), the kvm-unit-tests suite was adjusted to
     * this value.
     */
    hdr->instruction_length =
        read_faulting_insn(cs, icpt->msg.instruction_bytes,
                           sizeof(icpt->msg.instruction_bytes));
    icpt->msg.instruction_byte_count = hdr->instruction_length;
    if (hdr->intercept_access_type == HV_X64_INTERCEPT_ACCESS_TYPE_EXECUTE) {
        icpt->msg.instruction_byte_count = 0;
        memset(icpt->msg.instruction_bytes, 0,
               sizeof(icpt->msg.instruction_bytes));
    }

    icpt->msg.memory_access_info.gva_valid = 0;
    icpt->msg.guest_virtual_address = 0;
    icpt->msg.guest_physical_address = gpa;
    icpt->msg.cache_type = HV_CACHE_TYPE_WRITE_BACK;
    get_seg(&env->segs[R_DS], &icpt->ds);
    icpt->ss = seg;
    icpt->rax = env->regs[R_EAX];
    icpt->rcx = env->regs[R_ECX];
    icpt->rdx = env->regs[R_EDX];
    icpt->rbx = env->regs[R_EBX];
    icpt->rsp = env->regs[R_ESP];
    icpt->rbp = env->regs[R_EBP];
    icpt->rsi = env->regs[R_ESI];
    icpt->rdi = env->regs[R_EDI];
    icpt->r8 = env->regs[8];
    icpt->r9 = env->regs[9];
    icpt->r10 = env->regs[10];
    icpt->r11 = env->regs[11];
    icpt->r12 = env->regs[12];
    icpt->r13 = env->regs[13];
    icpt->r14 = env->regs[14];
    icpt->r15 = env->regs[15];

    trace_hyperv_vsm_memory_intercept(hdr->vp_index, hdr->rip, gpa,
                                      hdr->intercept_access_type,
                                      hdr->instruction_length);
}

static void intercept_cb(void *data, int status)
{
    VpVsmState *vpvsm = data;

    if (!status) {
        return;
    }

    assert(status == -EAGAIN);

    /* the slot was busy; repost once the guest has acknowledged */
    while (hyperv_post_msg(vpvsm->intercept_route, &vpvsm->intercept_msg)) {
        sched_yield();
    }
}

/* Post @msg on SINT0 of @cs (the higher VTL vCPU of the faulting VP) */
static int deliver_memory_intercept(CPUState *cs,
                                    const struct hyperv_message *msg)
{
    VpVsmState *vpvsm = get_vp_vsm(cs);

    vpvsm->intercept_msg = *msg;

    if (!vpvsm->intercept_route) {
        vpvsm->intercept_route = hyperv_sint_route_new(hyperv_vp_index(cs),
                                                       active_vtl(cs), 0,
                                                       intercept_cb, vpvsm);
    }
    if (!vpvsm->intercept_route) {
        error_report("hyperv-vsm: cannot create the intercept SINT route for "
                     "VP %u VTL%d", hyperv_vp_index(cs), active_vtl(cs));
        return -1;
    }

    while (hyperv_post_msg(vpvsm->intercept_route, &vpvsm->intercept_msg)) {
        sched_yield();
    }

    return 0;
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
    build_memory_intercept(cs, &msg, gpa, flags);
    if (deliver_memory_intercept(next, &msg)) {
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

static int set_memory_attrs_range(uint8_t vtl, uint64_t start, uint64_t end,
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

uint64_t hyperv_hcall_vtl_protection_mask(CPUState *cs,
                                          struct kvm_hyperv_exit *exit)
{
    uint64_t in = exit->u.hcall.input;
    uint16_t rep_cnt = (in >> HV_HYPERCALL_REP_COMP_OFFSET) & 0xfff;
    uint16_t rep_idx = (in >> HV_HYPERCALL_REP_START_OFFSET) & 0xfff;
    bool fast = exit->u.hcall.input & HV_HYPERCALL_FAST;
    union hv_modify_vtl_protection_mask input;
    g_autofree uint64_t *gfn_list = NULL;
    uint8_t target_vtl;
    uint16_t count, i;

    if (rep_idx >= rep_cnt) {
        return HV_STATUS_INVALID_HYPERCALL_INPUT;
    }
    count = rep_cnt - rep_idx;

    if (fast) {
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
    } else {
        uint64_t ingpa = exit->u.hcall.params[0];

        if (vsm_physmem_read(cs, ingpa, &input, sizeof(input)) != MEMTX_OK) {
            return HV_STATUS_INVALID_HYPERCALL_INPUT;
        }

        gfn_list = g_new0(uint64_t, count);
        ingpa += sizeof(input) + rep_idx * sizeof(*gfn_list);
        if (vsm_physmem_read(cs, ingpa, gfn_list,
                             count * sizeof(*gfn_list)) != MEMTX_OK) {
            return HV_STATUS_INVALID_HYPERCALL_INPUT;
        }
    }

    trace_hyperv_vsm_hcall_vtl_protection_mask(input.target_partition_id,
                                               input.map_flags,
                                               input.input_vtl.target_vtl,
                                               count);

    if (input.target_partition_id != HV_PARTITION_ID_SELF) {
        return HV_STATUS_INVALID_PARTITION_ID;
    }

    /* protections apply to a lower VTL; default is the one right below */
    if (input_vtl_targets(input.input_vtl)) {
        target_vtl = input.input_vtl.target_vtl;
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

    if (set_memory_attrs(target_vtl, input.map_flags, count, gfn_list)) {
        return HV_STATUS_INVALID_PARAMETER;
    }

    return (uint64_t)count << HV_HYPERCALL_REP_COMP_OFFSET;
}

uint64_t hyperv_hcall_get_vp_index_from_apic_id(CPUState *cs,
                                                struct kvm_hyperv_exit *exit)
{
    uint64_t in = exit->u.hcall.input;
    uint16_t rep_cnt = (in >> HV_HYPERCALL_REP_COMP_OFFSET) & 0xfff;
    uint16_t rep_idx = (in >> HV_HYPERCALL_REP_START_OFFSET) & 0xfff;
    bool fast = exit->u.hcall.input & HV_HYPERCALL_FAST;
    struct hv_get_vp_index_from_apic_id_input input;
    CPUState *target_vcpu;
    uint64_t apic_id;
    uint64_t vp_index;
    uint16_t count;

    /* one APIC id per call */
    if (rep_idx >= rep_cnt) {
        return HV_STATUS_INVALID_HYPERCALL_INPUT;
    }
    count = 1;

    if (fast) {
        if (!hv_exit_has_xmm(exit)) {
            return HV_STATUS_INVALID_HYPERCALL_INPUT;
        }
        input.partition_id = exit->u.hcall.params[0];
        input.target_vtl = exit->u.hcall.params[1] & 0xff;
        apic_id = hv_exit_xmm_get(exit, 0);
    } else if (vsm_physmem_read(cs, exit->u.hcall.params[0], &input,
                                sizeof(input)) != MEMTX_OK ||
               vsm_physmem_read(cs, exit->u.hcall.params[0] + sizeof(input),
                                &apic_id, sizeof(apic_id)) != MEMTX_OK) {
        return HV_STATUS_INVALID_HYPERCALL_INPUT;
    }

    if (input.partition_id != HV_PARTITION_ID_SELF) {
        return HV_STATUS_INVALID_PARTITION_ID;
    }

    apic_id &= 0xffffffff;
    target_vcpu = cpu_by_arch_id(apic_id);
    if (!target_vcpu ||
        !hv_plane_vcpu(hyperv_vp_index(target_vcpu), input.target_vtl)) {
        return HV_STATUS_INVALID_PARAMETER;
    }

    vp_index = hyperv_vp_index(target_vcpu);
    trace_hyperv_vsm_hcall_get_vp_index_from_apic_id(input.partition_id,
                                                     input.target_vtl, apic_id,
                                                     vp_index);

    if (fast) {
        hv_exit_xmm_set(exit, 2, vp_index);
    } else {
        vsm_physmem_write(cs, exit->u.hcall.params[1], &vp_index,
                          sizeof(vp_index));
    }

    return ((uint64_t)count << HV_HYPERCALL_REP_COMP_OFFSET) |
           HV_STATUS_SUCCESS;
}

uint64_t hyperv_hcall_start_virtual_processor(CPUState *cs,
                                              struct kvm_hyperv_exit *exit)
{
    uint64_t in = exit->u.hcall.input;
    uint16_t rep_idx = (in >> HV_HYPERCALL_REP_START_OFFSET) & 0xfff;
    uint16_t rep_cnt = (in >> HV_HYPERCALL_REP_COMP_OFFSET) & 0xfff;
    bool fast = exit->u.hcall.input & HV_HYPERCALL_FAST;
    uint8_t current_vtl = active_vtl(cs);
    uint64_t status = HV_STATUS_SUCCESS;
    struct hv_enable_vp_vtl input;
    uint8_t start_vtl;
    VpVsmState *vpvsm;
    CPUState *vcpu;
    int i;

    /* TLFS 15.5.9: neither fast nor rep */
    if (fast || rep_cnt || rep_idx) {
        return HV_STATUS_INVALID_HYPERCALL_INPUT;
    }

    if (vsm_physmem_read(cs, exit->u.hcall.params[0], &input,
                         sizeof(input)) != MEMTX_OK) {
        return HV_STATUS_INVALID_HYPERCALL_INPUT;
    }

    trace_hyperv_vsm_hcall_start_virtual_processor(input.partition_id,
                                                   input.vp_index,
                                                   input.target_vtl,
                                                   current_vtl);

    if (input.partition_id != HV_PARTITION_ID_SELF) {
        return HV_STATUS_INVALID_PARTITION_ID;
    }

    if (input.target_vtl > hv_vsm.partition_status.maximum_vtl ||
        input.target_vtl > current_vtl) {
        return HV_STATUS_INVALID_PARAMETER;
    }

    vcpu = hv_plane_vcpu(input.vp_index, 0);
    if (!vcpu) {
        return HV_STATUS_INVALID_VP_INDEX;
    }
    vpvsm = get_vp_vsm(vcpu);

    /*
     * The hypercall carries a processor context, so a higher VTL uses it to
     * seize a lower VTL's processor rather than to bring an unstarted one
     * up: the secure kernel takes an application processor away from the
     * firmware that parked it and hands it the context of the operating
     * system. Any idle state is therefore expected, including HALTED, which
     * is where firmware leaves a processor it has run. Only the BSP, a
     * running processor and a start already in flight are refused. Checked
     * for every VTL below the target, and for VTL0 itself when that is the
     * target, which is how Windows starts a processor.
     */
    /* run_on_cpu() on a vCPU other than this one needs the BQL */
    bql_lock();

    for (i = MAX(input.target_vtl, 1) - 1; i >= 0; i--) {
        vcpu = hv_plane_vcpu(input.vp_index, i);
        if (!vcpu || cpu_is_bsp(X86_CPU(vcpu))) {
            status = HV_STATUS_INVALID_VP_STATE;
            goto out;
        }
        cpu_synchronize_state(vcpu);
        switch (X86_CPU(vcpu)->env.mp_state) {
        case KVM_MP_STATE_UNINITIALIZED:
        case KVM_MP_STATE_INIT_RECEIVED:
        case KVM_MP_STATE_HALTED:
        case KVM_MP_STATE_STOPPED:
            break;
        default:
            status = HV_STATUS_INVALID_VP_STATE;
            goto out;
        }
    }

    if (!(vpvsm->vp_status.enabled_vtl_set & BIT(input.target_vtl))) {
        status = HV_STATUS_INVALID_PARAMETER;
        goto out;
    }

    vcpu = hv_plane_vcpu(input.vp_index, input.target_vtl);
    if (!vcpu) {
        status = HV_STATUS_INVALID_PARAMETER;
        goto out;
    }

    /* the context describes a 64-bit VP; EFER.LMA follows from LME + PG */
    input.vp_context.efer |= MSR_EFER_LMA;
    /*
     * The context this hypercall carries is registers only, so load that and
     * touch no other per-VP state. An INIT here would clear state the caller
     * never named and does not restore: the LAPIC, which apic_init_reset()
     * leaves with SPIV clear and every LVT masked, and the SynIC control,
     * message and event pages and interrupt source entries, which sit
     * outside the INIT-preserved window of CPUX86State and so would reach
     * KVM as zero through the synchronise below. Whatever the firmware or
     * the guest left in them then stands, which is correct for a VP being
     * restarted and identical to a reset for one started the first time,
     * since that one holds its creation reset state. HvCallEnableVpVtl loads
     * its context the same way.
     *
     * SPIV is forced on for a VTL>0 VP, whose secure kernel expects an
     * enabled APIC; a VTL0 VP enables its own, as after a SIPI.
     */
    load_vp_context(vcpu, &input.vp_context, input.target_vtl > 0);
    cpu_synchronize_post_reset(vcpu);

    start_vtl = highest_vtl(vpvsm->vp_status.enabled_vtl_set);
    if (hv_plane_vcpu_start(input.vp_index, start_vtl)) {
        status = HV_STATUS_INVALID_VP_STATE;
    }

out:
    bql_unlock();
    return status;
}

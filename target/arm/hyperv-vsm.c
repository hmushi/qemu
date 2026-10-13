/*
 * Hyper-V VSM on arm64: the target side of the plane API
 * (include/hw/hyperv/vsm-plane-api.h) and of the VSM core
 * (include/hw/hyperv/vsm-core.h).
 *
 * What ARM64 has no counterpart for is refused with a logged error: the
 * descriptor-table load intercepts and the hypercall code page.
 *
 * TLFS references are to the copy in the room: vsm.md "Private and Shared
 * Registers / On ARM64 Platforms" (X18 the only private general-purpose
 * register; PC, SP_EL0, SP_EL1, PSTATE, FPCR, FPSR and every system register
 * private; X0-X17, X19-X30 and Q0-Q31 shared), vp-properties.md "VP Assist
 * Page / On ARM64 Platforms" (HvRegisterVpAssistPage, x64 MSR format),
 * hvdef HvArm64RegisterName and InitialVpContextArm64 for the register ids
 * and the start context layout.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "qapi/error.h"
#include "qobject/qobject.h"
#include "qom/qom-qobject.h"
#include "system/hw_accel.h"
#include "system/kvm.h"
#include "system/reset.h"
#include "hw/core/boards.h"
#include "hw/hyperv/hyperv.h"
#include "hw/intc/arm_gic_common.h"
#include "hw/arm/virt.h"
#include "hw/hyperv/vsm-plane-api.h"
#include "hw/hyperv/vsm-core.h"
#include "hw/hyperv/hyperv-vsm-arm.h"

/*
 * HvRegisterPendingEvent0. The imported hvgdk_mini.h carries no name for it;
 * measured as the register WS2025's secure kernel reads through 0x0051 just
 * before it gives up (R2r).
 */
#define HV_REGISTER_PENDING_EVENT0  0x00010004
#include "cpu.h"
#include "internals.h"
#include "system/memory.h"
#include <linux/kvm.h>  /* KVM_REG_ARM_TIMER_CNT */
#include "exec/memattrs.h"
#include "hyperv-arm.h"
#include "hyperv-vsm.h"
#include "trace.h"

/* hvdef HvArm64RegisterName (vm/hv1/hvdef/src/lib.rs) */
enum {
    HV_ARM64_REGISTER_X0        = 0x00020000,
    HV_ARM64_REGISTER_X28       = 0x0002001C,
    HV_ARM64_REGISTER_FP        = 0x0002001D,
    HV_ARM64_REGISTER_LR        = 0x0002001E,
    HV_ARM64_REGISTER_SP        = 0x0002001F,
    HV_ARM64_REGISTER_SP_EL0    = 0x00020020,
    HV_ARM64_REGISTER_SP_ELX    = 0x00020021,
    HV_ARM64_REGISTER_PC        = 0x00020022,
    HV_ARM64_REGISTER_CPSR      = 0x00020023,
    HV_ARM64_REGISTER_MPIDR_EL1 = 0x00040001,
    HV_ARM64_REGISTER_SCTLR_EL1 = 0x00040002,
    HV_ARM64_REGISTER_TTBR0_EL1 = 0x00040005,
    HV_ARM64_REGISTER_TTBR1_EL1 = 0x00040006,
    HV_ARM64_REGISTER_TCR_EL1   = 0x00040007,
    HV_ARM64_REGISTER_ESR_EL1   = 0x00040008,
    HV_ARM64_REGISTER_FAR_EL1   = 0x00040009,
    HV_ARM64_REGISTER_MAIR_EL1  = 0x0004000b,
    HV_ARM64_REGISTER_VBAR_EL1  = 0x0004000c,
    HV_ARM64_REGISTER_ELR_EL1   = 0x00040015,
};

/* hvdef InitialVpContextArm64: the VP context of EnableVpVtl and StartVp */
struct hv_init_vp_context_arm64 {
    uint64_t pc;
    uint64_t sp_elh;
    uint64_t sctlr_el1;
    uint64_t mair_el1;
    uint64_t tcr_el1;
    uint64_t vbar_el1;
    uint64_t ttbr0_el1;
    uint64_t ttbr1_el1;
    uint64_t x18;
};

/* x1 to x17 carry the input of a fast hypercall on arm64 */
#define HV_ARM64_HCALL_FAST_INPUT_REGS  17

/* Inject one SGI edge into the selected plane's vCPU. */
static int plane_sgi(CPUState *cs, unsigned intid, bool level)
{
    unsigned long vcpu_id = kvm_arch_vcpu_id(cs);
    struct kvm_irq_level irq = {
        .irq = (KVM_ARM_IRQ_TYPE_SGI << KVM_ARM_IRQ_TYPE_SHIFT) |
               ((vcpu_id & KVM_ARM_IRQ_VCPU_MASK) << KVM_ARM_IRQ_VCPU_SHIFT) |
               ((vcpu_id >> 8) << KVM_ARM_IRQ_VCPU2_SHIFT) | intid,
        .level = level,
    };
    int ret;

    if (intid >= GIC_NR_SGIS) {
        ret = -EINVAL;
    } else if (cs->kvm_plane == 0) {
        ret = kvm_vm_ioctl(kvm_state, KVM_IRQ_LINE, &irq);
    } else {
        ret = kvm_plane_ioctl(cs->kvm_plane, KVM_IRQ_LINE, &irq);
    }
    trace_hyperv_vsm_arm_plane_sgi(hyperv_vp_index(cs), cs->kvm_plane, intid,
                                   level, ret);
    if (ret < 0) {
        error_report_once("hyperv-vsm: VP %u VTL%d cannot inject SGI %u: %d",
                          hyperv_vp_index(cs), cs->kvm_plane, intid, ret);
    }
    return ret;
}

/*
 * SynIC. KVM has no SynIC on arm64, so QEMU owns the registers, writes
 * the message page and injects the SINT vector as an SGI.
 */
bool hv_plane_arch_sint_userspace(void)
{
    return true;
}

int hv_plane_arch_sint_set(CPUState *cs, uint32_t sint, bool level)
{
    VpVsmState *vpvsm = get_vp_vsm(cs);
    int intid;

    if (!vpvsm || sint >= HV_SINT_COUNT) {
        return -EINVAL;
    }
    switch (hv_arm_sint_action(vpvsm->synic_sint[sint], level, &intid)) {
    case HV_ARM_SINT_HOLD:
        /* raised when the guest unmasks it, the message waits in its slot */
        return 0;
    case HV_ARM_SINT_INVALID:
        error_report_once("hyperv-vsm: VP %u VTL%d SINT%u = 0x%" PRIx64
                          " names no SGI", hyperv_vp_index(cs),
                          cs->kvm_plane, sint, vpvsm->synic_sint[sint]);
        return intid;
    default:
        return plane_sgi(cs, intid, level);
    }
}

/*
 * TLFS 11.8.3: every SINTx comes out of reset masked. Leaving them clear
 * would make an unprogrammed SINT look unmasked on SGI 0.
 */
static void synic_sint_reset(VpVsmState *vpvsm)
{
    int i;

    for (i = 0; i < HV_SINT_COUNT; i++) {
        vpvsm->synic_sint[i] = HV_SINT_MASKED;
    }
}

static void synic_update(CPUState *cs)
{
    VpVsmState *vpvsm = get_vp_vsm(cs);
    hwaddr msg = vpvsm->synic_simp & HV_SIMP_ENABLE ?
                 vpvsm->synic_simp & ~(hwaddr)(HV_HYP_PAGE_SIZE - 1) : 0;
    hwaddr evt = vpvsm->synic_siefp & HV_SIEFP_ENABLE ?
                 vpvsm->synic_siefp & ~(hwaddr)(HV_HYP_PAGE_SIZE - 1) : 0;

    hyperv_synic_update(cs, vpvsm->synic_sctl & HV_SYNIC_ENABLE, msg, evt);
    /* a message page or an enable can make a held intercept deliverable */
    hyperv_vsm_intercept_retry(cs);
}

/*
 * R2O diagnostic: every write that creates the SynIC state, and the whole
 * state at a point of interest. Read-only beyond the printing.
 */
static void r2o_synic_write_log(CPUState *cs, uint32_t name, uint64_t val)
{
    fprintf(stderr, "R2OSYNW VP %u vtl=%d name=0x%x val=0x%" PRIx64 "\n",
            hyperv_vp_index(cs), cs->kvm_plane, name, val);
}

static void r2o_synic_state_dump(CPUState *cs, const char *tag)
{
    VpVsmState *vpvsm = get_vp_vsm(cs);
    int i;

    if (!vpvsm) {
        fprintf(stderr, "R2OVSM %s VP %u vtl=%d: no VpVsmState\n", tag,
                hyperv_vp_index(cs), cs->kvm_plane);
        return;
    }
    fprintf(stderr, "R2OVSM %s VP %u vtl=%d SCONTROL=0x%" PRIx64
            " SIMP=0x%" PRIx64 " SIEFP=0x%" PRIx64 "\n", tag,
            hyperv_vp_index(cs), cs->kvm_plane, vpvsm->synic_sctl,
            vpvsm->synic_simp, vpvsm->synic_siefp);
    for (i = 0; i < HV_SINT_COUNT; i++) {
        fprintf(stderr, "R2OVSM %s   SINT%-2d=0x%" PRIx64 " vector=%u"
                " masked=%d auto_eoi=%d\n", tag, i, vpvsm->synic_sint[i],
                (unsigned)(vpvsm->synic_sint[i] & HV_SINT_VECTOR_MASK),
                !!(vpvsm->synic_sint[i] & HV_SINT_MASKED),
                !!(vpvsm->synic_sint[i] & HV_SINT_AUTO_EOI));
    }
    fprintf(stderr, "R2OVSM %s   VINA=0x%" PRIx64 " vector=%u enabled=%u"
            " auto_reset=%u auto_eoi=%u line=%d\n", tag, vpvsm->vina.as_uint64,
            (unsigned)vpvsm->vina.vector, (unsigned)vpvsm->vina.enabled,
            (unsigned)vpvsm->vina.auto_reset, (unsigned)vpvsm->vina.auto_eoi,
            vpvsm->vina_line);
    fprintf(stderr, "R2OVSM %s   intercept_route=%s unposted=%" PRIu64 "\n",
            tag, vpvsm->intercept_route ? "present" : "none",
            vpvsm->intercepts_unposted);
    hyperv_synic_dbg_dump(cs, tag);
}

static void synic_set_sint(CPUState *cs, unsigned sint, uint64_t val)
{
    VpVsmState *vpvsm = get_vp_vsm(cs);
    uint64_t old = vpvsm->synic_sint[sint];

    if ((old & (HV_SINT_MASKED | HV_SINT_VECTOR_MASK)) !=
        (val & (HV_SINT_MASKED | HV_SINT_VECTOR_MASK)) &&
        !(old & HV_SINT_MASKED)) {
        int old_intid = hv_arm_vector_sgi_intid(old);

        if (old_intid >= 0) {
            plane_sgi(cs, old_intid, false);
        }
    }
    vpvsm->synic_sint[sint] = val;
    trace_hyperv_vsm_arm_synic_sint(hyperv_vp_index(cs), cs->kvm_plane, sint,
                                    val, hv_arm_vector_sgi_intid(val),
                                    !!(val & HV_SINT_MASKED));
    /* an unmask can make a held intercept deliverable */
    hyperv_vsm_intercept_retry(cs);
}

static void vina_line(CPUState *cs, bool level)
{
    VpVsmState *vpvsm = get_vp_vsm(cs);
    int intid;

    if (vpvsm->vina_line == level) {
        return;
    }
    vpvsm->vina_line = level;
    intid = hv_arm_vector_sgi_intid(vpvsm->vina.as_uint64);
    trace_hyperv_vsm_arm_vina_sgi(hyperv_vp_index(cs), cs->kvm_plane, intid,
                                  level);
    if (intid < 0) {
        error_report_once("hyperv-vsm: VP %u VTL%d VINA = 0x%" PRIx64
                          " names no SGI", hyperv_vp_index(cs),
                          cs->kvm_plane, vpvsm->vina.as_uint64);
        return;
    }
    plane_sgi(cs, intid, level);
}

/*
 * Plane API hooks
 */

bool hv_plane_arch_host_supported(int vtl)
{
    /* a plane has its own stage-2 table, so protections hold per VTL */
    if (kvm_vm_check_extension(kvm_state, KVM_CAP_PLANES) < 2) {
        error_report("hyperv-vsm: VTL%d needs KVM planes on this host", vtl);
        return false;
    }
    if (!kvm_vm_check_extension(kvm_state, KVM_CAP_ARM_IRQ_LINE_SGI)) {
        error_report("hyperv-vsm: VTL%d needs plane SGI injection", vtl);
        return false;
    }
    return true;
}

/*
 * The plane vCPU is the leader's twin: same cpu_index (the Hyper-V VP
 * index) and MPIDR, the same exception levels and PSCI conduit. Steal time
 * needs an IPA region per vCPU, which the twin has not.
 */
void hv_plane_arch_vcpu_init(CPUState *plane, CPUState *leader)
{
    static const char *const copied[] = {
        "mp-affinity", "has_el3", "has_el2", "psci-conduit",
    };
    Object *obj = OBJECT(plane);
    int i;

    plane->cpu_index = leader->cpu_index;
    for (i = 0; i < ARRAY_SIZE(copied); i++) {
        if (object_property_find(OBJECT(leader), copied[i])) {
            QObject *v = object_property_get_qobject(OBJECT(leader),
                                                     copied[i], NULL);
            object_property_set_qobject(obj, copied[i], v, NULL);
            qobject_unref(v);
        }
    }
    if (object_property_find(obj, "kvm-steal-time")) {
        object_property_set_bool(obj, "kvm-steal-time", false, NULL);
    }
}

void hv_plane_arch_trace_reset(CPUState *plane)
{
    CPUARMState *env = &ARM_CPU(plane)->env;

    trace_hyperv_vsm_arm_plane_vcpu_reset(hyperv_vp_index(plane),
                                          plane->kvm_plane, env->pc,
                                          env->cp15.sctlr_el[1],
                                          env->cp15.vbar_el[1]);
}

/*
 * TLFS 15.3.1 VTL-shared state: X0-X17, X19-X30 and the 128-bit vector
 * registers. X18, the stack pointers, PC, PSTATE, FPCR, FPSR and the system
 * registers stay with the plane. SVE above 128 bits is private too; a VTL
 * switch leaves it where it is.
 */
static void move_shared_state(CPUState *from, CPUState *to)
{
    CPUARMState *src = &ARM_CPU(from)->env;
    CPUARMState *dst = &ARM_CPU(to)->env;
    int i;

    for (i = 0; i < 31; i++) {
        if (i != 18) {
            dst->xregs[i] = src->xregs[i];
        }
    }
    for (i = 0; i < 32; i++) {
        dst->vfp.zregs[i].d[0] = src->vfp.zregs[i].d[0];
        dst->vfp.zregs[i].d[1] = src->vfp.zregs[i].d[1];
    }
}

/*
 * HV_VP_VTL_CONTROL carries the entry reason and VINA state on ARM64. Its
 * return-register slots are x64-only; move_shared_state() carries X0/X1.
 */
int hv_plane_arch_switch_state(CPUState *cs, CPUState *target,
                               HvPlaneSwitchReason reason)
{
    CPUARMState *prev_env = &ARM_CPU(cs)->env;
    CPUARMState *next_env = &ARM_CPU(target)->env;
    struct hv_vp_vtl_control ctl;

    cpu_synchronize_state(cs);
    cpu_synchronize_state(target);

    trace_hyperv_vsm_arm_vtl_switch(hyperv_vp_index(cs), cs->kvm_plane,
                                    target->kvm_plane, reason, prev_env->pc,
                                    next_env->pc);

    bql_lock();
    move_shared_state(cs, target);
    if (reason == HV_PLANE_SWITCH_VTL_RETURN) fprintf(stderr, "R2VTLRET vp=%u from_plane=%d to_plane=%d to_pc=0x%llx\n", hyperv_vp_index(cs), cs->kvm_plane, target->kvm_plane, (unsigned long long)next_env->pc);
    if (reason == HV_PLANE_SWITCH_VTL_RETURN && hyperv_vp_index(cs) != 0) {
        static uint32_t r2order_seen;
        uint32_t vp = hyperv_vp_index(cs);
        if (vp < 32 && !(r2order_seen & (1u << vp))) {
            uint64_t ttbr1 = next_env->cp15.ttbr1_el[1];
            uint64_t tcr = next_env->cp15.tcr_el[1];
            uint64_t pc = next_env->pc;
            uint64_t base4k = ttbr1 & 0x0000fffffffff000ULL;
            uint64_t base2k = base4k | (ttbr1 & 0x800ULL);
            uint32_t t1sz = (uint32_t)((tcr >> 16) & 0x3f);
            uint32_t idx512 = (uint32_t)((pc >> 39) & 0x1ff);
            uint32_t idx256 = (uint32_t)((pc >> 39) & 0xff);
            uint64_t l0page[512] = {0};
            uint64_t e256 = 0;
            MemTxResult mr1, mr2;
            int nz = 0, i;
            r2order_seen |= (1u << vp);
            mr1 = address_space_read(target->as, base4k, MEMTXATTRS_UNSPECIFIED,
                                     l0page, sizeof(l0page));
            for (i = 0; i < 512; i++) {
                if (l0page[i]) {
                    nz++;
                }
            }
            mr2 = address_space_read(target->as,
                                     base2k + (uint64_t)idx256 * 8,
                                     MEMTXATTRS_UNSPECIFIED, &e256, 8);
            fprintf(stderr, "R2ORDER vp=%u firstVTLRET ttbr1=0x%llx tcr=0x%llx "
                    "t1sz=%u pc=0x%llx base4k=0x%llx mr=%d/%d nz512=%d "
                    "idx512=%u L0_4k=0x%llx base2k=0x%llx idx256=%u "
                    "L0_2k=0x%llx\n",
                    vp, (unsigned long long)ttbr1, (unsigned long long)tcr,
                    t1sz, (unsigned long long)pc, (unsigned long long)base4k,
                    (int)mr1, (int)mr2, nz, idx512,
                    (unsigned long long)l0page[idx512],
                    (unsigned long long)base2k, idx256,
                    (unsigned long long)e256);
        }
    }

    if (reason == HV_PLANE_SWITCH_VTL_RETURN) {
        if (hv_vsm_arch_ops.vp_assist_enabled(cs)) {
            read_vtl_control(cs, &ctl);
            if (!ctl.vina_asserted) {
                vina_line(cs, false);
            }
        }
    } else if (hv_vsm_arch_ops.vp_assist_enabled(target)) {
        read_vtl_control(target, &ctl);
        /* TLFS: AutoReset clears VINA on the next entry to this VTL. */
        if (ctl.vina_asserted && get_vp_vsm(target)->vina.auto_reset) {
            ctl.vina_asserted = 0;
        }
        ctl.vtl_entry_reason = reason == HV_PLANE_SWITCH_VTL_CALL ?
                               HV_VTL_ENTRY_VTL_CALL :
                               HV_VTL_ENTRY_INTERRUPT;
        write_vtl_control(target, &ctl);
    }
    bql_unlock();

    /* both files are dirty after the synchronise: pushed before KVM_RUN */
    return 0;
}

void hv_plane_arch_pre_run(CPUState *cs, struct kvm_run *run)
{
}

bool hv_plane_arch_vina_armed(CPUState *cs)
{
    VpVsmState *vpvsm = get_vp_vsm(cs);
    bool armed = hyperv_vsm_vina_armed(cs);

    if (armed) {
        vina_line(cs, false);
    }
    /*
     * Keep KVM tracking the pending level while VinaAsserted gates SGI edges.
     */
    return vpvsm && vpvsm->vina.enabled;
}

/*
 * The VINA vector is raised in the VTL's own GIC (TLFS vsm.md "each VTL has
 * a separate GIC") as a PPI of its vCPU, a level the guest's VINA handling
 * takes down after AutoReset on the next VTL entry, or after the guest
 * clears vina_asserted and userspace observes it before another run.
 */
void hv_plane_arch_vina_notify(CPUState *cs)
{
    VpVsmState *vpvsm = get_vp_vsm(cs);

    if (!vpvsm || !vpvsm->vina.enabled || vina_asserted(cs)) {
        return;
    }
    set_vina_asserted(cs, true);
    vina_line(cs, true);
}

int hv_plane_arch_desc_load(CPUState *cs, struct kvm_plane_event_exit *ev)
{
    error_report("hyperv-vsm: VP %u VTL%d: descriptor load event on arm64",
                 hyperv_vp_index(cs), cs->kvm_plane);
    return -1;
}

/*
 * VSM core ops
 */

static hwaddr vtl_control_gpa(CPUState *cs)
{
    return (get_vp_vsm(cs)->msr_hv_vp_assist &
            HV_X64_MSR_VP_ASSIST_PAGE_ADDRESS_MASK) +
           offsetof(struct hv_vp_assist_page, vtl_control);
}

static bool vp_assist_enabled(CPUState *cs)
{
    VpVsmState *vpvsm = get_vp_vsm(cs);

    return vpvsm &&
           (vpvsm->msr_hv_vp_assist & HV_X64_MSR_VP_ASSIST_PAGE_ENABLE);
}

/*
 * Load an InitialVpContextArm64 into @cs: EL1h with interrupts masked, the
 * translation and exception registers from the context, every other
 * register zero so a VP the firmware already ran hands nothing over.
 */
static void load_vp_context(CPUState *cs, const struct hv_init_vp_context *x,
                            bool enable_spiv, hwaddr input_gpa)
{
    struct hv_init_vp_context_arm64 ctx, *c = &ctx;
    CPUARMState *env = &ARM_CPU(cs)->env;

    /* the core reads the x64-sized context; the arm64 layout leads it */
    QEMU_BUILD_BUG_ON(sizeof(ctx) > sizeof(*x));
    memcpy(&ctx, x, sizeof(ctx));
    trace_hyperv_vsm_arm_vp_context(hyperv_vp_index(cs), cs->kvm_plane, c->pc,
                                    c->sp_elh, c->sctlr_el1, c->ttbr0_el1,
                                    c->ttbr1_el1, c->vbar_el1, c->tcr_el1,
                                    input_gpa);

    memset(env->xregs, 0, sizeof(env->xregs));
    env->xregs[18] = c->x18;
    env->aarch64 = true;
    pstate_write(env, PSTATE_MODE_EL1h | PSTATE_DAIF);
    env->pc = c->pc;
    env->sp_el[0] = 0;
    env->sp_el[1] = c->sp_elh;
    env->xregs[31] = c->sp_elh;
    env->cp15.sctlr_el[1] = c->sctlr_el1;
    env->cp15.mair_el[1] = c->mair_el1;
    env->cp15.tcr_el[1] = c->tcr_el1;
    env->cp15.vbar_el[1] = c->vbar_el1;
    env->cp15.ttbr0_el[1] = c->ttbr0_el1;
    env->cp15.ttbr1_el[1] = c->ttbr1_el1;
    env->elr_el[1] = 0;
    env->banked_spsr[aarch64_banked_spsr_index(1)] = 0;
    cs->halted = 0;
}

/* the SynIC registers are not readable from here on arm64 */
static void trace_vtl1_synic_once(CPUState *cs)
{
    VpVsmState *vpvsm = get_vp_vsm(cs);

    if (vpvsm->synic_traced) {
        return;
    }
    vpvsm->synic_traced = true;
    qemu_log_mask(LOG_UNIMP, "hyperv-vsm: VP %u VTL%d SynIC state not read "
                  "on arm64\n", hyperv_vp_index(cs), cs->kvm_plane);
}

static uint64_t r_arm_40004[64]; /* R3o iter4: HV reg 0x40004 per-VP store */
static uint16_t get_vp_register(uint32_t name, struct hv_u128 *val,
                                CPUState *target_vcpu)
{
    VpVsmState *vpvsm = get_vp_vsm(target_vcpu);
    ARMCPU *cpu = ARM_CPU(target_vcpu);
    CPUARMState *env = &cpu->env;

    val->low_part = val->high_part = 0;

    switch (name) {
    case HV_ARM64_REGISTER_X0 ... HV_ARM64_REGISTER_LR:
        val->low_part = env->xregs[name - HV_ARM64_REGISTER_X0];
        break;
    case HV_ARM64_REGISTER_SP:
        val->low_part = env->xregs[31];
        break;
    case HV_ARM64_REGISTER_SP_EL0:
        val->low_part = env->sp_el[0];
        break;
    case HV_ARM64_REGISTER_SP_ELX:
        val->low_part = env->sp_el[1];
        break;
    case HV_ARM64_REGISTER_PC:
        val->low_part = env->pc;
        break;
    case HV_ARM64_REGISTER_CPSR:
        val->low_part = pstate_read(env);
        break;
    case HV_ARM64_REGISTER_MPIDR_EL1:
        val->low_part = cpu->mp_affinity;
        break;
    case HV_ARM64_REGISTER_SCTLR_EL1:
        val->low_part = env->cp15.sctlr_el[1];
        break;
    case HV_ARM64_REGISTER_TTBR0_EL1:
        val->low_part = env->cp15.ttbr0_el[1];
        break;
    case HV_ARM64_REGISTER_TTBR1_EL1:
        val->low_part = env->cp15.ttbr1_el[1];
        break;
    case HV_ARM64_REGISTER_TCR_EL1:
        val->low_part = env->cp15.tcr_el[1];
        break;
    case HV_ARM64_REGISTER_ESR_EL1:
        val->low_part = env->cp15.esr_el[1];
        break;
    case HV_ARM64_REGISTER_FAR_EL1:
        val->low_part = env->cp15.far_el[1];
        break;
    case HV_ARM64_REGISTER_MAIR_EL1:
        val->low_part = env->cp15.mair_el[1];
        break;
    case HV_ARM64_REGISTER_VBAR_EL1:
        val->low_part = env->cp15.vbar_el[1];
        break;
    case HV_ARM64_REGISTER_ELR_EL1:
        val->low_part = env->elr_el[1];
        break;
    case 0x00040004: /* R3o iter4: unnamed VTL1 EL1 ctx reg (was REFUSED) */
        val->low_part = r_arm_40004[hyperv_vp_index(target_vcpu) & 63];
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
    case HV_REGISTER_GUEST_OS_ID:
        val->low_part = cpu->hyperv_guest_os_id;
        break;
    case HV_REGISTER_VP_CONFIG:
        val->low_part = vpvsm->vp_config;
        break;
    case HV_REGISTER_UNDOCUMENTED_90005:
        val->low_part = vpvsm->undocumented_90005;
        break;
    case HV_REGISTER_REFERENCE_TSC:
        val->low_part = vpvsm->msr_hv_tsc;
        break;
    case HV_REGISTER_VSM_VINA:
        val->low_part = vpvsm->vina.as_uint64;
        break;
    case HV_REGISTER_VSM_CODE_PAGE_OFFSETS:
        /* vsm.md: "not available on ARM64" */
        qemu_log_mask(LOG_GUEST_ERROR, "hyperv-vsm: GetVpRegisters: "
                      "HvRegisterVsmCodePageOffsets is x64 only\n");
        return HV_STATUS_INVALID_PARAMETER;
    case HV_REGISTER_SINT0 ... HV_REGISTER_SINT15:
        val->low_part = vpvsm->synic_sint[name - HV_REGISTER_SINT0];
        break;
    case HV_REGISTER_PENDING_EVENT0:
        /* no event is injected yet, so this reads back what was written */
        val->low_part = vpvsm->pending_event0[0];
        val->high_part = vpvsm->pending_event0[1];
        break;
    case HV_REGISTER_SCONTROL:
        val->low_part = vpvsm->synic_sctl;
        break;
    case HV_REGISTER_SVERSION:
        val->low_part = HV_SYNIC_VERSION;
        break;
    case HV_REGISTER_SIEFP:
        val->low_part = vpvsm->synic_siefp;
        break;
    case HV_REGISTER_SIMP:
        val->low_part = vpvsm->synic_simp;
        break;
    case 0x000B0000 ... 0x000B0007: { /* HvRegisterStimer{0..3}{Config,Count} */
        int n = (name - 0x000B0000) >> 1;
        val->low_part = ((name - 0x000B0000) & 1) ? vpvsm->stimer_count[n]
                                                  : vpvsm->stimer_config[n];
        break;
    }
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "hyperv-vsm: GetVpRegisters: unknown "
                      "register 0x%x\n", name);
        return HV_STATUS_INVALID_PARAMETER;
    }

    trace_hyperv_vsm_arm_vp_register(false, hyperv_vp_index(target_vcpu),
                                     target_vcpu->kvm_plane, name,
                                     val->low_part);
    return HV_STATUS_SUCCESS;
}

typedef struct ArmStimerCtx { CPUState *cs; int idx; } ArmStimerCtx;

/*
 * Hyper-V synthetic timers (arm64). KVM arm64 has no in-kernel SynIC/stimer,
 * so QEMU drives them: a periodic QEMU timer injects the configured interrupt.
 * Direct mode delivers the vector as a GIC SGI to this plane; message mode
 * raises the configured SINTx. First cut uses a fixed tick, not the exact
 * reference-time deadline, enough to unblock the guest's periodic tick.
 */
static void arm_stimer_cb(void *opaque)
{
    ArmStimerCtx *c = opaque;
    CPUState *cs = c->cs;
    VpVsmState *vpvsm = get_vp_vsm(cs);
    uint64_t cfg;

    if (!vpvsm) {
        return;
    }
    cfg = vpvsm->stimer_config[c->idx];
    if (!((cfg & 1) || ((cfg >> 3) & 1))) {
        return;
    }
    if ((cfg >> 12) & 1) {
        plane_sgi(cs, (cfg >> 4) & 0xff, true);
    } else {
        hv_plane_arch_sint_set(cs, (cfg >> 16) & 0xf, true);
    }
    timer_mod((QEMUTimer *)vpvsm->stimer_qt[c->idx],
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1000000);
}

static void arm_stimer_update(CPUState *cs, int n)
{
    VpVsmState *vpvsm = get_vp_vsm(cs);
    uint64_t cfg = vpvsm->stimer_config[n];
    uint64_t cnt = vpvsm->stimer_count[n];
    bool enable = (cfg & 1) || ((cfg >> 3) & 1);

    if (enable && cnt) { /* R4a: arm only when the guest set a Count */
        if (!vpvsm->stimer_qt[n]) {
            ArmStimerCtx *c = g_new0(ArmStimerCtx, 1);
            c->cs = cs;
            c->idx = n;
            vpvsm->stimer_qt[n] = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                               arm_stimer_cb, c);
        }
        timer_mod((QEMUTimer *)vpvsm->stimer_qt[n],
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1000000);
    } else if (vpvsm->stimer_qt[n]) {
        timer_del((QEMUTimer *)vpvsm->stimer_qt[n]);
    }
}

static uint16_t set_vp_register(uint32_t name, const struct hv_u128 *val,
                                CPUState *target_vcpu, bool *dirty)
{
    VpVsmState *vpvsm = get_vp_vsm(target_vcpu);
    ARMCPU *cpu = ARM_CPU(target_vcpu);
    CPUARMState *env = &cpu->env;

    trace_hyperv_vsm_arm_vp_register(true, hyperv_vp_index(target_vcpu),
                                     target_vcpu->kvm_plane, name,
                                     val->low_part);

    switch (name) {
    case HV_ARM64_REGISTER_X0 ... HV_ARM64_REGISTER_LR:
        env->xregs[name - HV_ARM64_REGISTER_X0] = val->low_part;
        break;
    case HV_ARM64_REGISTER_SP:
        env->xregs[31] = val->low_part;
        break;
    case HV_ARM64_REGISTER_SP_EL0:
        env->sp_el[0] = val->low_part;
        break;
    case HV_ARM64_REGISTER_SP_ELX:
        env->sp_el[1] = val->low_part;
        break;
    case HV_ARM64_REGISTER_PC:
        env->pc = val->low_part;
        break;
    case HV_ARM64_REGISTER_CPSR:
        pstate_write(env, val->low_part);
        break;
    case HV_ARM64_REGISTER_SCTLR_EL1:
        env->cp15.sctlr_el[1] = val->low_part;
        break;
    case HV_ARM64_REGISTER_TTBR0_EL1:
        env->cp15.ttbr0_el[1] = val->low_part;
        break;
    case HV_ARM64_REGISTER_TTBR1_EL1:
        env->cp15.ttbr1_el[1] = val->low_part;
        break;
    case HV_ARM64_REGISTER_TCR_EL1:
        env->cp15.tcr_el[1] = val->low_part;
        break;
    case HV_ARM64_REGISTER_ESR_EL1:
        env->cp15.esr_el[1] = val->low_part;
        break;
    case HV_ARM64_REGISTER_FAR_EL1:
        env->cp15.far_el[1] = val->low_part;
        break;
    case HV_ARM64_REGISTER_MAIR_EL1:
        env->cp15.mair_el[1] = val->low_part;
        break;
    case HV_ARM64_REGISTER_VBAR_EL1:
        env->cp15.vbar_el[1] = val->low_part;
        break;
    case HV_ARM64_REGISTER_ELR_EL1:
        env->elr_el[1] = val->low_part;
        break;
    case 0x00040004: /* R3o iter4: unnamed VTL1 EL1 ctx reg (was REFUSED) */
        r_arm_40004[hyperv_vp_index(target_vcpu) & 63] = val->low_part;
        break;
    case HV_ARM64_REGISTER_MPIDR_EL1:
        /* read-only */
        return HV_STATUS_INVALID_PARAMETER;
    case HV_REGISTER_VSM_PARTITION_CONFIG:
        set_vsm_partition_config(active_vtl(target_vcpu), val->low_part);
        return HV_STATUS_SUCCESS;
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0 ...
         HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL14:
        if (!set_vp_secure_vtl_config(target_vcpu, name, val->low_part)) {
            return HV_STATUS_INVALID_PARAMETER;
        }
        return HV_STATUS_SUCCESS;
    case HV_REGISTER_VP_ASSIST_PAGE: {
        /* vp-properties.md: the x64 MSR format, set through this register */
        uint64_t v = val->low_part;
        bool on = v & HV_X64_MSR_VP_ASSIST_PAGE_ENABLE;
        hwaddr gpa = v & HV_X64_MSR_VP_ASSIST_PAGE_ADDRESS_MASK;

        trace_hyperv_vsm_arm_vp_assist_page(hyperv_vp_index(target_vcpu),
                                            target_vcpu->kvm_plane, on, gpa);
        vpvsm->msr_hv_vp_assist = v;
        return HV_STATUS_SUCCESS;
    }
    case HV_REGISTER_GUEST_OS_ID:
        cpu->hyperv_guest_os_id = val->low_part;
        return HV_STATUS_SUCCESS;
    case HV_REGISTER_VP_CONFIG:
        vpvsm->vp_config = val->low_part;
        return HV_STATUS_SUCCESS;
    case HV_REGISTER_UNDOCUMENTED_90005:
        vpvsm->undocumented_90005 = val->low_part;
        return HV_STATUS_SUCCESS;
    case HV_REGISTER_REFERENCE_TSC: {
        /*
         * Publish the reference-time page the guest reads through
         * cntvct_el0. On ARM64 the Hyper-V reference TSC is the virtual
         * counter: the page holds {sequence, scale, offset} and the guest
         * computes (cntvct * scale >> 64) + offset in 100 ns units. With
         * the page present QueryPerformanceCounter takes its fast path
         * instead of the TIME_REF_COUNT hypercall.
         */
        uint64_t v = val->low_part;
        uint64_t gpa = v & ~0xfffULL;
        uint64_t cntfrq = cpu->gt_cntfrq_hz ? cpu->gt_cntfrq_hz
                                            : GTIMER_DEFAULT_HZ;
        uint64_t scale = (uint64_t)(((__uint128_t)10000000ULL << 64) /
                                    cntfrq);
        uint64_t cnt = 0;
        int64_t off = 0;
        struct {
            uint32_t sequence;
            uint32_t reserved;
            uint64_t tsc_scale;
            int64_t tsc_offset;
            uint8_t pad[40];
        } page;

        vpvsm->msr_hv_tsc = v;
        if (!(v & 1)) {
            vpvsm->ref_tsc_gpa = 0;
            return HV_STATUS_SUCCESS;
        }
        if (kvm_get_one_reg(target_vcpu, KVM_REG_ARM_TIMER_CNT, &cnt) == 0) {
            off = (int64_t)(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / 100) -
                  (int64_t)(uint64_t)(((__uint128_t)cnt * scale) >> 64);
        }
        memset(&page, 0, sizeof(page));
        page.sequence = 1;
        page.tsc_scale = scale;
        page.tsc_offset = off;
        vpvsm->ref_tsc_gpa = gpa;
        vsm_physmem_write(target_vcpu, gpa, &page, sizeof(page));
        fprintf(stderr, "R4aTSC vp=%u vtl=%d gpa=0x%llx cntfrq=%llu "
                "scale=0x%llx cnt=0x%llx off=0x%llx\n",
                hyperv_vp_index(target_vcpu), target_vcpu->kvm_plane,
                (unsigned long long)gpa, (unsigned long long)cntfrq,
                (unsigned long long)scale, (unsigned long long)cnt,
                (unsigned long long)off);
        return HV_STATUS_SUCCESS;
    }
    case HV_REGISTER_VSM_VINA:
        r2o_synic_write_log(target_vcpu, name, val->low_part);
        vina_line(target_vcpu, false);
        set_vina(target_vcpu, val->low_part);
        return HV_STATUS_SUCCESS;
    case HV_REGISTER_SINT0 ... HV_REGISTER_SINT15:
        r2o_synic_write_log(target_vcpu, name, val->low_part);
        synic_set_sint(target_vcpu, name - HV_REGISTER_SINT0, val->low_part);
        return HV_STATUS_SUCCESS;
    case HV_REGISTER_SCONTROL:
        r2o_synic_write_log(target_vcpu, name, val->low_part);
        vpvsm->synic_sctl = val->low_part;
        synic_update(target_vcpu);
        return HV_STATUS_SUCCESS;
    case HV_REGISTER_SIEFP:
        r2o_synic_write_log(target_vcpu, name, val->low_part);
        vpvsm->synic_siefp = val->low_part;
        synic_update(target_vcpu);
        return HV_STATUS_SUCCESS;
    case HV_REGISTER_SIMP:
        r2o_synic_write_log(target_vcpu, name, val->low_part);
        vpvsm->synic_simp = val->low_part;
        synic_update(target_vcpu);
        return HV_STATUS_SUCCESS;
    case HV_REGISTER_EOM:
        hyperv_synic_eom(target_vcpu);
        return HV_STATUS_SUCCESS;
    case 0x000B0000 ... 0x000B0007: { /* HvRegisterStimer{0..3}{Config,Count} */
        int n = (name - 0x000B0000) >> 1;
        if (!((name - 0x000B0000) & 1)) {
            vpvsm->stimer_config[n] = val->low_part;
        } else {
            vpvsm->stimer_count[n] = val->low_part;
        }
        arm_stimer_update(target_vcpu, n);
        return HV_STATUS_SUCCESS;
    }
    case HV_REGISTER_PENDING_EVENT0:
        /*
         * TLFS vsm.md "Handling Secure Intercepts": a higher VTL completes an
         * intercept by injecting an event into the lower VTL. The value is
         * stored and traced; the injection into plane 0 is not done yet, so
         * accepting the write records what VTL1 asks for without claiming the
         * lower VTL saw it.
         */
        vpvsm->pending_event0[0] = val->low_part;
        vpvsm->pending_event0[1] = val->high_part;
        trace_hyperv_vsm_arm_pending_event(hyperv_vp_index(target_vcpu),
                                           target_vcpu->kvm_plane,
                                           val->low_part, val->high_part);
        qemu_log_mask(LOG_UNIMP, "hyperv-vsm: HvRegisterPendingEvent0 is "
                      "stored, not injected into the lower VTL\n");
        return HV_STATUS_SUCCESS;
    case HV_X64_REGISTER_CR_INTERCEPT_CONTROL ...
         HV_X64_REGISTER_CR_INTERCEPT_IA32_MISC_ENABLE_MASK:
        /* vsm.md "Secure Register Intercepts": x64 only */
        qemu_log_mask(LOG_GUEST_ERROR, "hyperv-vsm: SetVpRegisters: register "
                      "intercept 0x%x is x64 only\n", name);
        return HV_STATUS_INVALID_PARAMETER;
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "hyperv-vsm: SetVpRegisters: unknown "
                      "register 0x%x\n", name);
        return HV_STATUS_INVALID_PARAMETER;
    }

    *dirty = true;
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

/*
 * The syndrome of a stage-2 abort the lower VTL would have seen had the
 * access faulted at EL1: an abort from a lower exception level, a 32-bit
 * instruction, a level-3 permission fault, WnR for a write. What Hyper-V
 * puts here is unverified (no trace of a secure-kernel intercept yet).
 */
static uint64_t intercept_syndrome(uint8_t access)
{
    if (access == HV_X64_INTERCEPT_ACCESS_TYPE_EXECUTE) {
        return syn_insn_abort(0, 0, 0, 0xf);
    }
    return syn_data_abort_no_iss(0, 0, 0, 0, 0,
                                 access == HV_X64_INTERCEPT_ACCESS_TYPE_WRITE,
                                 0xf);
}

/* set across one injected fault so build_memory_intercept emits a valid ISS */
static bool inject_intercept_active;

/*
 * The GPA intercept message of a lower-VTL fault (TLFS vsm.md "memory
 * intercept") in the hvdef ARM64 layout. The instruction bytes are
 * reported for a data access only, as on x86; no GVA is known for a
 * stage-2 fault.
 */
static void build_memory_intercept(CPUState *cs, struct hyperv_message *msg,
                                   uint64_t gpa, uint64_t flags)
{
    CPUARMState *env = &ARM_CPU(cs)->env;
    HvArmMemoryIntercept f = {};
    uint32_t insn;

    /*
     * kvm_hv_handle_fault() synchronises @cs before this hook. Repeating it
     * keeps the contract local to the builder; it is a no-op while the
     * register file is already dirty.
     */
    cpu_synchronize_state(cs);

    f.vp_index = hyperv_vp_index(cs);
    f.vtl = cs->kvm_plane;
    f.cpl = arm_current_el(env);
    f.access_type = intercept_access_type(flags);
    f.pc = env->pc;
    f.cpsr = pstate_read(env);
    f.gpa = gpa;
    f.gva_valid = false;        /* a stage-2 abort names no GVA */
    f.syndrome = intercept_syndrome(f.access_type);

    if (inject_intercept_active) {
        /*
         * Synthetic fault (QEMU_R2Q_INJECT_INTERCEPT). The parked lower-VTL
         * instruction does not access @gpa, so an ISV=0 syndrome and the
         * bytes at @pc contradict @gpa and the secure kernel drops the
         * message. Describe the access with a valid ISS taken from that
         * instruction and send no bytes: the secure kernel reads the
         * syndrome and does not decode an instruction that would disagree.
         */
        uint32_t insn4 = 0;
        bool is_store = true, sf = true;
        unsigned sas = 3, srt = 18;

        inject_intercept_active = false;
        if (cpu_memory_rw_debug(cs, f.pc, (uint8_t *)&insn4, sizeof(insn4),
                                false) == 0) {
            hv_arm_decode_ldst(insn4, &is_store, &sas, &srt, &sf);
        }
        f.access_type = is_store ? HV_X64_INTERCEPT_ACCESS_TYPE_WRITE
                                 : HV_X64_INTERCEPT_ACCESS_TYPE_READ;
        f.syndrome = syn_data_abort_with_iss(0, sas, 0, srt, sf, 0,
                                             0, 0, 0, is_store, 0xf, false);
        f.insn_count = 0;
    } else if (f.access_type != HV_X64_INTERCEPT_ACCESS_TYPE_EXECUTE &&
               !cpu_memory_rw_debug(cs, f.pc, f.insn_bytes,
                                    sizeof(f.insn_bytes), false)) {
        f.insn_count = sizeof(f.insn_bytes);
    }

    hv_arm_build_memory_intercept(&f, msg);

    insn = f.insn_bytes[0] | f.insn_bytes[1] << 8 |
           f.insn_bytes[2] << 16 | (uint32_t)f.insn_bytes[3] << 24;
    trace_hyperv_vsm_arm_memory_intercept(f.vp_index, f.vtl, f.pc, gpa,
                                          f.access_type, f.insn_count, insn,
                                          f.gva_valid, f.syndrome);
}

/*
 * Post the intercept on SINT0 of the secure VTL's SynIC (TLFS 15.10), the
 * same way as x86; the route raises the SINT's PPI through
 * hv_plane_arch_sint_set(). A busy slot keeps the message in flight: the
 * lower VTL is stopped at the instruction and repeats it.
 */
static int deliver_memory_intercept(CPUState *cs,
                                    const struct hyperv_message *msg)
{
    VpVsmState *vpvsm = get_vp_vsm(cs);
    int ret;

    vpvsm->intercept_msg = *msg;
    if (!vpvsm->intercept_route) {
        vpvsm->intercept_route = hyperv_sint_route_new(hyperv_vp_index(cs),
                                                       cs->kvm_plane, 0,
                                                       intercept_cb, vpvsm);
    }
    if (!vpvsm->intercept_route) {
        error_report("hyperv-vsm: cannot create the intercept SINT route for "
                     "VP %u VTL%d", hyperv_vp_index(cs), cs->kvm_plane);
        return -1;
    }
    r2o_synic_state_dump(cs, "at-fault");
    ret = hyperv_post_msg(vpvsm->intercept_route, &vpvsm->intercept_msg);
    fprintf(stderr, "R2OPOST VP %u vtl=%d type=0x%x armed=%d post_ret=%d\n",
            hyperv_vp_index(cs), cs->kvm_plane,
            vpvsm->intercept_msg.header.message_type,
            hyperv_sint_route_armed(vpvsm->intercept_route), ret);
    trace_hyperv_vsm_arm_intercept_post(hyperv_vp_index(cs), cs->kvm_plane,
                                        msg->header.message_type,
                                        hyperv_sint_route_armed(
                                            vpvsm->intercept_route),
                                        vpvsm->synic_sint[0], ret);
    if (ret && ++vpvsm->intercepts_unposted == 1) {
        error_report("hyperv-vsm: VP %u VTL%d: intercept slot busy, the lower "
                     "VTL re-faults until the secure VTL acknowledges",
                     hyperv_vp_index(cs), cs->kvm_plane);
    } else if (!ret) {
        vpvsm->intercepts_unposted = 0;
    }
    return 0;
}

/* a frame the hypervisor overlays on @cs's GPA space rather than RAM */
static bool gpa_is_overlay(CPUState *cs, uint64_t gpa)
{
    VpVsmState *vpvsm = get_vp_vsm(cs);
    uint64_t hcall = hv_vsm.hypercall[active_vtl(cs)] &
                     HV_X64_MSR_HYPERCALL_PAGE_ADDRESS_MASK;
    uint64_t assist = vpvsm->msr_hv_vp_assist &
                      HV_X64_MSR_VP_ASSIST_PAGE_ADDRESS_MASK;

    return hcall == gpa || assist == gpa;
}

/*
 * arm64 KVM implements neither KVM_TRANSLATE2 nor
 * KVM_HYPERV_SET_TLB_FLUSH_INHIBIT, so the walk is QEMU's own debug walk of
 * the plane vCPU's stage-1 tables, at that vCPU's current EL and translation
 * regime. It answers reachability only: a privilege failure and a reserved
 * page-table bit are not distinguishable from an unmapped GVA, so every
 * failure is reported as PAGE_NOT_PRESENT rather than guessed at.
 */
static uint32_t translate_gva(CPUState *target_vcpu, uint64_t gva_page,
                              uint64_t flags, uint64_t *gpa_page,
                              bool *overlay)
{
    TranslateForDebugResult tres;
    hwaddr gpa;

    cpu_synchronize_state(target_vcpu);
    if (!cpu_translate_for_debug(target_vcpu, gva_page << HV_HYP_PAGE_SHIFT,
                                 &tres)) {
        return HV_TRANSLATE_GVA_PAGE_NOT_PRESENT;
    }
    gpa = tres.physaddr;

    /*
     * The debug walk reads the tables and writes nothing, so an accessed or
     * dirty bit the caller asked for is not set. Say so rather than let the
     * caller believe it was.
     */
    if (flags & HV_TRANSLATE_GVA_SET_PAGE_TABLE_BITS) {
        qemu_log_mask(LOG_UNIMP, "hyperv-vsm: TranslateVirtualAddress: "
                      "accessed and dirty bits are not set on arm64\n");
    }
    if (flags & HV_TRANSLATE_GVA_TLB_FLUSH_INHIBIT) {
        qemu_log_mask(LOG_UNIMP, "hyperv-vsm: TranslateVirtualAddress: TLB "
                      "flush inhibit is not implemented on arm64\n");
    }

    *gpa_page = gpa >> HV_HYP_PAGE_SHIFT;
    *overlay = gpa_is_overlay(target_vcpu, gpa);
    return HV_TRANSLATE_GVA_SUCCESS;
}

/*
 * HvCallTranslateVirtualAddress. The guest calls the fast form with the TLFS
 * input block from x1 up and reads one output pair, so the four input words
 * are x1..x4 and the two output words are x15 and x16.
 *
 * x1 must be HV_PARTITION_ID_SELF. A different value means the input block
 * is not where this reads it, and the traced raw words say so instead of a
 * plausible wrong GPA reaching the guest.
 */
static uint64_t hcall_translate_virtual_address(CPUState *cs,
                                                struct kvm_run *run)
{
    CPUARMState *env = &ARM_CPU(cs)->env;
    struct hv_output_translate_virtual_address out;
    struct hv_input_translate_virtual_address in;
    uint16_t status;

    cpu_synchronize_state(cs);
    trace_hyperv_vsm_arm_translate_input(hyperv_vp_index(cs), cs->kvm_plane,
                                         env->xregs[0], env->xregs[1],
                                         env->xregs[2], env->xregs[3],
                                         env->xregs[4]);

    if (!(env->xregs[0] & HV_HYPERCALL_FAST)) {
        /* no boot has used the memory form of this call */
        qemu_log_mask(LOG_UNIMP, "hyperv-vsm: TranslateVirtualAddress: the "
                      "memory form is not served\n");
        return HV_STATUS_INVALID_HYPERCALL_INPUT;
    }

    memset(&in, 0, sizeof(in));
    in.partition_id = env->xregs[hv_arm_fast_in_reg(0)];
    in.vp_index = env->xregs[hv_arm_fast_in_reg(1)];
    in.control_flags = env->xregs[hv_arm_fast_in_reg(2)];
    in.gva_page = env->xregs[hv_arm_fast_in_reg(3)];

    status = hyperv_vsm_translate_gva(cs, &in, &out);
    if (status != HV_STATUS_SUCCESS) {
        return status;
    }

    {
        uint64_t val[2] = { out.translation_result.as_uint64, out.gpa_page };

        /* one output pair: x15 then x16 (hv_arm_fast_out, R2u ABI) */
        hv_arm_fast_out(env->xregs, val, 1);
    }
    return HV_STATUS_SUCCESS;
}

const HvVsmArchOps hv_vsm_arch_ops = {
    .vtl_control_gpa = vtl_control_gpa,
    .vp_assist_enabled = vp_assist_enabled,
    .load_vp_context = load_vp_context,
    .trace_vtl1_synic_once = trace_vtl1_synic_once,
    .get_vp_register = get_vp_register,
    .set_vp_register = set_vp_register,
    .build_memory_intercept = build_memory_intercept,
    .deliver_memory_intercept = deliver_memory_intercept,
    .translate_gva = translate_gva,
};

/*
 * VM and vCPU setup, reset, and the HVC immediates
 */

static bool vsm_enabled;

/* QEMU_R2Q_INJECT_INTERCEPT: arm one deliberate protected-memory fault */
static bool inject_intercept_want;
static bool inject_intercept_done;

bool hyperv_vsm_arm_enabled(void)
{
    return vsm_enabled;
}

/*
 * HvCallEnablePartitionVtl (fast, x1 and x2 the two input words),
 * HvCallEnableVpVtl and HvCallModifyVtlProtectionMask (memory, x1 the input
 * GPA) through the HVC #1 dispatcher's table (hyperv-arm.h). The other VSM
 * calls reach the core through hv_arm_vp_register_fallback() and the
 * HVC #2/#3 exits.
 */
static uint64_t hcall_enable_partition_vtl(CPUState *cs, struct kvm_run *run)
{
    CPUARMState *env = &ARM_CPU(cs)->env;

    return hyperv_hcall_vtl_enable_partition_vtl(cs, env->xregs[1],
                                                 env->xregs[2], true);
}

static uint64_t hcall_enable_vp_vtl(CPUState *cs, struct kvm_run *run)
{
    CPUARMState *env = &ARM_CPU(cs)->env;

    return hyperv_hcall_vtl_enable_vp_vtl(cs, env->xregs[1], false);
}

/*
 * x0 is the control word. The memory form carries the input GPA in x1. The
 * register-fast form has no XMM to put the GFN list in, so the whole input
 * travels in the general registers: x1 and x2 are the two-word input header
 * and the list runs from x3 up to x17, the last input register of a fast
 * hypercall. Both forms are rep calls and both return reps completed.
 */
static uint64_t hcall_modify_vtl_protection_mask(CPUState *cs,
                                                 struct kvm_run *run)
{
    CPUARMState *env = &ARM_CPU(cs)->env;
    uint64_t control = env->xregs[0];

    if (control & HV_HYPERCALL_FAST) {
        uint64_t regs[HV_ARM64_HCALL_FAST_INPUT_REGS];
        unsigned i;

        for (i = 0; i < ARRAY_SIZE(regs); i++) {
            regs[i] = env->xregs[1 + i];
        }
        return hyperv_hcall_vtl_protection_mask_regs(cs, control, regs,
                                                     ARRAY_SIZE(regs));
    }

    return hyperv_hcall_vtl_protection_mask_mem(cs, control, env->xregs[1]);
}

/* HvRegisterVsm* and the ARM64 VP registers of @vp at @vtl (hyperv-arm.h) */
uint16_t hv_arm_vp_register_fallback(bool set, uint32_t vp, int vtl,
                                     uint32_t name, uint64_t value[2])
{
    struct hv_u128 val = { .low_part = value[0], .high_part = value[1] };
    CPUState *target = hv_plane_vcpu(vp, vtl);
    bool dirty = false;
    uint16_t status;

    if (!vsm_enabled || !target || !get_vp_vsm(target)) {
        return HV_STATUS_INVALID_PARAMETER;
    }

    bql_lock();
    if (vp_start_pending(vp)) {
        bql_unlock();
        return HV_STATUS_INVALID_VP_STATE;
    }
    cpu_synchronize_state(target);
    if (set) {
        status = set_vp_register(name, &val, target, &dirty);
        if (dirty) {
            cpu_synchronize_post_reset(target);
        }
    } else {
        status = get_vp_register(name, &val, target);
        value[0] = val.low_part;
        value[1] = val.high_part;
    }
    bql_unlock();
    return status;
}

/*
 * System reset with VSM enabled: the VTLs go back to disabled, the lower
 * VTLs' protections are lifted, the planes persist and the plane layer runs
 * plane 0 again. The VSM registers of every VP return to their initial
 * values; there are no MSRs to write back on arm64.
 */
static void hyperv_vsm_arm_reset(void *opaque)
{
    CPUState *cs;
    int vtl;

    CPU_FOREACH(cs) {
        VpVsmState *vpvsm = get_vp_vsm(cs);

        if (!vpvsm) {
            continue;
        }
        vpvsm->start_pending = false;
        vpvsm->started = false;
        vpvsm->reset_gen++;
        vpvsm->msr_hv_vp_assist = 0;
        if (vpvsm->intercept_route) {
            hyperv_sint_route_cancel(vpvsm->intercept_route);
            hyperv_sint_route_unref(vpvsm->intercept_route);
            vpvsm->intercept_route = NULL;
        }
        memset(vpvsm->vtl_config, 0, sizeof(vpvsm->vtl_config));
        vina_line(cs, false);
        set_vina(cs, 0);
        vpvsm->synic_sctl = 0;
        vpvsm->synic_simp = 0;
        vpvsm->synic_siefp = 0;
        synic_sint_reset(vpvsm);
        vpvsm->intercept_pending = false;
        hyperv_synic_reset(cs);
        vpvsm->intercepts_unposted = 0;
        vpvsm->vp_config = 0;
        vpvsm->undocumented_90005 = 0;
        vpvsm->msr_hv_tsc = 0;
        vpvsm->ref_tsc_gpa = 0;
        vpvsm->synic_traced = false;
        vpvsm->vp_status.as_uint64 = 0;
        vpvsm->vp_status.enabled_vtl_set = BIT(0);
        vpvsm->vp_status.active_vtl = active_vtl(cs);
        ARM_CPU(cs)->hyperv_guest_os_id = 0;
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

    /* TLFS 15.6.3 zero_memory_on_reset */
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

int hyperv_vsm_arm_init(KVMState *s)
{
    int ret;

    if (!virt_hv_vsm()) {
        return 0;
    }
    /* on the VM fd: the dev fd answers 1 whatever the kernel supports */
    if (kvm_vm_check_extension(s, KVM_CAP_PLANES) < 2) {
        error_report("hyperv-vsm: hv-vsm=on needs a host kernel with KVM "
                     "planes (KVM_CAP_PLANES >= 2)");
        return -ENOTSUP;
    }
    /* HVC #2 and #3 exit before any SMCCC dispatch (TLFS vsm.md ARM64) */
    {
        uint64_t imm = BIT(2) | BIT(3);
        inject_intercept_want = !!getenv("QEMU_R2Q_INJECT_INTERCEPT");
        if (getenv("QEMU_R2_VSMGATE_PROBE")) {
            imm |= BIT(4) | BIT(5); /* VSM gate probe + positive control */
        }
        ret = kvm_vm_enable_cap(s, KVM_CAP_ARM_HVC_IMM_EXITS, 0, imm);
    }
    if (ret < 0) {
        error_report("hyperv-vsm: KVM_CAP_ARM_HVC_IMM_EXITS: %s",
                     strerror(-ret));
        return ret;
    }
    /*
     * No KVM_CAP_HYPERV_VSM here: that cap turns on the x86 in-kernel
     * handling of the VSM hypercalls, on arm64 every HVC #2/#3 exits to
     * QEMU and the hypercalls are dispatched from here.
     */
    ret = hv_arm_register_hcall(HVCALL_ENABLE_PARTITION_VTL,
                                hcall_enable_partition_vtl);
    if (!ret) {
        ret = hv_arm_register_hcall(HVCALL_ENABLE_VP_VTL, hcall_enable_vp_vtl);
    }
    if (!ret) {
        ret = hv_arm_register_hcall(HVCALL_MODIFY_VTL_PROTECTION_MASK,
                                    hcall_modify_vtl_protection_mask);
    }
    if (!ret) {
        ret = hv_arm_register_hcall(HVCALL_TRANSLATE_VIRTUAL_ADDRESS,
                                    hcall_translate_virtual_address);
    }
    if (ret < 0) {
        return ret;
    }
    /* layout pin: Microsoft puts dr6_shared at bit 0 (hvgdk_mini.h) */
    {
        union hv_register_vsm_capabilities pin = { .dr6_shared = 1 };
        assert(pin.as_uint64 == 1);
    }
    /* ARM64 has no DR6, and no other capability bit is implemented */
    hv_vsm.capabilities.dr6_shared = 0;
    qemu_register_reset(hyperv_vsm_arm_reset, NULL);
    vsm_enabled = true;
    return 0;
}

int hyperv_vsm_arm_init_vcpu(CPUState *cs)
{
    VpVsmState *vpvsm;
    Object *obj;

    if (!vsm_enabled) {
        return 0;
    }
    obj = object_new(TYPE_VP_VSM);
    vpvsm = VP_VSM(obj);
    vpvsm->cs = cs;
    object_property_add_child(OBJECT(cs), "vp-vsm", obj);
    object_unref(obj);
    qdev_realize(DEVICE(obj), NULL, &error_abort);
    synic_sint_reset(vpvsm);
    hyperv_synic_add(cs);
    return 0;
}

/*
 * One deliberate protected-memory fault, for the intercept path a normal
 * boot does not reach: the secure kernel hands back every page VTL0 needs,
 * so VTL0 never touches one it has lost. Only the trigger is synthetic.
 * The GPA comes out of the live protection table and everything after it is
 * the live path: kvm_hv_handle_fault(), its intercept builder, its SynIC
 * post and its VTL switch.
 *
 * It fires at a VtlReturn, the one point where VTL0 is the plane about to
 * run and VTL1 is idle, and only once VTL1 has the two things a post needs:
 * a message page, and a SINT0 that names a PPI.
 */
static bool inject_intercept_armed(CPUState *vtl1)
{
    VpVsmState *vpvsm = get_vp_vsm(vtl1);
    int intid;

    if (!inject_intercept_want || inject_intercept_done || !vpvsm) {
        return false;
    }
    if (!(vpvsm->synic_simp & HV_SIMP_ENABLE)) {
        return false;
    }
    return hv_arm_sint_action(vpvsm->synic_sint[0], true, &intid) ==
           HV_ARM_SINT_RAISE;
}

static int inject_intercept(CPUState *vtl1)
{
    CPUState *vtl0 = vtl1->kvm_plane_leader ?: vtl1;
    uint64_t gfn;

    if (!hyperv_vsm_protected_gfn(0, &gfn)) {
        error_report_once("hyperv-vsm: VP %u: VTL0 has no fully protected "
                          "page to fault on", hyperv_vp_index(vtl0));
        return 0;
    }
    inject_intercept_done = true;
    trace_hyperv_vsm_arm_inject_intercept(hyperv_vp_index(vtl0),
                                          gfn << HV_HYP_PAGE_SHIFT);
    inject_intercept_active = true;
    return kvm_hv_handle_fault(vtl0, gfn << HV_HYP_PAGE_SHIFT,
                               HV_HYP_PAGE_SIZE, KVM_MEMORY_EXIT_FLAG_WRITE);
}

int hyperv_vsm_arm_handle_hvc_imm(CPUState *cs, struct kvm_run *run)
{
    uint64_t status = HV_STATUS_INVALID_HYPERCALL_CODE;
    int ret = 0;

    switch (run->hypercall.nr) {
    case 2:
        ret = hyperv_hcall_vtl_call(cs, &status);
        break;
    case 3:
        ret = hyperv_hcall_vtl_return(cs, &status);
        break;
    default:
        qemu_log_mask(LOG_UNIMP, "hyperv-vsm: HVC #%" PRIu64 " exit on VP %u "
                      "VTL%d has no handler\n", (uint64_t)run->hypercall.nr,
                      hyperv_vp_index(cs), cs->kvm_plane);
        break;
    }
    trace_hyperv_vsm_arm_hvc_imm(hyperv_vp_index(cs), cs->kvm_plane,
                                 (uint64_t)run->hypercall.nr, status, ret);
    {
        /* R4 diag (env R4_SC_TRACE=1): VP0 VTL0->VTL1 calls. Print the VTL0
         * registers and dump 0x30 bytes behind each callee-saved candidate
         * so the NT secure-call block (type=2, call#) can be located. */
        static int r4_sc_trace = -1;
        if (r4_sc_trace < 0) {
            r4_sc_trace = getenv("R4_SC_TRACE") ? 1 : 0;
        }
        static uint64_t r4_last_blk;
        if (r4_sc_trace && hyperv_vp_index(cs) == 0 &&
            status == HV_STATUS_SUCCESS && run->hypercall.nr == 3 &&
            cs->kvm_plane == 1 && r4_last_blk) {
            CPUState *v0 = hv_plane_vcpu(0, 0);
            uint8_t b[0x30];
            int i;
            if (v0 && !cpu_memory_rw_debug(v0, r4_last_blk, b, sizeof(b), false)) {
                fprintf(stderr, "R4SC3 ret blk=0x%" PRIx64 ":", r4_last_blk);
                for (i = 0; i < 0x30; i++) {
                    fprintf(stderr, "%s%02x", (i % 8) ? "" : " ", b[i]);
                }
                fprintf(stderr, "\n");
            }
        }
        if (r4_sc_trace && hyperv_vp_index(cs) == 0 &&
            status == HV_STATUS_SUCCESS && run->hypercall.nr == 2 &&
            cs->kvm_plane == 0) {
            CPUARMState *env = &ARM_CPU(cs)->env;
            static const int regs[] = { 0, 1, 2, 3, 18, 19, 20, 21, 22, 29 };
            int k;
            cpu_synchronize_state(cs);
            r4_last_blk = env->xregs[3];
            fprintf(stderr, "R4SC2 sp=0x%" PRIx64 " pc=0x%" PRIx64,
                    env->xregs[31], env->pc);
            for (k = 0; k < (int)ARRAY_SIZE(regs); k++) {
                fprintf(stderr, " x%d=0x%" PRIx64, regs[k], env->xregs[regs[k]]);
            }
            fprintf(stderr, "\n");
            for (k = 0; k < (int)ARRAY_SIZE(regs); k++) {
                uint64_t a = env->xregs[regs[k]];
                uint8_t b[0x20];
                int i;
                if (a < 0xffff000000000000ULL || regs[k] == 18 || regs[k] == 29) {
                    continue;
                }
                if (cpu_memory_rw_debug(cs, a, b, sizeof(b), false)) {
                    continue;
                }
                fprintf(stderr, "R4SC2  [x%d]:", regs[k]);
                for (i = 0; i < 0x20; i++) {
                    fprintf(stderr, "%s%02x", (i % 8) ? "" : " ", b[i]);
                }
                fprintf(stderr, "\n");
            }
        }
    }
    /* a refused switch: the kernel injects an undefined instruction */
    run->hypercall.ret = status == HV_STATUS_SUCCESS ? 0 : 1;

    if (run->hypercall.nr == 3 && status == HV_STATUS_SUCCESS &&
        inject_intercept_armed(cs)) {
        ret = inject_intercept(cs);
    }
    return ret;
}

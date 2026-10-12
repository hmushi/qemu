/*
 * ARM implementation of KVM hooks
 *
 * Copyright Christoffer Dall 2009-2010
 * Copyright Mian-M. Hamayun 2013, Virtual Open Systems
 * Copyright Alex Bennée 2014, Linaro
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include <sys/ioctl.h>

#include <linux/kvm.h>

#include "qemu/timer.h"
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "qom/object.h"
#include "qapi/error.h"
#include "system/system.h"
#include "system/runstate.h"
#include "hw/hyperv/hyperv.h"
#include "system/hw_accel.h"
#include "hw/core/cpu.h"
#include "system/ramblock.h"
#include "system/kvm.h"
#include "system/kvm_int.h"
#include "kvm_arm.h"
#include "cpu.h"
#include "cpu-sysregs.h"
#include "trace.h"
#include "internals.h"
#include "hw/pci/pci.h"
#include "exec/memattrs.h"
#include "system/address-spaces.h"
#include "gdbstub/enums.h"
#include "hw/core/boards.h"
#include "hw/core/irq.h"
#include "qapi/visitor.h"
#include "qemu/log.h"
#include "hw/acpi/acpi.h"
#include "hw/acpi/ghes.h"
#include "target/arm/gtimer.h"
#include "migration/blocker.h"
#include "hw/hyperv/vsm-plane-api.h"
#include "hw/hyperv/vsm-core.h"
#include "hw/hyperv/hyperv-vsm-arm.h"
#include "hyperv-vsm.h"
#include "hyperv-arm.h"
#include "hw/arm/virt.h"

const KVMCapabilityInfo kvm_arch_required_capabilities[] = {
    KVM_CAP_INFO(DEVICE_CTRL),
    KVM_CAP_LAST_INFO
};

static bool cap_has_mp_state;
static bool cap_has_inject_serror_esr;
static bool cap_has_inject_ext_dabt;

/**
 * ARMHostCPUFeatures: information about the host CPU (identified
 * by asking the host kernel)
 */
typedef struct ARMHostCPUFeatures {
    ARMISARegisters isar;
    uint64_t features;
    uint32_t target;
    uint32_t sve_vq_supported;
    const char *dtb_compatible;
} ARMHostCPUFeatures;

static ARMHostCPUFeatures arm_host_cpu_features;

/**
 * kvm_arm_vcpu_init:
 * @cpu: ARMCPU
 *
 * Initialize (or reinitialize) the VCPU by invoking the
 * KVM_ARM_VCPU_INIT ioctl with the CPU type and feature
 * bitmask specified in the CPUState.
 *
 * Returns: 0 if success else < 0 error code
 */
static int kvm_arm_vcpu_init(ARMCPU *cpu)
{
    struct kvm_vcpu_init init;

    init.target = cpu->kvm_target;
    memcpy(init.features, cpu->kvm_init_features, sizeof(init.features));

    return kvm_vcpu_ioctl(CPU(cpu), KVM_ARM_VCPU_INIT, &init);
}

/**
 * kvm_arm_vcpu_finalize:
 * @cpu: ARMCPU
 * @feature: feature to finalize
 *
 * Finalizes the configuration of the specified VCPU feature by
 * invoking the KVM_ARM_VCPU_FINALIZE ioctl. Features requiring
 * this are documented in the "KVM_ARM_VCPU_FINALIZE" section of
 * KVM's API documentation.
 *
 * Returns: 0 if success else < 0 error code
 */
static int kvm_arm_vcpu_finalize(ARMCPU *cpu, int feature)
{
    return kvm_vcpu_ioctl(CPU(cpu), KVM_ARM_VCPU_FINALIZE, &feature);
}

bool kvm_arm_create_scratch_host_vcpu(int *fdarray,
                                      struct kvm_vcpu_init *init)
{
    int ret = 0, kvmfd = -1, vmfd = -1, cpufd = -1;
    int max_vm_pa_size;

    kvmfd = qemu_open_old("/dev/kvm", O_RDWR);
    if (kvmfd < 0) {
        goto err;
    }
    max_vm_pa_size = ioctl(kvmfd, KVM_CHECK_EXTENSION, KVM_CAP_ARM_VM_IPA_SIZE);
    if (max_vm_pa_size < 0) {
        max_vm_pa_size = 0;
    }
    do {
        vmfd = ioctl(kvmfd, KVM_CREATE_VM, max_vm_pa_size);
    } while (vmfd == -1 && errno == EINTR);
    if (vmfd < 0) {
        goto err;
    }

    /*
     * The MTE capability must be enabled by the VMM before creating
     * any VCPUs in order to allow the MTE bits of the ID_AA64PFR1
     * register to be probed correctly, as they are masked if MTE
     * is not enabled.
     */
    if (kvm_arm_mte_supported()) {
        KVMState kvm_state;

        kvm_state.fd = kvmfd;
        kvm_state.vmfd = vmfd;
        kvm_vm_enable_cap(&kvm_state, KVM_CAP_ARM_MTE, 0);
    }

    cpufd = ioctl(vmfd, KVM_CREATE_VCPU, 0);
    if (cpufd < 0) {
        goto err;
    }

    if (!init) {
        /* Caller doesn't want the VCPU to be initialized, so skip it */
        goto finish;
    }

    if (init->target == -1) {
        struct kvm_vcpu_init preferred;

        ret = ioctl(vmfd, KVM_ARM_PREFERRED_TARGET, &preferred);
        if (ret < 0) {
            goto err;
        }
        init->target = preferred.target;
    }
    ret = ioctl(cpufd, KVM_ARM_VCPU_INIT, init);
    if (ret < 0) {
        goto err;
    }

finish:
    fdarray[0] = kvmfd;
    fdarray[1] = vmfd;
    fdarray[2] = cpufd;

    return true;

err:
    if (cpufd >= 0) {
        close(cpufd);
    }
    if (vmfd >= 0) {
        close(vmfd);
    }
    if (kvmfd >= 0) {
        close(kvmfd);
    }

    return false;
}

void kvm_arm_destroy_scratch_host_vcpu(int *fdarray)
{
    int i;

    for (i = 2; i >= 0; i--) {
        close(fdarray[i]);
    }
}

static int read_sys_reg32(int fd, uint32_t *pret, uint64_t id)
{
    uint64_t ret;
    struct kvm_one_reg idreg = { .id = id, .addr = (uintptr_t)&ret };
    int err;

    assert((id & KVM_REG_SIZE_MASK) == KVM_REG_SIZE_U64);
    err = ioctl(fd, KVM_GET_ONE_REG, &idreg);
    if (err < 0) {
        return -1;
    }
    *pret = ret;
    return 0;
}

static int read_sys_reg64(int fd, uint64_t *pret, uint64_t id)
{
    struct kvm_one_reg idreg = { .id = id, .addr = (uintptr_t)pret };

    assert((id & KVM_REG_SIZE_MASK) == KVM_REG_SIZE_U64);
    return ioctl(fd, KVM_GET_ONE_REG, &idreg);
}

static bool kvm_arm_pauth_supported(void)
{
    return (kvm_check_extension(kvm_state, KVM_CAP_ARM_PTRAUTH_ADDRESS) &&
            kvm_check_extension(kvm_state, KVM_CAP_ARM_PTRAUTH_GENERIC));
}


static uint64_t idregs_sysreg_to_kvm_reg(ARMSysRegs sysreg)
{
    return ARM64_SYS_REG((sysreg & CP_REG_ARM64_SYSREG_OP0_MASK) >> CP_REG_ARM64_SYSREG_OP0_SHIFT,
                         (sysreg & CP_REG_ARM64_SYSREG_OP1_MASK) >> CP_REG_ARM64_SYSREG_OP1_SHIFT,
                         (sysreg & CP_REG_ARM64_SYSREG_CRN_MASK) >> CP_REG_ARM64_SYSREG_CRN_SHIFT,
                         (sysreg & CP_REG_ARM64_SYSREG_CRM_MASK) >> CP_REG_ARM64_SYSREG_CRM_SHIFT,
                         (sysreg & CP_REG_ARM64_SYSREG_OP2_MASK) >> CP_REG_ARM64_SYSREG_OP2_SHIFT);
}

/* read a sysreg value and store it in the idregs */
static int get_host_cpu_reg(int fd, ARMHostCPUFeatures *ahcf,
                            ARMIDRegisterIdx index)
{
    uint64_t *reg;
    int ret;

    reg = &ahcf->isar.idregs[index];
    ret = read_sys_reg64(fd, reg,
                         idregs_sysreg_to_kvm_reg(id_register_sysreg[index]));
    return ret;
}


/* CSSELR values supported by kvm; used to index KVM_REG_ARM_DEMUX_ID_CCSIDR */
#define KVM_CSSELR_MAX 14
/*
 * QEMU historically supported CSSELR values 0..15. This difference
 * doen't matter since CSSELR_EL1.Level == 0b111 is reserved and thus
 * CSSELR values 14..15 will make CCSIDR read as zero. Larger CSSELR
 * values will only be necessary when support for MTE Allocation Tag
 * caches is added.
 */
#define QEMU_CSSELR_MAX 16

static int get_host_cpu_reg_demux(int fd, ARMHostCPUFeatures *ahcf,
                                  ARMIDRegisterIdx index, int subindex)
{

    struct kvm_one_reg one_reg = {
        .id = KVM_REG_ARM64 | KVM_REG_SIZE_U32 | KVM_REG_ARM_DEMUX,
    };

    switch (index) {
    case CCSIDR_EL1_IDX:
        if (subindex >= QEMU_CSSELR_MAX) {
            return -EINVAL;
        } else if (subindex >= KVM_CSSELR_MAX) {
            /* CSSELR_EL1.Level == 0b111 is reserved. */
            ahcf->isar.idregs[index + subindex] = 0;
            return 0;
        }
        one_reg.id |= KVM_REG_ARM_DEMUX_ID_CCSIDR | subindex;
        one_reg.addr = (uintptr_t)&ahcf->isar.idregs[index + subindex];
        break;
    default:
        return -EINVAL;
    }

    return ioctl(fd, KVM_GET_ONE_REG, &one_reg);
}

static uint32_t kvm_arm_sve_get_vls(int fd)
{
    uint64_t vls[KVM_ARM64_SVE_VLS_WORDS];
    struct kvm_one_reg reg = {
        .id = KVM_REG_ARM64_SVE_VLS,
        .addr = (uint64_t)&vls[0],
    };
    uint32_t vq = 0;
    int ret;

    ret = ioctl(fd, KVM_GET_ONE_REG, &reg);
    if (ret) {
        error_report("failed to get KVM_REG_ARM64_SVE_VLS: %s",
                     strerror(errno));
        abort();
    }

    for (int i = KVM_ARM64_SVE_VLS_WORDS - 1; i >= 0; --i) {
        if (vls[i]) {
            vq = 64 - clz64(vls[i]) + i * 64;
            break;
        }
    }
    if (vq > ARM_MAX_VQ) {
        warn_report("KVM supports vector lengths larger than QEMU can enable");
    }
    return vls[0] & MAKE_64BIT_MASK(0, ARM_MAX_VQ);
}

static void kvm_arm_get_host_cpu_features(ARMHostCPUFeatures *ahcf)
{
    /* Identify the feature bits corresponding to the host CPU, and
     * fill out the ARMHostCPUClass fields accordingly. To do this
     * we have to create a scratch VM, create a single CPU inside it,
     * and then query that CPU for the relevant ID registers.
     */
    int fdarray[3];
    bool sve_supported;
    bool el2_supported;
    bool pmu_supported = false;
    uint64_t features = 0;
    int err;

    ahcf->target = QEMU_KVM_ARM_TARGET_NONE;
    ahcf->dtb_compatible = "arm,armv8";

    if (!kvm_enabled()) {
        return;
    }

    /*
     * target = -1 informs kvm_arm_create_scratch_host_vcpu()
     * to use the preferred target
     */
    struct kvm_vcpu_init init = { .target = -1, };

    /*
     * Ask for SVE if supported, so that we can query ID_AA64ZFR0,
     * which is otherwise RAZ.
     */
    sve_supported = kvm_check_extension(kvm_state, KVM_CAP_ARM_SVE);
    if (sve_supported) {
        init.features[0] |= 1 << KVM_ARM_VCPU_SVE;
    }

    /*
     * Ask for EL2 if supported.
     */
    el2_supported = kvm_arm_el2_supported();
    if (el2_supported) {
        init.features[0] |= 1 << KVM_ARM_VCPU_HAS_EL2;
    }

    /*
     * Ask for Pointer Authentication if supported, so that we get
     * the unsanitized field values for AA64ISAR1_EL1.
     */
    if (kvm_arm_pauth_supported()) {
        init.features[0] |= (1 << KVM_ARM_VCPU_PTRAUTH_ADDRESS |
                             1 << KVM_ARM_VCPU_PTRAUTH_GENERIC);
    }

    if (kvm_check_extension(kvm_state, KVM_CAP_ARM_PMU_V3)) {
        init.features[0] |= 1 << KVM_ARM_VCPU_PMU_V3;
        pmu_supported = true;
        features |= 1ULL << ARM_FEATURE_PMU;
    }

    if (!kvm_arm_create_scratch_host_vcpu(fdarray, &init)) {
        return;
    }

    int fd = fdarray[2];

    err = get_host_cpu_reg(fd, ahcf, ID_AA64PFR0_EL1_IDX);
    if (unlikely(err < 0)) {
        /*
         * Before v4.15, the kernel only exposed a limited number of system
         * registers, not including any of the interesting AArch64 ID regs.
         * For the most part we could leave these fields as zero with minimal
         * effect, since this does not affect the values seen by the guest.
         *
         * However, it could cause problems down the line for QEMU,
         * so provide a minimal v8.0 default.
         *
         * ??? Could read MIDR and use knowledge from cpu64.c.
         * ??? Could map a page of memory into our temp guest and
         *     run the tiniest of hand-crafted kernels to extract
         *     the values seen by the guest.
         * ??? Either of these sounds like too much effort just
         *     to work around running a modern host kernel.
         */
        SET_IDREG(&ahcf->isar, ID_AA64PFR0, 0x00000011); /* EL1&0, AArch64 only */
        err = 0;
    } else {
        err |= get_host_cpu_reg(fd, ahcf, ID_AA64PFR1_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_AA64PFR2_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_AA64SMFR0_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_AA64DFR0_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_AA64DFR1_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_AA64ISAR0_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_AA64ISAR1_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_AA64ISAR2_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_AA64MMFR0_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_AA64MMFR1_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_AA64MMFR2_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_AA64MMFR3_EL1_IDX);

        /*
         * Note that if AArch32 support is not present in the host,
         * the AArch32 sysregs are present to be read, but will
         * return UNKNOWN values.  This is neither better nor worse
         * than skipping the reads and leaving 0, as we must avoid
         * considering the values in every case.
         */
        err |= get_host_cpu_reg(fd, ahcf, ID_PFR0_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_PFR1_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_DFR0_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_MMFR0_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_MMFR1_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_MMFR2_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_MMFR3_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_ISAR0_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_ISAR1_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_ISAR2_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_ISAR3_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_ISAR4_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_ISAR5_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_ISAR6_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_MMFR4_EL1_IDX);

        err |= read_sys_reg32(fd, &ahcf->isar.mvfr0,
                              ARM64_SYS_REG(3, 0, 0, 3, 0));
        err |= read_sys_reg32(fd, &ahcf->isar.mvfr1,
                              ARM64_SYS_REG(3, 0, 0, 3, 1));
        err |= read_sys_reg32(fd, &ahcf->isar.mvfr2,
                              ARM64_SYS_REG(3, 0, 0, 3, 2));
        err |= get_host_cpu_reg(fd, ahcf, ID_PFR2_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_DFR1_EL1_IDX);
        err |= get_host_cpu_reg(fd, ahcf, ID_MMFR5_EL1_IDX);

        /*
         * DBGDIDR is a bit complicated because the kernel doesn't
         * provide an accessor for it in 64-bit mode, which is what this
         * scratch VM is in, and there's no architected "64-bit sysreg
         * which reads the same as the 32-bit register" the way there is
         * for other ID registers. Instead we synthesize a value from the
         * AArch64 ID_AA64DFR0, the same way the kernel code in
         * arch/arm64/kvm/sys_regs.c:trap_dbgidr() does.
         * We only do this if the CPU supports AArch32 at EL1.
         */
        if (FIELD_EX32_IDREG(&ahcf->isar, ID_AA64PFR0, EL1) >= 2) {
            int wrps = FIELD_EX64_IDREG(&ahcf->isar, ID_AA64DFR0, WRPS);
            int brps = FIELD_EX64_IDREG(&ahcf->isar, ID_AA64DFR0, BRPS);
            int ctx_cmps =
                FIELD_EX64_IDREG(&ahcf->isar, ID_AA64DFR0, CTX_CMPS);
            int version = 6; /* ARMv8 debug architecture */
            bool has_el3 =
                !!FIELD_EX32_IDREG(&ahcf->isar, ID_AA64PFR0, EL3);
            uint32_t dbgdidr = 0;

            dbgdidr = FIELD_DP32(dbgdidr, DBGDIDR, WRPS, wrps);
            dbgdidr = FIELD_DP32(dbgdidr, DBGDIDR, BRPS, brps);
            dbgdidr = FIELD_DP32(dbgdidr, DBGDIDR, CTX_CMPS, ctx_cmps);
            dbgdidr = FIELD_DP32(dbgdidr, DBGDIDR, VERSION, version);
            dbgdidr = FIELD_DP32(dbgdidr, DBGDIDR, NSUHD_IMP, has_el3);
            dbgdidr = FIELD_DP32(dbgdidr, DBGDIDR, SE_IMP, has_el3);
            dbgdidr |= (1 << 15); /* RES1 bit */
            ahcf->isar.dbgdidr = dbgdidr;
        }

        if (pmu_supported) {
            /* PMCR_EL0 is only accessible if the vCPU has feature PMU_V3 */
            err |= read_sys_reg64(fd, &ahcf->isar.reset_pmcr_el0,
                                  ARM64_SYS_REG(3, 3, 9, 12, 0));
        }

        if (sve_supported) {
            /*
             * There is a range of kernels between kernel commit 73433762fcae
             * and f81cb2c3ad41 which have a bug where the kernel doesn't
             * expose SYS_ID_AA64ZFR0_EL1 via the ONE_REG API unless the VM has
             * enabled SVE support, which resulted in an error rather than RAZ.
             * So only read the register if we set KVM_ARM_VCPU_SVE above.
             */
            err |= get_host_cpu_reg(fd, ahcf, ID_AA64ZFR0_EL1_IDX);

            /* Read the set of supported vector lengths. */
            arm_host_cpu_features.sve_vq_supported = kvm_arm_sve_get_vls(fd);
        }
        /* Grab demuxed registers. */
        for (int i = 0; i < QEMU_CSSELR_MAX; i++) {
            err |= get_host_cpu_reg_demux(fd, ahcf, CCSIDR_EL1_IDX, i);
        }
    }

    kvm_arm_destroy_scratch_host_vcpu(fdarray);

    if (err < 0) {
        return;
    }

    /*
     * We can assume any KVM supporting CPU is at least a v8
     * with VFPv4+Neon; this in turn implies most of the other
     * feature bits.
     */
    features |= 1ULL << ARM_FEATURE_V8;
    features |= 1ULL << ARM_FEATURE_NEON;
    features |= 1ULL << ARM_FEATURE_AARCH64;
    features |= 1ULL << ARM_FEATURE_GENERIC_TIMER;

    if (el2_supported) {
        features |= 1ULL << ARM_FEATURE_EL2;
    }

    ahcf->target = init.target;
    ahcf->features = features;
}

void kvm_arm_set_cpu_features_from_host(ARMCPU *cpu)
{
    CPUARMState *env = &cpu->env;

    if (!arm_host_cpu_features.dtb_compatible) {
        kvm_arm_get_host_cpu_features(&arm_host_cpu_features);
    }

    cpu->kvm_target = arm_host_cpu_features.target;

    if (cpu->kvm_target == QEMU_KVM_ARM_TARGET_NONE) {
        /*
         * We can't report this error yet, so flag that we need to
         * in arm_cpu_realizefn().
         */
        cpu->host_cpu_probe_failed = true;
        return;
    }

    cpu->dtb_compatible = arm_host_cpu_features.dtb_compatible;
    cpu->isar = arm_host_cpu_features.isar;
    cpu->sve_vq.supported = arm_host_cpu_features.sve_vq_supported;
    env->features = arm_host_cpu_features.features;
}

static bool kvm_no_adjvtime_get(Object *obj, Error **errp)
{
    return !ARM_CPU(obj)->kvm_adjvtime;
}

static void kvm_no_adjvtime_set(Object *obj, bool value, Error **errp)
{
    ARM_CPU(obj)->kvm_adjvtime = !value;
}

static bool kvm_steal_time_get(Object *obj, Error **errp)
{
    return ARM_CPU(obj)->kvm_steal_time != ON_OFF_AUTO_OFF;
}

static void kvm_steal_time_set(Object *obj, bool value, Error **errp)
{
    ARM_CPU(obj)->kvm_steal_time = value ? ON_OFF_AUTO_ON : ON_OFF_AUTO_OFF;
}

static char *kvm_get_psci_version(Object *obj, Error **errp)
{
    ARMCPU *cpu = ARM_CPU(obj);

    return g_strdup_printf("%d.%d",
                           (int) PSCI_VERSION_MAJOR(cpu->psci_version),
                           (int) PSCI_VERSION_MINOR(cpu->psci_version));
}

static void kvm_set_psci_version(Object *obj, const char *value, Error **errp)
{
    ARMCPU *cpu = ARM_CPU(obj);
    uint16_t maj, min;

    if (sscanf(value, "%hu.%hu", &maj, &min) != 2) {
        error_setg(errp, "Invalid PSCI version.");
        return;
    }

    cpu->psci_version = PSCI_VERSION(maj, min);
}

/* KVM VCPU properties should be prefixed with "kvm-". */
void kvm_arm_add_vcpu_properties(ARMCPU *cpu)
{
    CPUARMState *env = &cpu->env;
    Object *obj = OBJECT(cpu);

    if (arm_feature(env, ARM_FEATURE_GENERIC_TIMER)) {
        cpu->kvm_adjvtime = true;
        object_property_add_bool(obj, "kvm-no-adjvtime", kvm_no_adjvtime_get,
                                 kvm_no_adjvtime_set);
        object_property_set_description(obj, "kvm-no-adjvtime",
                                        "Set on to disable the adjustment of "
                                        "the virtual counter. VM stopped time "
                                        "will be counted.");
    }

    cpu->kvm_steal_time = ON_OFF_AUTO_AUTO;
    object_property_add_bool(obj, "kvm-steal-time", kvm_steal_time_get,
                             kvm_steal_time_set);
    object_property_set_description(obj, "kvm-steal-time",
                                    "Set off to disable KVM steal time.");

    object_property_add_str(obj, "kvm-psci-version", kvm_get_psci_version,
                            kvm_set_psci_version);
    object_property_set_description(obj, "kvm-psci-version",
                                    "Set PSCI version. "
                                    "Valid values are 0.1, 0.2, 1.0, 1.1, 1.2, 1.3");
}

int kvm_arm_get_max_vm_ipa_size(MachineState *ms, bool *fixed_ipa)
{
    KVMState *s = KVM_STATE(ms->accelerator);
    int ret;

    ret = kvm_check_extension(s, KVM_CAP_ARM_VM_IPA_SIZE);
    *fixed_ipa = ret <= 0;

    return ret > 0 ? ret : 40;
}

int kvm_arch_get_default_type(MachineState *ms)
{
    bool fixed_ipa;
    int size = kvm_arm_get_max_vm_ipa_size(ms, &fixed_ipa);
    return fixed_ipa ? 0 : size;
}

int kvm_arch_init(MachineState *ms, KVMState *s)
{
    int ret;
    /* For ARM interrupt delivery is always asynchronous,
     * whether we are using an in-kernel VGIC or not.
     */
    kvm_async_interrupts_allowed = true;

    /*
     * PSCI wakes up secondary cores, so we always need to
     * have vCPUs waiting in kernel space
     */
    kvm_halt_in_kernel_allowed = true;

    cap_has_mp_state = kvm_check_extension(s, KVM_CAP_MP_STATE);

    /* Check whether user space can specify guest syndrome value */
    cap_has_inject_serror_esr =
        kvm_check_extension(s, KVM_CAP_ARM_INJECT_SERROR_ESR);

    if (ms->smp.cpus > 256 &&
        !kvm_check_extension(s, KVM_CAP_ARM_IRQ_LINE_LAYOUT_2)) {
        error_report("Using more than 256 vcpus requires a host kernel "
                     "with KVM_CAP_ARM_IRQ_LINE_LAYOUT_2");
        return -EINVAL;
    }

    /* Hyper-V VSM on KVM planes: the HVC #2/#3 exits, before any vCPU runs */
    ret = hyperv_vsm_arm_init(s);
    if (ret < 0) {
        return ret;
    }

    if (kvm_check_extension(s, KVM_CAP_ARM_NISV_TO_USER)) {
        if (kvm_vm_enable_cap(s, KVM_CAP_ARM_NISV_TO_USER, 0)) {
            error_report("Failed to enable KVM_CAP_ARM_NISV_TO_USER cap");
        } else {
            /* Set status for supporting the external dabt injection */
            cap_has_inject_ext_dabt = kvm_check_extension(s,
                                    KVM_CAP_ARM_INJECT_EXT_DABT);
        }
    }

    if (s->kvm_eager_split_size) {
        uint32_t sizes;

        sizes = kvm_vm_check_extension(s, KVM_CAP_ARM_SUPPORTED_BLOCK_SIZES);
        if (!sizes) {
            s->kvm_eager_split_size = 0;
            warn_report("Eager Page Split support not available");
        } else if (!(s->kvm_eager_split_size & sizes)) {
            error_report("Eager Page Split requested chunk size not valid");
            return -EINVAL;
        } else {
            ret = kvm_vm_enable_cap(s, KVM_CAP_ARM_EAGER_SPLIT_CHUNK_SIZE, 0,
                                    s->kvm_eager_split_size);
            if (ret < 0) {
                error_report("Enabling of Eager Page Split failed: %s",
                             strerror(-ret));
                return ret;
            }
        }
    }

    max_hw_wps = kvm_check_extension(s, KVM_CAP_GUEST_DEBUG_HW_WPS);
    hw_watchpoints = g_array_sized_new(true, true,
                                       sizeof(HWWatchpoint), max_hw_wps);

    max_hw_bps = kvm_check_extension(s, KVM_CAP_GUEST_DEBUG_HW_BPS);
    hw_breakpoints = g_array_sized_new(true, true,
                                       sizeof(HWBreakpoint), max_hw_bps);

    /*
     * The virt machine names Hyper-V in the FADT, so a Windows guest issues
     * Hyper-V hypercalls as HVC #1 with the TLFS control word in x0. KVM
     * dispatches on x0's low 32 bits, so forward the Hyper-V code range to
     * userspace. The range stops below the PSCI owner, which the filter does
     * not reserve. It must be set before any vCPU runs or KVM returns -EBUSY.
     */
    {
        struct kvm_smccc_filter f = {
            .base = 0x0,
            .nr_functions = 0x20000,
            .action = KVM_SMCCC_FILTER_FWD_TO_USER,
        };
        struct kvm_device_attr attr = {
            .group = KVM_ARM_VM_SMCCC_CTRL,
            .attr = KVM_ARM_VM_SMCCC_FILTER,
            .addr = (uint64_t)(uintptr_t)&f,
        };

        ret = kvm_vm_ioctl(s, KVM_SET_DEVICE_ATTR, &attr);
        if (ret < 0) {
            error_report("Hyper-V SMCCC filter not installed: %s",
                         strerror(-ret));
        } else {
            fprintf(stderr, "r1_hv_hcall: filter installed 0x0+0x20000 "
                    "FWD_TO_USER\n");
        }
    }

    return 0;
}

unsigned long kvm_arch_vcpu_id(CPUState *cpu)
{
    return cpu->cpu_index;
}

/* We track all the KVM devices which need their memory addresses
 * passing to the kernel in a list of these structures.
 * When board init is complete we run through the list and
 * tell the kernel the base addresses of the memory regions.
 * We use a MemoryListener to track mapping and unmapping of
 * the regions during board creation, so the board models don't
 * need to do anything special for the KVM case.
 *
 * Sometimes the address must be OR'ed with some other fields
 * (for example for KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION).
 * @kda_addr_ormask aims at storing the value of those fields.
 */
typedef struct KVMDevice {
    struct kvm_arm_device_addr kda;
    struct kvm_device_attr kdattr;
    uint64_t kda_addr_ormask;
    MemoryRegion *mr;
    QSLIST_ENTRY(KVMDevice) entries;
    int dev_fd;
} KVMDevice;

static QSLIST_HEAD(, KVMDevice) kvm_devices_head;

static void kvm_arm_devlistener_add(MemoryListener *listener,
                                    MemoryRegionSection *section)
{
    KVMDevice *kd;

    QSLIST_FOREACH(kd, &kvm_devices_head, entries) {
        if (section->mr == kd->mr) {
            kd->kda.addr = section->offset_within_address_space;
        }
    }
}

static void kvm_arm_devlistener_del(MemoryListener *listener,
                                    MemoryRegionSection *section)
{
    KVMDevice *kd;

    QSLIST_FOREACH(kd, &kvm_devices_head, entries) {
        if (section->mr == kd->mr) {
            kd->kda.addr = -1;
        }
    }
}

static MemoryListener devlistener = {
    .name = "kvm-arm",
    .region_add = kvm_arm_devlistener_add,
    .region_del = kvm_arm_devlistener_del,
    .priority = MEMORY_LISTENER_PRIORITY_MIN,
};

static void kvm_arm_set_device_addr(KVMDevice *kd)
{
    struct kvm_device_attr *attr = &kd->kdattr;
    int ret;
    uint64_t addr = kd->kda.addr;

    addr |= kd->kda_addr_ormask;
    attr->addr = (uintptr_t)&addr;
    ret = kvm_device_ioctl(kd->dev_fd, KVM_SET_DEVICE_ATTR, attr);

    if (ret < 0) {
        fprintf(stderr, "Failed to set device address: %s\n",
                strerror(-ret));
        abort();
    }
}

static void kvm_arm_machine_init_done(Notifier *notifier, void *data)
{
    KVMDevice *kd, *tkd;

    QSLIST_FOREACH_SAFE(kd, &kvm_devices_head, entries, tkd) {
        if (kd->kda.addr != -1) {
            kvm_arm_set_device_addr(kd);
        }
        memory_region_unref(kd->mr);
        QSLIST_REMOVE_HEAD(&kvm_devices_head, entries);
        g_free(kd);
    }
    memory_listener_unregister(&devlistener);
}

static Notifier notify = {
    .notify = kvm_arm_machine_init_done,
};

void kvm_arm_register_device(MemoryRegion *mr, uint64_t devid, uint64_t group,
                             uint64_t attr, int dev_fd, uint64_t addr_ormask)
{
    KVMDevice *kd;

    if (!kvm_irqchip_in_kernel()) {
        return;
    }

    if (QSLIST_EMPTY(&kvm_devices_head)) {
        memory_listener_register(&devlistener, &address_space_memory);
        qemu_add_machine_init_done_notifier(&notify);
    }
    kd = g_new0(KVMDevice, 1);
    kd->mr = mr;
    kd->kda.id = devid;
    kd->kda.addr = -1;
    kd->kdattr.flags = 0;
    kd->kdattr.group = group;
    kd->kdattr.attr = attr;
    kd->dev_fd = dev_fd;
    kd->kda_addr_ormask = addr_ormask;
    QSLIST_INSERT_HEAD(&kvm_devices_head, kd, entries);
    memory_region_ref(kd->mr);
}

/*
 * cpreg_values are sorted in ascending order by KVM register ID
 * (see kvm_arm_init_cpreg_list). This allows us to cheaply find
 * the storage for a KVM register by ID with a binary search.
 */
static uint64_t *kvm_arm_get_cpreg_ptr(ARMCPU *cpu, uint64_t regidx)
{
    uint64_t *res;

    res = bsearch(&regidx, cpu->cpreg_indexes, cpu->cpreg_array_len,
                  sizeof(uint64_t), compare_u64);
    assert(res);

    return &cpu->cpreg_values[res - cpu->cpreg_indexes];
}

/**
 * kvm_arm_reg_syncs_via_cpreg_list:
 * @regidx: KVM register index
 *
 * Return true if this KVM register should be synchronized via the
 * cpreg list of arbitrary system registers, false if it is synchronized
 * by hand using code in kvm_arch_get/put_registers().
 */
static bool kvm_arm_reg_syncs_via_cpreg_list(uint64_t regidx)
{
    switch (regidx & KVM_REG_ARM_COPROC_MASK) {
    case KVM_REG_ARM_CORE:
    case KVM_REG_ARM64_SVE:
        return false;
    default:
        return true;
    }
}

/**
 * kvm_arm_init_cpreg_list:
 * @cpu: ARMCPU
 *
 * Initialize the ARMCPU cpreg list according to the kernel's
 * definition of what CPU registers it knows about (and throw away
 * the previous TCG-created cpreg list).
 *
 * Returns: 0 if success, else < 0 error code
 */
static int kvm_arm_init_cpreg_list(ARMCPU *cpu)
{
    struct kvm_reg_list rl;
    struct kvm_reg_list *rlp;
    int i, ret, arraylen;
    CPUState *cs = CPU(cpu);

    rl.n = 0;
    ret = kvm_vcpu_ioctl(cs, KVM_GET_REG_LIST, &rl);
    if (ret != -E2BIG) {
        return ret;
    }
    rlp = g_malloc(sizeof(struct kvm_reg_list) + rl.n * sizeof(uint64_t));
    rlp->n = rl.n;
    ret = kvm_vcpu_ioctl(cs, KVM_GET_REG_LIST, rlp);
    if (ret) {
        goto out;
    }
    /* Sort the list we get back from the kernel, since cpreg_tuples
     * must be in strictly ascending order.
     */
    qsort(&rlp->reg, rlp->n, sizeof(rlp->reg[0]), compare_u64);

    for (i = 0, arraylen = 0; i < rlp->n; i++) {
        if (!kvm_arm_reg_syncs_via_cpreg_list(rlp->reg[i])) {
            continue;
        }
        switch (rlp->reg[i] & KVM_REG_SIZE_MASK) {
        case KVM_REG_SIZE_U32:
        case KVM_REG_SIZE_U64:
            break;
        default:
            fprintf(stderr, "Can't handle size of register in kernel list\n");
            ret = -EINVAL;
            goto out;
        }

        arraylen++;
    }

    cpu->cpreg_indexes = g_renew(uint64_t, cpu->cpreg_indexes, arraylen);
    cpu->cpreg_values = g_renew(uint64_t, cpu->cpreg_values, arraylen);
    cpu->cpreg_array_len = arraylen;

    for (i = 0, arraylen = 0; i < rlp->n; i++) {
        uint64_t regidx = rlp->reg[i];
        if (!kvm_arm_reg_syncs_via_cpreg_list(regidx)) {
            continue;
        }
        cpu->cpreg_indexes[arraylen] = regidx;
        arraylen++;
    }
    assert(cpu->cpreg_array_len == arraylen);

    if (!write_kvmstate_to_list(cpu)) {
        /* Shouldn't happen unless kernel is inconsistent about
         * what registers exist.
         */
        fprintf(stderr, "Initial read of kernel register state failed\n");
        ret = -EINVAL;
        goto out;
    }

out:
    g_free(rlp);
    return ret;
}

/**
 * kvm_arm_cpreg_level:
 * @regidx: KVM register index
 *
 * Return the level of this coprocessor/system register.  Return value is
 * either KVM_PUT_RUNTIME_STATE, KVM_PUT_RESET_STATE, or KVM_PUT_FULL_STATE.
 */
static int kvm_arm_cpreg_level(uint64_t regidx)
{
    /*
     * All system registers are assumed to be level KVM_PUT_RUNTIME_STATE.
     * If a register should be written less often, you must add it here
     * with a state of either KVM_PUT_RESET_STATE or KVM_PUT_FULL_STATE.
     */
    switch (regidx) {
    case KVM_REG_ARM_TIMER_CNT:
    case KVM_REG_ARM_PTIMER_CNT:
        return KVM_PUT_FULL_STATE;
    }
    return KVM_PUT_RUNTIME_STATE;
}

bool write_kvmstate_to_list(ARMCPU *cpu)
{
    CPUState *cs = CPU(cpu);
    int i;
    bool ok = true;

    for (i = 0; i < cpu->cpreg_array_len; i++) {
        uint64_t regidx = cpu->cpreg_indexes[i];
        uint32_t v32;
        int ret;

        switch (regidx & KVM_REG_SIZE_MASK) {
        case KVM_REG_SIZE_U32:
            ret = kvm_get_one_reg(cs, regidx, &v32);
            if (!ret) {
                cpu->cpreg_values[i] = v32;
            }
            break;
        case KVM_REG_SIZE_U64:
            ret = kvm_get_one_reg(cs, regidx, cpu->cpreg_values + i);
            break;
        default:
            g_assert_not_reached();
        }
        if (ret) {
            ok = false;
        }
    }
    return ok;
}

/* pretty-print a KVM register */
#define CP_REG_ARM64_SYSREG_OP(_reg, _op)                       \
    ((uint8_t)((_reg & CP_REG_ARM64_SYSREG_ ## _op ## _MASK) >> \
               CP_REG_ARM64_SYSREG_ ## _op ## _SHIFT))

static gchar *kvm_print_sve_register_name(uint64_t regidx)
{
    uint16_t sve_reg = regidx & 0x000000000000ffff;

    if (regidx == KVM_REG_ARM64_SVE_VLS) {
        return g_strdup_printf("SVE VLS");
    }
    /* zreg, preg, ffr */
    switch (sve_reg & 0xfc00) {
    case 0:
        return g_strdup_printf("SVE zreg n:%d slice:%d",
                               (sve_reg & 0x03e0) >> 5, sve_reg & 0x001f);
    case 0x04:
        return g_strdup_printf("SVE preg n:%d slice:%d",
                               (sve_reg & 0x01e0) >> 5, sve_reg & 0x001f);
    case 0x06:
        return g_strdup_printf("SVE ffr slice:%d", sve_reg & 0x001f);
    default:
        return g_strdup_printf("SVE ???");
    }
}

char *kvm_print_register_name(uint64_t regidx)
{
        switch ((regidx & KVM_REG_ARM_COPROC_MASK)) {
        case KVM_REG_ARM_CORE:
            return g_strdup_printf("core reg %"PRIx64, regidx);
        case KVM_REG_ARM_DEMUX:
            return g_strdup_printf("demuxed reg %"PRIx64, regidx);
        case KVM_REG_ARM64_SYSREG:
            return g_strdup_printf("system register op0:%d op1:%d crn:%d crm:%d op2:%d",
                                   CP_REG_ARM64_SYSREG_OP(regidx, OP0),
                                   CP_REG_ARM64_SYSREG_OP(regidx, OP1),
                                   CP_REG_ARM64_SYSREG_OP(regidx, CRN),
                                   CP_REG_ARM64_SYSREG_OP(regidx, CRM),
                                   CP_REG_ARM64_SYSREG_OP(regidx, OP2));
        case KVM_REG_ARM_FW:
            return g_strdup_printf("fw reg %d", (int)(regidx & 0xffff));
        case KVM_REG_ARM64_SVE:
            return kvm_print_sve_register_name(regidx);
        case KVM_REG_ARM_FW_FEAT_BMAP:
            return g_strdup_printf("fw feat reg %d", (int)(regidx & 0xffff));
        default:
            return g_strdup_printf("%"PRIx64, regidx);
        }
}

bool write_list_to_kvmstate(ARMCPU *cpu, int level)
{
    CPUState *cs = CPU(cpu);
    int i;
    bool ok = true;

    for (i = 0; i < cpu->cpreg_array_len; i++) {
        uint64_t regidx = cpu->cpreg_indexes[i];
        uint32_t v32;
        int ret;

        if (kvm_arm_cpreg_level(regidx) > level) {
            continue;
        }

        switch (regidx & KVM_REG_SIZE_MASK) {
        case KVM_REG_SIZE_U32:
            v32 = cpu->cpreg_values[i];
            ret = kvm_set_one_reg(cs, regidx, &v32);
            break;
        case KVM_REG_SIZE_U64:
            ret = kvm_set_one_reg(cs, regidx, cpu->cpreg_values + i);
            break;
        default:
            g_assert_not_reached();
        }
        if (ret) {
            gchar *reg_str = kvm_print_register_name(regidx);

            /* We might fail for "unknown register" and also for
             * "you tried to set a register which is constant with
             * a different value from what it actually contains".
             */
            ok = false;
            switch (ret) {
            case -ENOENT:
                error_report("Could not set register %s: unknown to KVM",
                             reg_str);
                break;
            case -EINVAL:
                if ((regidx & KVM_REG_SIZE_MASK) == KVM_REG_SIZE_U32) {
                    if (!kvm_get_one_reg(cs, regidx, &v32)) {
                        error_report("Could not set register %s to %x (is %x)",
                                     reg_str, (uint32_t)cpu->cpreg_values[i],
                                     v32);
                    } else {
                        error_report("Could not set register %s to %x",
                                     reg_str, (uint32_t)cpu->cpreg_values[i]);
                    }
                } else /* U64 */ {
                    uint64_t v64;

                    if (!kvm_get_one_reg(cs, regidx, &v64)) {
                        error_report("Could not set register %s to %"PRIx64" (is %"PRIx64")",
                                     reg_str, cpu->cpreg_values[i], v64);
                    } else {
                        error_report("Could not set register %s to %"PRIx64,
                                     reg_str, cpu->cpreg_values[i]);
                    }
                }
                break;
            default:
                error_report("Could not set register %s: %s",
                             reg_str, strerror(-ret));
            }
            g_free(reg_str);
        }
    }
    return ok;
}

void kvm_arm_cpu_pre_save(ARMCPU *cpu)
{
    /* KVM virtual time adjustment */
    if (cpu->kvm_vtime_dirty) {
        *kvm_arm_get_cpreg_ptr(cpu, KVM_REG_ARM_TIMER_CNT) = cpu->kvm_vtime;
    }
}

bool kvm_arm_cpu_post_load(ARMCPU *cpu)
{
    if (!write_list_to_kvmstate(cpu, KVM_PUT_FULL_STATE)) {
        return false;
    }
    /* Note that it's OK for the TCG side not to know about
     * every register in the list; KVM is authoritative if
     * we're using it.
     */
    write_list_to_cpustate(cpu);

    /* KVM virtual time adjustment */
    if (cpu->kvm_adjvtime) {
        cpu->kvm_vtime = *kvm_arm_get_cpreg_ptr(cpu, KVM_REG_ARM_TIMER_CNT);
        cpu->kvm_vtime_dirty = true;
    }

    return true;
}

static void kvm_arm_reset_vcpu_work(CPUState *cs, run_on_cpu_data arg)
{
    ARMCPU *cpu = ARM_CPU(cs);
    int ret;

    /* Re-init VCPU so that all registers are set to
     * their respective reset values.
     */
    ret = kvm_arm_vcpu_init(cpu);
    if (ret < 0) {
        fprintf(stderr, "kvm_arm_vcpu_init failed: %s\n", strerror(-ret));
        abort();
    }
    if (!write_kvmstate_to_list(cpu)) {
        fprintf(stderr, "write_kvmstate_to_list failed\n");
        abort();
    }
    /*
     * Sync the reset values also into the CPUState. This is necessary
     * because the next thing we do will be a kvm_arch_put_registers()
     * which will update the list values from the CPUState before copying
     * the list values back to KVM. It's OK to ignore failure returns here
     * for the same reason we do so in kvm_arch_get_registers().
     */
    write_list_to_cpustate(cpu);
}

void kvm_arm_reset_vcpu(ARMCPU *cpu)
{
    CPUState *cs = CPU(cpu);
    /* a plane > 0 vCPU is driven by its leader's thread */
    CPUState *owner = cs->kvm_plane_leader ?: cs;

    /*
     * KVM_ARM_VCPU_INIT and the register reads behind it are vCPU ioctls.
     * Once the VM has planes KVM refuses those from a thread that did not
     * run the vCPU, so a guest-triggered reset runs them on the owning
     * thread. A cold reset precedes that thread and runs inline.
     */
    fprintf(stderr, "R2NRESET cpu=%d plane=%d owner=%d owner_created=%d"
            " self=%d route=%s\n", cs->cpu_index, cs->kvm_plane,
            owner->cpu_index, owner->created,
            owner->created ? qemu_cpu_is_self(cs) : -1,
            owner->created ? "run_on_cpu" : "inline");

    if (owner->created) {
        run_on_cpu(cs, kvm_arm_reset_vcpu_work, RUN_ON_CPU_NULL);
    } else {
        kvm_arm_reset_vcpu_work(cs, RUN_ON_CPU_NULL);
    }
}

/*
 * Update KVM's MP_STATE based on what QEMU thinks it is
 */
static int kvm_arm_sync_mpstate_to_kvm(ARMCPU *cpu)
{
    if (cap_has_mp_state) {
        struct kvm_mp_state mp_state = {
            .mp_state = (cpu->power_state == PSCI_OFF) ?
            KVM_MP_STATE_STOPPED : KVM_MP_STATE_RUNNABLE
        };
        return kvm_vcpu_ioctl(CPU(cpu), KVM_SET_MP_STATE, &mp_state);
    }
    return 0;
}

/*
 * Sync the KVM MP_STATE into QEMU
 */
static int kvm_arm_sync_mpstate_to_qemu(ARMCPU *cpu)
{
    if (cap_has_mp_state) {
        struct kvm_mp_state mp_state;
        int ret = kvm_vcpu_ioctl(CPU(cpu), KVM_GET_MP_STATE, &mp_state);
        ARMPSCIState state;
        if (ret) {
            return ret;
        }
        state = (mp_state.mp_state == KVM_MP_STATE_STOPPED) ? PSCI_OFF : PSCI_ON;
        arm_set_cpu_power_state(cpu, state);
    }
    return 0;
}

/*
 * R2k: attribute a vtime failure to an fd, a plane and an errno. KVM gates
 * vCPU ioctls from a foreign thread once a plane exists (kvm_vcpu_ioctl).
 */
static void kvm_arm_vtime_failed(ARMCPU *cpu, const char *op, int ret)
{
    CPUState *cs = CPU(cpu);
    CPUState *leader = cs->kvm_plane_leader;

    error_report("Failed to %s KVM_REG_ARM_TIMER_CNT: %s (ret=%d) "
                 "cpu_index=%d kvm_fd=%d plane=%d role=%s leader_index=%d",
                 op, strerror(-ret), ret, cs->cpu_index, cs->kvm_fd,
                 cs->kvm_plane, leader ? "sibling" : "leader",
                 leader ? leader->cpu_index : cs->cpu_index);
}

/**
 * kvm_arm_get_virtual_time:
 * @cpu: ARMCPU
 *
 * Gets the VCPU's virtual counter and stores it in the KVM CPU state.
 */
static void kvm_arm_get_virtual_time(ARMCPU *cpu)
{
    int ret;

    if (cpu->kvm_vtime_dirty) {
        return;
    }

    ret = kvm_get_one_reg(CPU(cpu), KVM_REG_ARM_TIMER_CNT, &cpu->kvm_vtime);
    if (ret) {
        kvm_arm_vtime_failed(cpu, "get", ret);
        abort();
    }

    cpu->kvm_vtime_dirty = true;
}

/**
 * kvm_arm_put_virtual_time:
 * @cpu: ARMCPU
 *
 * Sets the VCPU's virtual counter to the value stored in the KVM CPU state.
 */
static void kvm_arm_put_virtual_time(ARMCPU *cpu)
{
    int ret;

    if (!cpu->kvm_vtime_dirty) {
        return;
    }

    ret = kvm_set_one_reg(CPU(cpu), KVM_REG_ARM_TIMER_CNT, &cpu->kvm_vtime);
    if (ret) {
        kvm_arm_vtime_failed(cpu, "set", ret);
        abort();
    }

    cpu->kvm_vtime_dirty = false;
}

/**
 * kvm_put_vcpu_events:
 * @cpu: ARMCPU
 *
 * Put VCPU related state to kvm.
 *
 * Returns: 0 if success else < 0 error code
 */
static int kvm_put_vcpu_events(ARMCPU *cpu)
{
    CPUARMState *env = &cpu->env;
    struct kvm_vcpu_events events;
    int ret;

    if (!kvm_has_vcpu_events()) {
        return 0;
    }

    memset(&events, 0, sizeof(events));
    events.exception.serror_pending = env->serror.pending;

    /* Inject SError to guest with specified syndrome if host kernel
     * supports it, otherwise inject SError without syndrome.
     */
    if (cap_has_inject_serror_esr) {
        events.exception.serror_has_esr = env->serror.has_esr;
        events.exception.serror_esr = env->serror.esr;
    }

    ret = kvm_vcpu_ioctl(CPU(cpu), KVM_SET_VCPU_EVENTS, &events);
    if (ret) {
        error_report("failed to put vcpu events");
    }

    return ret;
}

/**
 * kvm_get_vcpu_events:
 * @cpu: ARMCPU
 *
 * Get VCPU related state from kvm.
 *
 * Returns: 0 if success else < 0 error code
 */
static int kvm_get_vcpu_events(ARMCPU *cpu)
{
    CPUARMState *env = &cpu->env;
    struct kvm_vcpu_events events;
    int ret;

    if (!kvm_has_vcpu_events()) {
        return 0;
    }

    memset(&events, 0, sizeof(events));
    ret = kvm_vcpu_ioctl(CPU(cpu), KVM_GET_VCPU_EVENTS, &events);
    if (ret) {
        error_report("failed to get vcpu events");
        return ret;
    }

    env->serror.pending = events.exception.serror_pending;
    env->serror.has_esr = events.exception.serror_has_esr;
    env->serror.esr = events.exception.serror_esr;

    return 0;
}

#define ARM64_REG_ESR_EL1 ARM64_SYS_REG(3, 0, 5, 2, 0)
#define ARM64_REG_TCR_EL1 ARM64_SYS_REG(3, 0, 2, 0, 2)

/*
 * ESR_EL1
 * ISS encoding
 * AARCH64: DFSC,   bits [5:0]
 * AARCH32:
 *      TTBCR.EAE == 0
 *          FS[4]   - DFSR[10]
 *          FS[3:0] - DFSR[3:0]
 *      TTBCR.EAE == 1
 *          FS, bits [5:0]
 */
#define ESR_DFSC(aarch64, lpae, v)        \
    ((aarch64 || (lpae)) ? ((v) & 0x3F)   \
               : (((v) >> 6) | ((v) & 0x1F)))

#define ESR_DFSC_EXTABT(aarch64, lpae) \
    ((aarch64) ? 0x10 : (lpae) ? 0x10 : 0x8)

/**
 * kvm_arm_verify_ext_dabt_pending:
 * @cpu: ARMCPU
 *
 * Verify the fault status code wrt the Ext DABT injection
 *
 * Returns: true if the fault status code is as expected, false otherwise
 */
static bool kvm_arm_verify_ext_dabt_pending(ARMCPU *cpu)
{
    CPUState *cs = CPU(cpu);
    uint64_t dfsr_val;

    if (!kvm_get_one_reg(cs, ARM64_REG_ESR_EL1, &dfsr_val)) {
        CPUARMState *env = &cpu->env;
        int aarch64_mode = arm_feature(env, ARM_FEATURE_AARCH64);
        int lpae = 0;

        if (!aarch64_mode) {
            uint64_t ttbcr;

            if (!kvm_get_one_reg(cs, ARM64_REG_TCR_EL1, &ttbcr)) {
                lpae = arm_feature(env, ARM_FEATURE_LPAE)
                        && (ttbcr & TTBCR_EAE);
            }
        }
        /*
         * The verification here is based on the DFSC bits
         * of the ESR_EL1 reg only
         */
         return (ESR_DFSC(aarch64_mode, lpae, dfsr_val) ==
                ESR_DFSC_EXTABT(aarch64_mode, lpae));
    }
    return false;
}

void kvm_arch_pre_run(CPUState *cs, struct kvm_run *run)
{
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;

    /* VTL switch bookkeeping and req_exit_planes */
    if (cpu_is_plane_sibling(cs) || cs->kvm_plane_next) {
        hv_plane_pre_run(cs, run);
    }

    if (unlikely(env->ext_dabt_raised)) {
        /*
         * Verifying that the ext DABT has been properly injected,
         * otherwise risking indefinitely re-running the faulting instruction
         * Covering a very narrow case for kernels 5.5..5.5.4
         * when injected abort was misconfigured to be
         * an IMPLEMENTATION DEFINED exception (for 32-bit EL1)
         */
        if (!arm_feature(env, ARM_FEATURE_AARCH64) &&
            unlikely(!kvm_arm_verify_ext_dabt_pending(cpu))) {

            error_report("Data abort exception with no valid ISS generated by "
                   "guest memory access. KVM unable to emulate faulting "
                   "instruction. Failed to inject an external data abort "
                   "into the guest.");
            abort();
       }
       /* Clear the status */
       env->ext_dabt_raised = 0;
    }
}

MemTxAttrs kvm_arch_post_run(CPUState *cs, struct kvm_run *run)
{
    ARMCPU *cpu;
    uint32_t switched_level;

    if (kvm_irqchip_in_kernel()) {
        /*
         * We only need to sync timer states with user-space interrupt
         * controllers, so return early and save cycles if we don't.
         */
        return MEMTXATTRS_UNSPECIFIED;
    }

    cpu = ARM_CPU(cs);

    /* Synchronize our shadowed in-kernel device irq lines with the kvm ones */
    if (run->s.regs.device_irq_level != cpu->device_irq_level) {
        switched_level = cpu->device_irq_level ^ run->s.regs.device_irq_level;

        bql_lock();

        if (switched_level & KVM_ARM_DEV_EL1_VTIMER) {
            qemu_set_irq(cpu->gt_timer_outputs[GTIMER_VIRT],
                         !!(run->s.regs.device_irq_level &
                            KVM_ARM_DEV_EL1_VTIMER));
            switched_level &= ~KVM_ARM_DEV_EL1_VTIMER;
        }

        if (switched_level & KVM_ARM_DEV_EL1_PTIMER) {
            qemu_set_irq(cpu->gt_timer_outputs[GTIMER_PHYS],
                         !!(run->s.regs.device_irq_level &
                            KVM_ARM_DEV_EL1_PTIMER));
            switched_level &= ~KVM_ARM_DEV_EL1_PTIMER;
        }

        if (switched_level & KVM_ARM_DEV_PMU) {
            qemu_set_irq(cpu->pmu_interrupt,
                         !!(run->s.regs.device_irq_level & KVM_ARM_DEV_PMU));
            switched_level &= ~KVM_ARM_DEV_PMU;
        }

        if (switched_level) {
            qemu_log_mask(LOG_UNIMP, "%s: unhandled in-kernel device IRQ %x\n",
                          __func__, switched_level);
        }

        /* We also mark unknown levels as processed to not waste cycles */
        cpu->device_irq_level = run->s.regs.device_irq_level;
        bql_unlock();
    }

    return MEMTXATTRS_UNSPECIFIED;
}

static void kvm_arm_vtime_work(CPUState *cs, run_on_cpu_data arg)
{
    if (arg.host_int) {
        kvm_arm_put_virtual_time(ARM_CPU(cs));
    } else {
        kvm_arm_get_virtual_time(ARM_CPU(cs));
    }
}

static void kvm_arm_vm_state_change(void *opaque, bool running, RunState state)
{
    ARMCPU *cpu = opaque;

    if (!cpu->kvm_adjvtime) {
        return;
    }
    /*
     * Once the VM has planes, KVM refuses a vCPU ioctl from a thread that did
     * not run the vCPU, so adjust the counter on the vCPU's own thread.
     */
    run_on_cpu(CPU(cpu), kvm_arm_vtime_work, RUN_ON_CPU_HOST_INT(running));
}

/**
 * kvm_arm_handle_dabt_nisv:
 * @cpu: ARMCPU
 * @esr_iss: ISS encoding (limited) for the exception from Data Abort
 *           ISV bit set to '0b0' -> no valid instruction syndrome
 * @fault_ipa: faulting address for the synchronous data abort
 *
 * Returns: 0 if the exception has been handled, < 0 otherwise
 */
static int kvm_arm_handle_dabt_nisv(ARMCPU *cpu, uint64_t esr_iss,
                                    uint64_t fault_ipa)
{
    CPUARMState *env = &cpu->env;
    /*
     * Request KVM to inject the external data abort into the guest
     */
    if (cap_has_inject_ext_dabt) {
        struct kvm_vcpu_events events = { };
        /*
         * The external data abort event will be handled immediately by KVM
         * using the address fault that triggered the exit on given VCPU.
         * Requesting injection of the external data abort does not rely
         * on any other VCPU state. Therefore, in this particular case, the VCPU
         * synchronization can be exceptionally skipped.
         */
        events.exception.ext_dabt_pending = 1;
        /* KVM_CAP_ARM_INJECT_EXT_DABT implies KVM_CAP_VCPU_EVENTS */
        if (!kvm_vcpu_ioctl(CPU(cpu), KVM_SET_VCPU_EVENTS, &events)) {
            env->ext_dabt_raised = 1;
            return 0;
        }
    } else {
        error_report("Data abort exception triggered by guest memory access "
                     "at physical address: 0x"  TARGET_FMT_lx,
                     (target_ulong)fault_ipa);
        error_printf("KVM unable to emulate faulting instruction.\n");
    }
    return -1;
}

/*
 * KVM_CAP_ARM_HVC_IMM_EXITS: an HVC whose immediate is in the mask exits
 * before any SMCCC dispatch, nr carrying the immediate. Hyper-V on ARM64
 * switches VTLs with HVC #2 (call) and HVC #3 (return); the VSM layer turns
 * them into plane switches. ret 0 is "handled"; a non-zero ret makes KVM
 * inject an undefined instruction exception at the HVC.
 */
static int r2_k200_reads;         /* kernel-space 0x200 reads reaching us */
static uint64_t r2_gate_addr;     /* NTBASE + HvlEnableVsmCalls tbz, if patched */
static uint32_t r2_gate_orig;     /* original word at the gate */
static uint64_t r2_ctrl_addr;     /* HviGetHypervisorFeatures entry, patched */
static uint32_t r2_ctrl_orig;
static int r2_ctrl_hits;          /* positive control: writes to .text are seen */

static int kvm_arm_handle_hypercall(CPUState *cs, struct kvm_run *run)
{
    if (!(run->hypercall.flags & KVM_HYPERCALL_EXIT_HVC_IMM)) {
        qemu_log_mask(LOG_UNIMP, "%s: SMCCC exit for function 0x%" PRIx64
                      " without a filter\n", __func__,
                      (uint64_t)run->hypercall.nr);
        return -1;
    }

    if (run->hypercall.nr == 5 && r2_ctrl_addr) {
        CPUARMState *env = &ARM_CPU(cs)->env;

        cpu_synchronize_state(cs);
        r2_ctrl_hits++;
        fprintf(stderr, "R2CTRL hit #%d (writes to .text are seen)\n",
                r2_ctrl_hits);
        cpu_memory_rw_debug(cs, r2_ctrl_addr, (uint8_t *)&r2_ctrl_orig, 4,
                            true);
        env->pc = r2_ctrl_addr;
        run->hypercall.ret = 0;
        r2_ctrl_addr = 0;
        return 0;
    }

    if (run->hypercall.nr == 4 && r2_gate_addr) {
        CPUARMState *env = &ARM_CPU(cs)->env;
        uint32_t w8;

        cpu_synchronize_state(cs);
        w8 = env->xregs[8];
        fprintf(stderr, "R2GATE hit ctx=0x%" PRIx64 " word=0x%08x bit8=%d"
                " k200reads=%d\n", env->xregs[0], w8, (w8 >> 8) & 1,
                r2_k200_reads);
        /* restore the real tbz and re-execute it with the real w8 */
        cpu_memory_rw_debug(cs, r2_gate_addr, (uint8_t *)&r2_gate_orig, 4,
                            true);
        env->pc = r2_gate_addr;
        run->hypercall.ret = 0;
        r2_gate_addr = 0;
        return 0;
    }

    trace_kvm_arm_hvc_imm_exit(cs->cpu_index, cs->kvm_plane,
                               (uint64_t)run->hypercall.nr);
    return hyperv_vsm_arm_handle_hvc_imm(cs, run);
}

/**
 * kvm_arm_handle_debug:
 * @cpu: ARMCPU
 * @debug_exit: debug part of the KVM exit structure
 *
 * Returns: TRUE if the debug exception was handled.
 *
 * See v8 ARM ARM D7.2.27 ESR_ELx, Exception Syndrome Register
 *
 * To minimise translating between kernel and user-space the kernel
 * ABI just provides user-space with the full exception syndrome
 * register value to be decoded in QEMU.
 */
static bool kvm_arm_handle_debug(ARMCPU *cpu,
                                 struct kvm_debug_exit_arch *debug_exit)
{
    int hsr_ec = syn_get_ec(debug_exit->hsr);
    CPUState *cs = CPU(cpu);
    CPUARMState *env = &cpu->env;

    /* Ensure PC is synchronised */
    kvm_cpu_synchronize_state(cs);

    switch (hsr_ec) {
    case EC_SOFTWARESTEP:
        if (cpu_single_stepping(cs)) {
            return true;
        } else {
            /*
             * The kernel should have suppressed the guest's ability to
             * single step at this point so something has gone wrong.
             */
            error_report("%s: guest single-step while debugging unsupported"
                         " (%"PRIx64", %"PRIx32")",
                         __func__, env->pc, debug_exit->hsr);
            return false;
        }
        break;
    case EC_AA64_BKPT:
        if (kvm_find_sw_breakpoint(cs, env->pc)) {
            return true;
        }
        break;
    case EC_BREAKPOINT:
        if (find_hw_breakpoint(cs, env->pc)) {
            return true;
        }
        break;
    case EC_WATCHPOINT:
    {
        CPUWatchpoint *wp = find_hw_watchpoint(cs, debug_exit->far);
        if (wp) {
            cs->watchpoint_hit = wp;
            return true;
        }
        break;
    }
    default:
        error_report("%s: unhandled debug exit (%"PRIx32", %"PRIx64")",
                     __func__, debug_exit->hsr, env->pc);
    }

    /* If we are not handling the debug exception it must belong to
     * the guest. Let's re-use the existing TCG interrupt code to set
     * everything up properly.
     */
    cs->exception_index = EXCP_BKPT;
    env->exception.syndrome = debug_exit->hsr;
    env->exception.vaddress = debug_exit->far;
    env->exception.target_el = 1;
    bql_lock();
    arm_cpu_do_interrupt(cs);
    bql_unlock();

    return false;
}

/*
 * HvCallStartVirtualProcessor input for ARM64 (hvdef StartVirtualProcessorArm64
 * and InitialVpContextArm64): 16-byte header, then nine registers.
 */
struct hv_start_vp_arm64 {
    uint64_t partition_id;
    uint32_t vp_index;
    uint8_t target_vtl;
    uint8_t rsvd0;
    uint16_t rsvd1;
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

typedef struct HvVpStartWork {
    struct hv_start_vp_arm64 in;
    CPUState *start_plane;
} HvVpStartWork;

/* On the target's own thread: load the supplied context and run it at EL1h. */
static void hv_vp_start_work(CPUState *cs, run_on_cpu_data arg)
{
    HvVpStartWork *w = arg.host_ptr;
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;

    cpu_synchronize_state(cs);

    memset(env->xregs, 0, sizeof(env->xregs));
    env->xregs[18] = w->in.x18;
    env->pc = w->in.pc;
    env->sp_el[1] = w->in.sp_elh;
    env->xregs[31] = w->in.sp_elh;
    env->cp15.sctlr_el[1] = w->in.sctlr_el1;
    env->cp15.mair_el[1] = w->in.mair_el1;
    env->cp15.tcr_el[1] = w->in.tcr_el1;
    env->cp15.vbar_el[1] = w->in.vbar_el1;
    env->cp15.ttbr0_el[1] = w->in.ttbr0_el1;
    env->cp15.ttbr1_el[1] = w->in.ttbr1_el1;
    pstate_write(env, PSTATE_MODE_EL1h | PSTATE_DAIF);
    env->aarch64 = 1;
    fprintf(stderr, "R2START vp=%u plane=%d want_pc=0x%llx got_pc=0x%llx want_sp=0x%llx\n", hyperv_vp_index(cs), cs->kvm_plane, (unsigned long long)w->in.pc, (unsigned long long)env->pc, (unsigned long long)w->in.sp_elh);

    arm_set_cpu_power_state(cpu, PSCI_ON);
    cs->halted = 0;
    /*
     * VSM AP bringup: if VTL1 is enabled on this VP, select its securekernel
     * plane to run before VTL0 so it initialises and checks in. Mirrors x86
     * vp_start_work, which selects highest_vtl via hv_plane_select_start.
     */
    if (w->start_plane && w->start_plane != cs) {
        w->start_plane->halted = 0;
        hv_plane_select_start(w->start_plane);
    }
    cs->vcpu_dirty = true;
    g_free(w);
}

static uint64_t r1_ntbase; /* diagnostic: ntoskrnl base from the anchor walk */

/* Identity-class registers Windows writes about itself and reads back. */
struct r1_hv_reg { uint32_t name; uint64_t val; };
static uint64_t r1_hv_crash[5]; /* GUEST_CRASH_P0..P4 */
static struct r1_hv_reg r1_hv_store[] = {
    { 0x90002, 0 }, /* GUEST_OS_ID */
    { 0x90007, 0 }, /* CPU_MANAGEMENT_VERSION */
    { 0x90015, 0 }, /* partition info page: last value the guest published */
    { 0x90016, 0 }, /* partition info group, adjacent to 0x90015: plain store */
    { 0x90017, 0 }, /* R4 gate-2: VP-info group member, adjacent to 0x90016: plain store */
    { 0x40400, 0 }, /* SyntheticVbarEl1: guest EL1 vector base VA, plain store */
    /*
     * Written by HvlConfigureMemoryZeroingOnReset. Not named in the TLFS or
     * hvdef (the nearest documented item is the ZeroMemoryOnReset partition
     * property). A reset-time policy nothing here acts on: plain store.
     */
    { 0x270, 0 },
};

static struct r1_hv_reg *r1_hv_store_find(uint32_t name)
{
    size_t i;
    for (i = 0; i < ARRAY_SIZE(r1_hv_store); i++) {
        if (r1_hv_store[i].name == name) {
            return &r1_hv_store[i];
        }
    }
    return NULL;
}

/*
 * Answer the VP-register hypercalls a Windows guest issues from the FADT
 * Hyper-V path. Name is in x3 low 32 bits, Set value in x5, x4 is scratch.
 * Result is returned x6 low, x7 high. x0 = (reps_completed << 32) | status.
 * KVM has already advanced the PC.
 */
static void r1_hv_hcall_log(CPUState *cs, struct kvm_run *run)
{
    CPUARMState *env = &ARM_CPU(cs)->env;
    uint64_t x[8];
    uint16_t code;
    uint32_t name;
    uint64_t lo = 0, hi = 0, status = HV_STATUS_INVALID_HYPERCALL_CODE;
    uint64_t reps_completed = 1;
    uint64_t in_gpa, out_gpa;
    uint16_t varhdr, reps;
    bool fast;
    int i;

    cpu_synchronize_state(cs);
    for (i = 0; i < 8; i++) {
        x[i] = env->xregs[i];
    }
    code = x[0] & 0xffff;
    name = (uint32_t)x[3];
    /* Control word: bit 16 selects the fast (register) form, bits 17-26 carry
     * the variable header size and bits 32-43 the rep count. In the memory
     * form x1 and x2 are the input and output block addresses. */
    fast = (x[0] >> 16) & 1;
    varhdr = (x[0] >> 17) & 0x1ff;
    reps = (x[0] >> 32) & 0xfff;
    in_gpa = fast ? 0 : x[1];
    out_gpa = fast ? 0 : x[2];

    {
        /* R1ROOTNOW: on a reboot loop the anchor base is stale, so recompute
         * the ntoskrnl base from the current kernel pc and read HvlpRootFlags
         * one hcall after the 0x204 answer, by when HvlpDetermineEnlightenments
         * has set it. Tells us if root (0x187/bit8) engaged. */
        static uint64_t r1_root_base;
        static bool r1_root_pending;
        if (r1_root_pending && (env->pc >> 40) == 0xfffff8) {
            uint32_t rf = 0;
            cpu_memory_rw_debug(cs, r1_root_base + 0xe07ae0,
                                (uint8_t *)&rf, 4, false);
            fprintf(stderr, "R1ROOTNOW HvlpRootFlags=0x%x base=0x%" PRIx64 "\n",
                    rf, r1_root_base);
            r1_root_pending = false;
        }
        if (code == 0x0050 && name == 0x204 && (env->pc >> 40) == 0xfffff8) {
            uint64_t a = env->pc & ~0xffffULL;
            int k;
            for (k = 0; k < 8192; k++) {
                uint8_t mz[2];
                if (cpu_memory_rw_debug(cs, a, mz, 2, false) == 0 &&
                    mz[0] == 0x4d && mz[1] == 0x5a) { r1_root_base = a; break; }
                a -= 0x10000;
            }
            r1_root_pending = true;
        }
    }

    {
        /* R1HOOK: at the first NVMe DMA map (late, interrupt setup active),
         * read the MapDeviceInterrupt hook ptr [0xe040b8], HvlpRootFlags, and
         * the interrupt-controller cap word (bit11 native-MSI). Tells us if
         * the hook is installed so the HAL would call 0x7c. */
        static bool r1_hook_done;
        if (!r1_hook_done && code == 0x0050 && name == 0x215 && (env->pc >> 40) == 0xfffff8) {
            uint64_t a = env->pc & ~0xffffULL; int k; uint64_t base = 0;
            for (k = 0; k < 8192; k++) {
                uint8_t mz[2];
                if (cpu_memory_rw_debug(cs, a, mz, 2, false) == 0 &&
                    mz[0] == 0x4d && mz[1] == 0x5a) { base = a; break; }
                a -= 0x10000;
            }
            if (base) {
                uint64_t hook = 0, ctrlptr = 0; uint32_t rf = 0, cap = 0;
                cpu_memory_rw_debug(cs, base + 0xe040b8, (uint8_t *)&hook, 8, false);
                cpu_memory_rw_debug(cs, base + 0xe07ae0, (uint8_t *)&rf, 4, false);
                cpu_memory_rw_debug(cs, base + 0xc0fed0, (uint8_t *)&ctrlptr, 8, false);
                if (ctrlptr) {
                    cpu_memory_rw_debug(cs, ctrlptr + 244, (uint8_t *)&cap, 4, false);
                }
                fprintf(stderr, "R1HOOK hook=0x%" PRIx64 " rootflags=0x%x cap=0x%x"
                        " ctrlptr=0x%" PRIx64 " base=0x%" PRIx64 "\n",
                        hook, rf, cap, ctrlptr, base);
            }
            r1_hook_done = true;
        }
    }

    if (code == 0x0050) { /* HvGetVpRegisters */
        struct r1_hv_reg *r;
        status = HV_STATUS_INVALID_PARAMETER; /* known call, unknown register */
        if (name == 0x90003) { /* VP_INDEX: the calling vCPU index, read-only */
            lo = hyperv_vp_index(cs);
            status = HV_STATUS_SUCCESS;
        } else if (name == 0x90004) { /* TIME_REF_COUNT: monotonic reference time, 100ns units */
            lo = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / 100;
            status = HV_STATUS_SUCCESS;
        } else if (name == 0x100) { /* HYPERVISOR_VERSION: mirror x86 CPUID 0x40000002.
                                     * eax=build hw/.../cpu.c hv-version-id defaults,
                                     * ebx=major<<16|minor; QEMU x86 kvm.c:1591. */
            lo = ((uint64_t)0x000A0000 << 32) | 0x3839; /* ver 10.0 build 14393 */
            hi = 0;                                      /* sp / sb / sn = 0 */
            status = HV_STATUS_SUCCESS;
        } else if (name == 0x215) { /* GUEST_CRASH_CTL: crash notify available */
            lo = (1ULL << 63);
            status = HV_STATUS_SUCCESS;
        } else if (name >= 0x210 && name <= 0x214) { /* GUEST_CRASH_P0..P4 */
            lo = r1_hv_crash[name - 0x210];
            status = HV_STATUS_SUCCESS;
        } else if (name == 0x201) {
            lo = (1ULL << 5); /* FEATURES_INFO: RelaxedTiming only */
            status = HV_STATUS_SUCCESS;
        } else if (name == 0x202) { /* IMPLEMENTATION_LIMITS, x86 leaf 0x40000005:
                                     * eax=max virtual processors,
                                     * ebx=max logical processors. Report what
                                     * -smp actually exposes, not zero. */
            uint32_t ncpu = current_machine ? current_machine->smp.max_cpus : 0;
            lo = ((uint64_t)ncpu << 32) | ncpu;
            status = HV_STATUS_SUCCESS;
        } else if (name == 0x204) { /* CpuManagementFeaturesInfo (hvdef): bit
                                     * 31 = root partition. We are the sole
                                     * partition and own every CPU and device
                                     * we see, so root is the truthful name and
                                     * the model a Hyper-V host runs Credential
                                     * Guard under. Only bit 31; bits 0/1 (which
                                     * would set other RootFlags bits) stay 0. */
            lo = (1ULL << 31);
            status = HV_STATUS_SUCCESS;
        } else if (name == 0x200) { /* PrivilegesAndFeaturesInfo: the partition
                                     * privilege mask, one 64-bit word whose
                                     * upper half is CPUID leaf 3 EBX (hvgdk_mini
                                     * HV_PARTITION_PRIVILEGE_MASK [63-32]). Zero
                                     * but for VSM when the machine offers it:
                                     * AccessVsm (EBX bit 16, here 48) and
                                     * AccessVpRegisters (17, here 49), and
                                     * StartVirtualProcessor (21, here 53). */
            lo = virt_hv_vsm() ? (1ULL << 1) | (1ULL << 9) | (1ULL << 48) | (1ULL << 49) |
                                    (1ULL << 53) : 0;
            { /* R2 probe: extra privilege bits from the environment */
                const char *e = getenv("QEMU_HV_PRIV_EXTRA");
                if (e) {
                    lo |= strtoull(e, NULL, 0);
                }
                e = getenv("QEMU_HV_PRIV_HI");
                if (e) {
                    hi = strtoull(e, NULL, 0);
                }
            }
            status = HV_STATUS_SUCCESS;
        } else if (name >= 0x201 && name <= 0x20f) {
            char var[32]; /* R2 probe: QEMU_HV_REG_203=0x8 etc. */
            const char *e;
            snprintf(var, sizeof(var), "QEMU_HV_REG_%x", name);
            e = getenv(var);
            if (e) {
                lo = strtoull(e, NULL, 0);
            }
            status = HV_STATUS_SUCCESS; /* feature-access leaf: honest zero */
        } else if (name == 0x40001) { /* HvArm64RegisterName MpidrEl1 */
            lo = ARM_CPU(cs)->mp_affinity | (1ULL << 31);
            status = HV_STATUS_SUCCESS;
        } else if (name == 0x90015) {
            /*
             * Partition information page. The hypervisor owns it: the
             * kernel's HvlpInitializePartitionInfoPage maps whatever GET
             * returns as a GPA and reads word 0 (TLB-flush hypercall
             * available). Report our zero page, present and enabled.
             */
            hwaddr base = virt_hv_overlay_base();
            lo = base ? (base | 1) : 0;
            status = HV_STATUS_SUCCESS;
        } else if (name == 0x90007) { /* CpuManagementVersion / VmmCapabilities:
                                       * bit 62 = CPU-management version present.
                                       * The gate that lets the HAL read 0x204
                                       * and set HvlpRootFlags bit 1. Answered
                                       * here, not from the store the ack writes. */
            lo = (1ULL << 62);
            status = HV_STATUS_SUCCESS;
        } else if (name == 0xd0006) { /* HvRegisterVsmCapabilities: the
                                       * partition-wide VSM report, from
                                       * the common state like x86. */
            lo = hv_vsm.capabilities.as_uint64;
            status = HV_STATUS_SUCCESS;
        } else if ((r = r1_hv_store_find(name)) != NULL) {
            lo = r->val;
            status = HV_STATUS_SUCCESS;
        }
    } else if (code == 0x0051) { /* HvSetVpRegisters */
        struct r1_hv_reg *r = r1_hv_store_find(name);
        status = HV_STATUS_INVALID_PARAMETER; /* known call, unknown register */
        if (name >= 0x210 && name <= 0x214) { /* store crash params */
            r1_hv_crash[name - 0x210] = x[5];
            status = HV_STATUS_SUCCESS;
        } else if (name == 0x215) { /* GUEST_CRASH_CTL notify */
            status = HV_STATUS_SUCCESS;
            if (x[5] & (1ULL << 63)) {
                fprintf(stderr, "r1_hv_hcall: GUEST BUGCHECK P0=0x%" PRIx64
                        " P1=0x%" PRIx64 " P2=0x%" PRIx64 " P3=0x%" PRIx64
                        " P4=0x%" PRIx64 "\n",
                        r1_hv_crash[0], r1_hv_crash[1], r1_hv_crash[2],
                        r1_hv_crash[3], r1_hv_crash[4]);
                {
                    /* R1BC: bugcheck 0x7B P1 points to a UNICODE_STRING
                     * (the boot object name not found) or a device obj.
                     * Dump it to see WHAT the kernel could not resolve. */
                    uint64_t p1 = r1_hv_crash[1];
                    uint8_t raw[16] = {0};
                    uint16_t ulen;
                    uint64_t ubuf = 0;

                    cpu_memory_rw_debug(cs, p1, raw, sizeof(raw), false);
                    ulen = raw[0] | (raw[1] << 8);
                    memcpy(&ubuf, raw + 8, 8);
                    fprintf(stderr, "R1BC P1=0x%" PRIx64 " ulen=%u ubuf=0x%"
                            PRIx64 "\n", p1, ulen, ubuf);
                    if (ulen && ulen < 512 && ubuf > 0xffff000000000000ULL) {
                        uint8_t wb[260] = {0};
                        char asc[131] = {0};
                        int n = ulen < 258 ? ulen : 258;
                        int j;

                        cpu_memory_rw_debug(cs, ubuf, wb, n, false);
                        for (j = 0; j * 2 < n && j < 130; j++) {
                            uint8_t c = wb[j * 2];

                            asc[j] = (c >= 32 && c < 127) ? c : 0x2e;
                        }
                        fprintf(stderr, "R1BC P1name='%s'\n", asc);
                    }
                }
                {
                    /* R1CTRL: walk HalpRegisteredInterruptControllers (RVA
                     * 0xe05250). A line-block of type 7 (+32) is what
                     * HalpAllocateMsiLines needs for an MSI/LPI; if none is
                     * registered the NVMe MSI alloc fails before 0x7c. */
                    uint64_t b2 = env->pc & ~0xffffULL; int k; uint64_t cb = 0;
                    for (k = 0; k < 8192; k++) {
                        uint8_t mz[2];
                        if (cpu_memory_rw_debug(cs, b2, mz, 2, false) == 0 &&
                            mz[0] == 0x4d && mz[1] == 0x5a) { cb = b2; break; }
                        b2 -= 0x10000;
                    }
                    if (cb) {
                        uint64_t head = cb + 0xe05250, node = 0;
                        int oc = 0, found7 = 0;
                        cpu_memory_rw_debug(cs, head, (uint8_t *)&node, 8, false);
                        while (node && node != head && oc < 16) {
                            uint64_t ihead = node + 264, e = 0;
                            int ic = 0;
                            cpu_memory_rw_debug(cs, ihead, (uint8_t *)&e, 8, false);
                            while (e && e != ihead && ic < 32) {
                                uint32_t ty = 0;
                                cpu_memory_rw_debug(cs, e + 32, (uint8_t *)&ty, 4, false);
                                fprintf(stderr, "R1CTRL node=%d blk=%d type=%u\n", oc, ic, ty);
                                if (ty == 7) {
                                    uint32_t sz = 0, f24 = 0, f28 = 0;
                                    uint64_t buf = 0, bits = 0;
                                    found7 = 1;
                                    cpu_memory_rw_debug(cs, e + 24, (uint8_t *)&f24, 4, false);
                                    cpu_memory_rw_debug(cs, e + 28, (uint8_t *)&f28, 4, false);
                                    cpu_memory_rw_debug(cs, e + 72, (uint8_t *)&sz, 4, false);
                                    cpu_memory_rw_debug(cs, e + 80, (uint8_t *)&buf, 8, false);
                                    if (buf) {
                                        cpu_memory_rw_debug(cs, buf, (uint8_t *)&bits, 8, false);
                                    }
                                    fprintf(stderr, "R1CTRL7 bitmapsize=%u buf=0x%" PRIx64
                                            " bits0=0x%" PRIx64 " f24=%u f28=%u\n",
                                            sz, buf, bits, f24, f28);
                                }
                                cpu_memory_rw_debug(cs, e, (uint8_t *)&e, 8, false);
                                ic++;
                            }
                            cpu_memory_rw_debug(cs, node, (uint8_t *)&node, 8, false);
                            oc++;
                        }
                        fprintf(stderr, "R1CTRL base=0x%" PRIx64 " outer=%d type7=%d\n", cb, oc, found7);
                    }
                }
                if (r1_ntbase) {
                    uint32_t nproc = 0; uint64_t pb; int i, nb = 0;
                    cpu_memory_rw_debug(cs, r1_ntbase + 0xe07a80, (uint8_t *)&nproc, 4, false);
                    for (i = 0; i < 64; i++) {
                        pb = 0;
                        cpu_memory_rw_debug(cs, r1_ntbase + 0xe09700 + 8 * i, (uint8_t *)&pb, 8, false);
                        nb += pb != 0;
                    }
                    fprintf(stderr, "R1PROC KeNumberProcessors=%u KiProcessorBlock_nonnull=%d\n", nproc, nb);
                    {
                        uint32_t r1rf = 0;
                        cpu_memory_rw_debug(cs, r1_ntbase + 0xe07ae0,
                                            (uint8_t *)&r1rf, 4, false);
                        fprintf(stderr, "R1ROOT late HvlpRootFlags=0x%x\n", r1rf);
                    }
                }
            }
        } else if (name == 0x90015) {
            /*
             * The guest publishes where it expects the page. winload writes
             * a VA-shaped value here that no IPA can reach; the kernel then
             * reads back GET and maps that. Alias the page at reachable
             * addresses so a reader of the published GPA sees the same zeros.
             */
            hwaddr gpa = x[5] & ~(hwaddr)0xfff;
            bool enable = x[5] & 1;

            bool aliased;

            r->val = x[5];
            status = HV_STATUS_SUCCESS;
            bql_lock(); /* memory topology change */
            aliased = virt_hv_overlay_alias(gpa, enable);
            bql_unlock();
            if (!aliased) {
                fprintf(stderr, "r1_hv_hcall: 0x90015 SET 0x%" PRIx64
                        " acknowledged, not aliased: GPA beyond the guest"
                        " physical address space; GET reports the overlay\n",
                        x[5]);
            }
        } else if (name == 0x90017) {
            /* R6: HvRegisterReferenceTsc. Populate the reference TSC page so
             * the guest reads time from CNTVCT (fast) instead of the slow
             * TimeRefCount hypercall fallback (which inflates IRQ-masked timed
             * measurements and wedges early boot). Page: {u32 seq; u32 rsvd;
             * u64 scale; s64 offset; ...}. */
            hwaddr gpa = x[5] & ~(hwaddr)0xfff;
            r->val = x[5];
            status = HV_STATUS_SUCCESS;
            if (x[5] & 1) {
                uint64_t cntfrq = ARM_CPU(cs)->gt_cntfrq_hz;
                if (cntfrq) {
                    uint8_t pg[40] = {0};
                    uint32_t seq = 1;
                    uint64_t scale = (uint64_t)(((__uint128_t)10000000ULL << 64) / cntfrq);
                    uint64_t cntvct = 0;
                    uint64_t tref = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / 100;
                    int64_t offset;
                    kvm_get_one_reg(cs, KVM_REG_ARM_TIMER_CNT, &cntvct);
                    offset = (int64_t)tref -
                             (int64_t)(uint64_t)(((__uint128_t)cntvct * scale) >> 64);
                    memcpy(pg + 0, &seq, 4);
                    memcpy(pg + 8, &scale, 8);
                    memcpy(pg + 16, &offset, 8);
                    address_space_write(&address_space_memory, gpa,
                                        MEMTXATTRS_UNSPECIFIED, pg, sizeof(pg));
                    fprintf(stderr, "r1_hv_hcall: 0x90017 ReferenceTsc gpa=0x%" PRIx64
                            " cntfrq=%" PRIu64 " scale=0x%" PRIx64 " cntvct=0x%" PRIx64
                            " tref=0x%" PRIx64 " off=0x%" PRIx64 "\n",
                            (uint64_t)gpa, cntfrq, scale, cntvct, tref, (uint64_t)offset);
                }
            }
        } else if (r) {
            if (name == 0x270 && !r->val) {
                info_report("hyperv: memory zeroing on reset policy 0x%"
                            PRIx64 " recorded, no action taken", x[5]);
            }
            r->val = x[5];
            status = HV_STATUS_SUCCESS;
        }
    }

    /*
     * HvCallNotifyPartitionEvent (memory form). The input is
     * hv_input_notify_partition_event: event at +0 and, for a root crashdump,
     * crashdump_action at +4 (hvhdk_mini.h). No TLFS copy is reachable from
     * this bench, so the status rests on the header layout and on this
     * handler saving nothing.
     */
    if (code == 0x0087) {
        uint32_t event = 0, action = 0;

        if (in_gpa) {
            address_space_read(&address_space_memory, in_gpa,
                               MEMTXATTRS_UNSPECIFIED, &event, sizeof(event));
            address_space_read(&address_space_memory, in_gpa + 4,
                               MEMTXATTRS_UNSPECIFIED, &action, sizeof(action));
        }
        /*
         * Preparation costs nothing to grant. STATE_SAVED and ENTRY assert a
         * dump was saved or entered; nothing here saved one, so success would
         * leave the guest with a false record. Refuse those two.
         */
        if (event == 2 /* ROOT_CRASHDUMP */ &&
            (action == 3 /* STATE_SAVED */ || action == 4 /* ENTRY */)) {
            status = HV_STATUS_INVALID_PARAMETER;
        } else {
            status = HV_STATUS_SUCCESS;
        }
        fprintf(stderr, "r1_hv_hcall: NOTIFY_PARTITION_EVENT event=%u"
                " crashdump_action=%u -> status=0x%" PRIx64 "\n",
                event, action, status);
    } else if (code == 0x007b) { /* HvCallGetSystemProperty, memory form.
                                  * The property is a u32 at the start of the
                                  * input block. */
        uint32_t prop = 0;

        if (in_gpa) {
            address_space_read(&address_space_memory, in_gpa,
                               MEMTXATTRS_UNSPECIFIED, &prop, sizeof(prop));
        }
        if (prop == 20 && out_gpa) {
            /* DMA guard: report it as not enabled, which is the truth. The
             * guest reads a single byte. This grants nothing. */
            uint8_t off = 0;

            address_space_write(&address_space_memory, out_gpa,
                                MEMTXATTRS_UNSPECIFIED, &off, sizeof(off));
            status = HV_STATUS_SUCCESS;
        } else if (prop == 15 && out_gpa) {
            /* HV_SYSTEM_PROPERTY_SCHEDULER_TYPE: this guest is the root
             * partition and runs the integrated (root) scheduler, so the
             * truthful answer is HV_SCHEDULER_TYPE_ROOT. Output is a u32. */
            uint32_t sched = 4; /* HV_SCHEDULER_TYPE_ROOT */

            address_space_write(&address_space_memory, out_gpa,
                                MEMTXATTRS_UNSPECIFIED, &sched, sizeof(sched));
            status = HV_STATUS_SUCCESS;
        } else {
            /* Any other property stays unanswered; guest tolerates it. */
            status = HV_STATUS_INVALID_PARAMETER;
        }
        fprintf(stderr, "r1_hv_hcall: GET_SYSTEM_PROPERTY prop=%u"
                " in=0x%" PRIx64 " out=0x%" PRIx64 " -> status=0x%" PRIx64 "\n",
                prop, in_gpa, out_gpa, status);
    } else if (code == 0x8001) { /* HvExtCallQueryCapabilities, memory form.
                                  * The extended interface exists and offers
                                  * nothing, so the mask is zero. */
        uint64_t caps = 0;

        if (out_gpa) {
            address_space_write(&address_space_memory, out_gpa,
                                MEMTXATTRS_UNSPECIFIED, &caps, sizeof(caps));
            status = HV_STATUS_SUCCESS;
        }
    } else if (code == 0x0019) {
        /*
         * The remote half of KeSweepIcacheRange: after its own
         * `ic ialluis; dsb sy; isb` the kernel asks the hypervisor to sweep the
         * other processors' instruction caches. hvdef has no name for the
         * code. On this host the guest's ic ialluis is already broadcast
         * across the inner-shareable domain by hardware, so the work is done
         * before the call arrives: success, no action.
         */
        static unsigned n_icache_sweeps;

        if (!(n_icache_sweeps++ % 8192)) {
            trace_kvm_arm_hv_icache_sweep(n_icache_sweeps - 1);
        }
        status = HV_STATUS_SUCCESS;
    } else if (code == 0x009a) { /* HvCallGetVpIndexFromApicId, rep call:
                                  * header {partition_id u64, target_vtl u8,
                                  * rsvd[7]} then one hardware id per rep;
                                  * on ARM64 the id is the MPIDR affinity. */
        struct { uint64_t partition_id; uint8_t target_vtl; uint8_t rsvd[7]; }
            hdr;
        uint64_t hwid, vp_index;
        CPUState *target = NULL, *it;

        status = HV_STATUS_INVALID_HYPERCALL_INPUT;
        if (!fast && in_gpa && out_gpa && reps == 1 &&
            address_space_read(&address_space_memory, in_gpa,
                               MEMTXATTRS_UNSPECIFIED, &hdr,
                               sizeof(hdr)) == MEMTX_OK &&
            address_space_read(&address_space_memory, in_gpa + sizeof(hdr),
                               MEMTXATTRS_UNSPECIFIED, &hwid,
                               sizeof(hwid)) == MEMTX_OK) {
            if (hdr.partition_id != HV_PARTITION_ID_SELF) {
                status = HV_STATUS_INVALID_PARTITION_ID;
            } else if (hdr.target_vtl != 0) {
                status = HV_STATUS_INVALID_PARAMETER;
            } else {
                CPU_FOREACH(it) {
                    if (ARM_CPU(it)->mp_affinity == (hwid & 0xff00ffffffULL)) {
                        target = it;
                        break;
                    }
                }
                if (target) {
                    vp_index = hyperv_vp_index(target);
                    address_space_write(&address_space_memory, out_gpa,
                                        MEMTXATTRS_UNSPECIFIED, &vp_index,
                                        sizeof(vp_index));
                    status = HV_STATUS_SUCCESS;
                } else {
                    status = HV_STATUS_INVALID_PARAMETER;
                }
            }
        }
    } else if (code == 0x0099) { /* HvCallStartVirtualProcessor, memory
                                  * form, not rep. */
        struct hv_start_vp_arm64 in;
        CPUState *target;

        status = HV_STATUS_INVALID_HYPERCALL_INPUT;
        if (!fast && !reps && in_gpa &&
            address_space_read(&address_space_memory, in_gpa,
                               MEMTXATTRS_UNSPECIFIED, &in,
                               sizeof(in)) == MEMTX_OK) {
            if (in.partition_id != HV_PARTITION_ID_SELF) {
                status = HV_STATUS_INVALID_PARTITION_ID;
            } else if (in.target_vtl != 0) {
                /* no VSM core yet: a higher VTL has nothing to run */
                qemu_log_mask(LOG_UNIMP, "hyperv: StartVirtualProcessor to "
                              "VTL %u refused\n", in.target_vtl);
                status = HV_STATUS_INVALID_PARAMETER;
            } else if (in.vp_index == HV_ANY_VP ||
                       in.vp_index == HV_VP_INDEX_SELF ||
                       !(target = qemu_get_cpu(in.vp_index))) {
                status = HV_STATUS_INVALID_VP_INDEX;
            } else {
                HvVpStartWork *w;

                bql_lock();
                if (ARM_CPU(target)->power_state != PSCI_OFF ||
                    target == cs) {
                    status = HV_STATUS_INVALID_VP_STATE;
                } else {
                    w = g_new(HvVpStartWork, 1);
                    w->in = in;
                    w->start_plane = hv_plane_vcpu(in.vp_index, 1);
                    /* claim the processor now so a second start is refused */
                    arm_set_cpu_power_state(ARM_CPU(target), PSCI_ON);
                    async_run_on_cpu(target, hv_vp_start_work,
                                     RUN_ON_CPU_HOST_PTR(w));
                    trace_kvm_arm_hv_start_vp(in.vp_index, in.pc, in.sp_elh,
                                              in.ttbr1_el1);
                    status = HV_STATUS_SUCCESS;
                }
                bql_unlock();
            }
        }
    } else if (code == 0x006f) {
        /*
         * Set-system-property class call, by its callers: the memory-form
         * sites write a property id into their input block and the fast
         * sites carry it in x1. hvdef names neither the code nor property 26.
         *
         * Property 26 is HvlUnblockDefaultDma, enlightenment slot 352 beside
         * GetDmaGuardEnabled: let devices in the default DMA domain start
         * DMA. We answered "DMA guard not enabled", so nothing was ever
         * blocked; success describes the machine as it is.
         *
         * Property 32 is HvlSetRootFaultReportingReady, slot 360: the guest
         * declares its IOMMU fault handler ready to receive reports. With no
         * guest IOMMU and no device domains there is nothing to report, so
         * acknowledging readiness commits us to nothing. Other properties
         * are refused and logged until one proves to be required.
         */
        uint32_t prop = fast ? (uint32_t)x[1] : 0;

        if (!fast && in_gpa) {
            address_space_read(&address_space_memory, in_gpa,
                               MEMTXATTRS_UNSPECIFIED, &prop, sizeof(prop));
        }
        if (fast && (prop == 26 || prop == 32)) {
            status = HV_STATUS_SUCCESS;
        } else {
            qemu_log_mask(LOG_UNIMP, "hyperv: set system property %u (%s)"
                          " refused\n", prop, fast ? "fast" : "memory");
            status = HV_STATUS_INVALID_PARAMETER;
        }
    } else if (code == 0x00aa) {
        /*
         * HvlGetDeviceCapabilities: what the hypervisor offers a PCI
         * device. Input is a device id (type 0x40 = PCI; segment, BDF) and
         * 16 zero bytes; output is 16 bytes of which the kernel reads bit 7
         * of the first word, domain transition supported. No device
         * domains, no DMA remapping, no passthrough here: all zero.
         */
        struct { uint16_t bdf; uint16_t segment; uint16_t rsvd; uint16_t type; }
            id = {0};
        uint8_t caps[16] = {0};

        status = HV_STATUS_INVALID_HYPERCALL_INPUT;
        if (!fast && in_gpa && out_gpa &&
            address_space_read(&address_space_memory, in_gpa,
                               MEMTXATTRS_UNSPECIFIED, &id,
                               sizeof(id)) == MEMTX_OK) {
            address_space_write(&address_space_memory, out_gpa,
                                MEMTXATTRS_UNSPECIFIED, caps, sizeof(caps));
            info_report("hyperv: device %04x:%02x:%02x.%u asked for"
                        " hypervisor capabilities: none", id.segment,
                        id.bdf >> 8, (id.bdf >> 3) & 0x1f, id.bdf & 7);
            status = HV_STATUS_SUCCESS;
        }
    } else if (code == 0x0108 || code == 0x0109) {
        /*
         * HvlMapDmaRanges / HvlUnmapDmaRanges: the driver names the guest
         * page ranges a device may DMA to. Each 16-byte element is a guest
         * page frame and a count, with no device-side address, so the
         * device uses the guest physical page directly. This machine has no
         * device domain and no DMA remapping, so the ranges are already
         * reachable. Accept and complete every rep.
         */
        status = HV_STATUS_INVALID_HYPERCALL_INPUT;
        if (!fast && in_gpa && reps) {
            static bool mapped, unmapped;
            bool *seen = (code == 0x0108) ? &mapped : &unmapped;

            if (!*seen) {
                uint64_t elem[2] = {0};
                address_space_read(&address_space_memory, in_gpa,
                                   MEMTXATTRS_UNSPECIFIED, elem, sizeof(elem));
                info_report("hyperv: %s %u device DMA range(s); first"
                            " element pfn 0x%" PRIx64 " pages %u"
                            " (raw 0x%016" PRIx64 " 0x%016" PRIx64 ")",
                            code == 0x0108 ? "map" : "unmap", reps,
                            elem[0], (uint32_t)elem[1], elem[0], elem[1]);
                *seen = true;
            }
            reps_completed = reps;
            status = HV_STATUS_SUCCESS;
        }
    } else if (code == 0x0046) {
        /* HvCallGetPartitionId: the caller asks for its own partition id.
         * This guest is the sole root partition, so the truthful id is 1
         * (the root partition id). No input; output is a u64 at out_gpa. */
        if (out_gpa) {
            uint64_t pid = 1;

            address_space_write(&address_space_memory, out_gpa,
                                MEMTXATTRS_UNSPECIFIED, &pid, sizeof(pid));
            status = HV_STATUS_SUCCESS;
        } else {
            status = HV_STATUS_INVALID_PARAMETER;
        }
    }

    if (code == 0x007c || code == 0x007d || code == 0x007e) {
        /* R1INTR diagnostic: dump the device-interrupt mapping input so the
         * handler field layout is verified live. hvdef RetargetDeviceInterrupt:
         * u64 partition_id, u64 device_id, InterruptEntry{u32 source,u32 rsvd,
         * u32 data[2]}, u64 rsvd, InterruptTarget{u32 vector,u32 flags,
         * u64 mask_or_format}. */
        uint64_t w[7] = {0};
        if (in_gpa &&
            cpu_memory_rw_debug(cs, in_gpa, (uint8_t *)w, sizeof(w), false) == 0) {
            fprintf(stderr, "R1INTR code=0x%x raw %016" PRIx64 " %016" PRIx64
                    " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64
                    " %016" PRIx64 "\n", code, w[0], w[1], w[2], w[3], w[4], w[5], w[6]);
            fprintf(stderr, "R1INTR code=0x%x devid=0x%" PRIx64 " entry.source=%u"
                    " msidata=0x%08x/0x%08x target.vector(LPI)=0x%08x flags=0x%08x"
                    " target=0x%" PRIx64 "\n", code, w[1], (uint32_t)w[2],
                    (uint32_t)w[3], (uint32_t)(w[3] >> 32), (uint32_t)w[5],
                    (uint32_t)(w[5] >> 32), w[6]);
        } else {
            fprintf(stderr, "R1INTR code=0x%x fast/in=0 x1=0x%" PRIx64 " x2=0x%" PRIx64
                    " x3=0x%" PRIx64 " x4=0x%" PRIx64 " x5=0x%" PRIx64 "\n",
                    code, x[1], x[2], x[3], x[4], x[5]);
        }
    }

    if (code == 0x0019) {
        /* R1IC: the icache-sweep storm spins here; dump the first 3 call
         * stacks to find the loop that waits by sweeping. */
        static int r1_ic_walks;
        if (r1_ic_walks < 3) {
            uint64_t fp = env->xregs[29];
            int depth;
            r1_ic_walks++;
            for (depth = 0; depth < 10 && fp >= 0xffff000000000000ULL; depth++) {
                uint64_t frame[2];
                uint64_t ret;
                if (cpu_memory_rw_debug(cs, fp, frame, sizeof(frame), false)) {
                    break;
                }
                ret = (frame[1] & 0xffffffffffffULL) | 0xffff800000000000ULL;
                fprintf(stderr, "R1IC walk%d d%d=0x%" PRIx64 "\n",
                        r1_ic_walks, depth, ret);
                fp = frame[0];
            }
        }
    }

    if (code == 0x006f || code == 0x0046 || code == 0x009b ||
        code == 0x007b) {
        /* R1CAP: capture the input of the refused root device-setup
         * hypercalls so we can answer precisely. in_gpa is a GPA. */
        uint64_t w[4] = {0};
        if (in_gpa) {
            address_space_read(&address_space_memory, in_gpa,
                               MEMTXATTRS_UNSPECIFIED, w, sizeof(w));
        }
        fprintf(stderr, "R1CAP code=0x%x fast=%d in=0x%" PRIx64
                " x1=0x%" PRIx64 " x2=0x%" PRIx64 " x3=0x%" PRIx64
                " inpg=%016" PRIx64 " %016" PRIx64 " %016" PRIx64
                " %016" PRIx64 "\n", code, fast, in_gpa, x[1], x[2],
                x[3], w[0], w[1], w[2], w[3]);
    }

    if (r1_ntbase) {
        /* R1LPI: cache the type-7 MSI/LPI line block, poll its bitmap each
         * hcall, and log any newly-set bit (a new LPI alloc) with its INTID
         * and the hcall context, to catch the NVMe allocating during init. */
        static uint64_t r1_t7block, r1_t7_lastbits = ~0ULL;
        if (!r1_t7block) {
            uint64_t head = r1_ntbase + 0xe05250, node = 0;
            int oc = 0;
            cpu_memory_rw_debug(cs, head, (uint8_t *)&node, 8, false);
            while (node && node != head && oc < 16) {
                uint64_t ihead = node + 264, e = 0;
                int ic = 0;
                cpu_memory_rw_debug(cs, ihead, (uint8_t *)&e, 8, false);
                while (e && e != ihead && ic < 32) {
                    uint32_t ty = 0;
                    cpu_memory_rw_debug(cs, e + 32, (uint8_t *)&ty, 4, false);
                    if (ty == 7) { r1_t7block = e; }
                    cpu_memory_rw_debug(cs, e, (uint8_t *)&e, 8, false);
                    ic++;
                }
                cpu_memory_rw_debug(cs, node, (uint8_t *)&node, 8, false);
                oc++;
            }
        }
        if (r1_t7block) {
            uint64_t buf = 0, bits = 0;
            cpu_memory_rw_debug(cs, r1_t7block + 80, (uint8_t *)&buf, 8, false);
            if (buf >= 0xffff000000000000ULL) {
                cpu_memory_rw_debug(cs, buf, (uint8_t *)&bits, 8, false);
            }
            if (r1_t7_lastbits == ~0ULL) {
                r1_t7_lastbits = bits;
            } else if (bits != r1_t7_lastbits) {
                uint64_t nw = bits & ~r1_t7_lastbits;
                int bb;
                for (bb = 0; bb < 64; bb++) {
                    if (nw & (1ULL << bb)) {
                        fprintf(stderr, "R1LPI NEW bit=%d INTID=0x%x near code=0x%x pc=0x%" PRIx64 "\n", bb, 8192 + bb, code, env->pc);
                    }
                }
                r1_t7_lastbits = bits;
            }
        }
    }

    if (code == 0x007b || code == 0x8001 || code == 0x0046 ||
        code == 0x006f || code == 0x009b ||
        code == 0x00aa || code == 0x0108 || code == 0x0109 ||
        code == 0x007c || code == 0x007d || code == 0x007e) {
        uint64_t fp = env->xregs[29];
        int depth;

        for (depth = 0; depth < 8 && fp >= 0xffff000000000000ULL; depth++) {
            uint64_t frame[2];
            uint64_t ret_addr;

            if (cpu_memory_rw_debug(cs, fp, frame, sizeof(frame), false)) {
                break;
            }
            /* Pointer authentication overwrites the top bits of a return
             * address, so restore the kernel half before reporting it. */
            ret_addr = (frame[1] & 0xffffffffffffULL) | 0xffff800000000000ULL;
            fprintf(stderr, "r1_hv_hcall: caller%d=0x%" PRIx64 "\n",
                    depth, ret_addr);
            fp = frame[0];
        }
    }

    /*
     * A code no branch above claimed falls through to the handlers
     * hv_arm_register_hcall() holds (hyperv-arm.h). Windows issues the VSM
     * setup calls on HVC #1, not on the HVC #2/#3 immediates.
     */
    /*
     * R2O diagnostic: the whole input register window of a protection-mask
     * call, before any handler sees it. The fast form carries the input
     * block and the GFN list in the general registers from x1 upward, so
     * x1 to x17 is the window the TLFS struct has to be laid over.
     */
    if (code == HVCALL_MODIFY_VTL_PROTECTION_MASK) {
        int r;

        fprintf(stderr, "R2OPROT pc=0x%" PRIx64 " vtl=%d fast=%d reps=%u"
                " varhdr=%u rep_start=%u x0=0x%" PRIx64 "\n", env->pc,
                active_vtl(cs), fast, reps, varhdr,
                (unsigned)((x[0] >> 48) & 0xfff), x[0]);
        for (r = 1; r <= 17; r++) {
            fprintf(stderr, "R2OPROT   x%-2d=0x%" PRIx64 "\n", r,
                    env->xregs[r]);
        }
        if (!fast) {
            uint64_t hdr[2] = { 0, 0 };
            uint64_t gfn[4] = { 0, 0, 0, 0 };

            cpu_memory_rw_debug(cs, x[1], (uint8_t *)hdr, sizeof(hdr), false);
            cpu_memory_rw_debug(cs, x[1] + sizeof(hdr), (uint8_t *)gfn,
                                sizeof(gfn), false);
            fprintf(stderr, "R2OPROT   mem hdr0=0x%" PRIx64 " hdr1=0x%" PRIx64
                    " gfn[0..3]=0x%" PRIx64 " 0x%" PRIx64 " 0x%" PRIx64
                    " 0x%" PRIx64 "\n", hdr[0], hdr[1], gfn[0], gfn[1],
                    gfn[2], gfn[3]);
        }
    }

    if (status == HV_STATUS_INVALID_HYPERCALL_CODE) {
        hv_arm_hcall_fn fn = hv_arm_hcall_handler(code);

        if (fn) {
            uint64_t res = fn(cs, run);

            status = res & 0xffff;
            /*
             * reps_completed keeps its default for a simple call: the guest
             * asks for no reps on 0x000d and 0x000f, so their x0 is
             * unchanged.
             */
            if (reps) {
                reps_completed = (res >> HV_HYPERCALL_REP_COMP_OFFSET) & 0xfff;
            }
        }
    }

    /*
     * A register name no branch in the two ladders above claimed falls
     * through to the VSM core the same way. Both ladders open with
     * HV_STATUS_INVALID_PARAMETER and every branch that claims a name sets
     * HV_STATUS_SUCCESS, so that status here means the name is unclaimed,
     * and the core answers an unknown name with INVALID_PARAMETER too.
     *
     * Fast form input is the TLFS block from x1 upward (hvgdk_mini
     * hv_input_get_vp_registers, hv_input_set_vp_registers and
     * hv_register_assoc): x1 the partition, x2 the VP index in its low half
     * and the input VTL in byte 4, x3 the name, and on a set x5 and x6 the
     * 128-bit value. The memory form is not served; no boot has used it for
     * these two codes.
     */
    if (fast && (code == 0x0050 || code == 0x0051) &&
        status == HV_STATUS_INVALID_PARAMETER &&
        x[1] == HV_PARTITION_ID_SELF) {
        union hv_input_vtl in_vtl = { .as_uint8 = (x[2] >> 32) & 0xff };
        uint64_t value[2] = { x[5], x[6] };
        uint32_t vp = (uint32_t)x[2];
        int vtl;

        if (input_vtl_targets(in_vtl)) {
            vtl = in_vtl.target_vtl;
        } else {
            vtl = active_vtl(cs);
        }
        if (vp == HV_VP_INDEX_SELF) {
            vp = hyperv_vp_index(cs);
        }

        if (vtl > active_vtl(cs)) {
            /* a lower VTL may not reach a higher one's registers */
            status = HV_STATUS_INVALID_VP_STATE;
        } else {
            status = hv_arm_vp_register_fallback(code == 0x0051, vp, vtl,
                                                 name, value);
            if (code == 0x0050 && status == HV_STATUS_SUCCESS) {
                lo = value[0];
                hi = value[1];
            }
        }
    }

    /* One line per call, after every decision, so the status printed is the
     * status returned. The register name only exists in the fast form of the
     * register calls. */
    if (code != 0x0019) { /* 0x19 fires tens of thousands of times during
                            * boot-driver relocation; logging each throttles
                            * the boot. Count-only below. */
    fprintf(stderr, "r1_hv_hcall: pc=0x%" PRIx64 " vtl=%d code=0x%04x fast=%d"
            " reps=%u varhdr=%u in=0x%" PRIx64 " out=0x%" PRIx64,
            env->pc, active_vtl(cs), code, fast, reps, varhdr, in_gpa,
            out_gpa);
    if (fast && (code == 0x0050 || code == 0x0051)) {
        fprintf(stderr, " name=0x%x part=0x%" PRIx64 " vpvtl=0x%" PRIx64
                " x5=0x%" PRIx64 " x6=0x%" PRIx64,
                name, x[1], x[2], x[5], x[6]);
    }
    fprintf(stderr, " -> status=0x%" PRIx64 " repsdone=%" PRIu64
            " lo=0x%" PRIx64 " hi=0x%" PRIx64 "%s\n", status, reps_completed,
            lo, hi, status != HV_STATUS_SUCCESS ? " REFUSED" : "");
    }
    if ((code == 0x50 || code == 0x51) &&
        ((name >= 0x200 && name <= 0x20f) || name == 0x90007)) {
        uint64_t r1lr = (env->xregs[30] & 0xffffffffffffULL) | 0xffff800000000000ULL;
        fprintf(stderr, "R1FEAT code=0x%x name=0x%x lo=0x%" PRIx64
                " caller=0x%" PRIx64 "\n", code, name, lo, r1lr);
    }
    if ((code == 0x50 || code == 0x51) && name == 0x200 &&
        (env->pc >> 40) == 0xfffff8) {
        r2_k200_reads++;
    }

    {
        /* diagnostic: pause once at the first kernel-space HVC so a debugger
         * can set a breakpoint before the early boot fault, and print the
         * ASLR'd ntoskrnl base found by walking down to its MZ header. */
        static bool r1_anchored;
        if (!r1_anchored && (env->pc >> 40) == 0xfffff8) {
            uint64_t a = env->pc & ~0xffffULL;
            int k;
            for (k = 0; k < 4096; k++) {
                uint8_t mz[2];
                if (cpu_memory_rw_debug(cs, a, mz, 2, false) == 0 &&
                    mz[0] == 'M' && mz[1] == 'Z') {
                    fprintf(stderr, "r1_hv_hcall: R1 NTBASE=0x%" PRIx64 "\n", a);
                    r1_ntbase = a;
                    {
                        uint32_t r1rf = 0;
                        cpu_memory_rw_debug(cs, a + 0xe07ae0,
                                            (uint8_t *)&r1rf, 4, false);
                        fprintf(stderr, "R1ROOT early HvlpRootFlags=0x%x\n", r1rf);
                    }
                    break;
                }
                a -= 0x10000;
            }
            r1_anchored = true;
            if (getenv("QEMU_R2_VSMGATE_PROBE") && r1_ntbase && !r2_gate_addr) {
                /* overwrite the tbz w8,#8 at HvlEnableVsmCalls+0x14 with an
                 * HVC #4 so the gate traps once; the real tbz is restored and
                 * re-executed from the trap. */
                uint64_t ga = r1_ntbase + 0xb42d2c;
                uint32_t hvc4 = 0xd4000082; /* HVC #4 */
                if (cpu_memory_rw_debug(cs, ga, (uint8_t *)&r2_gate_orig, 4,
                                        false) == 0 &&
                    r2_gate_orig == 0x36400108 /* tbz w8,#8,.+0x20 */) {
                    cpu_memory_rw_debug(cs, ga, (uint8_t *)&hvc4, 4, true);
                    r2_gate_addr = ga;
                    fprintf(stderr, "R2GATE armed at 0x%" PRIx64
                            " (orig 0x%x)\n", ga, r2_gate_orig);
                }
                {   /* positive control: HviGetHypervisorFeatures entry, which
                     * runs on every later 0x200 read; if this traps, writes to
                     * ntoskrnl .text are seen and the gate miss is real. */
                    uint64_t ca = r1_ntbase + 0x591690;
                    uint32_t hvc5 = 0xd40000a2; /* HVC #5 */
                    if (cpu_memory_rw_debug(cs, ca, (uint8_t *)&r2_ctrl_orig, 4,
                                            false) == 0 &&
                        r2_ctrl_orig == 0xd503237f /* paciasp */) {
                        cpu_memory_rw_debug(cs, ca, (uint8_t *)&hvc5, 4, true);
                        r2_ctrl_addr = ca;
                        fprintf(stderr, "R2CTRL armed at 0x%" PRIx64 "\n", ca);
                    }
                }
            } else {
                qemu_system_vmstop_request(RUN_STATE_PAUSED);
            }
        }
    }

    env->xregs[0] = (reps_completed << 32) | status;
    if (code == 0x0050 && status == HV_STATUS_SUCCESS) {
        /*
         * One 128-bit value is one output pair, so it lands in x15/x16.
         * x1 to x4 carry this call's input and are left alone: no stub in
         * bootmgfw, winload, securekernel or ntoskrnl reads an output from
         * them, and TLFS keeps fast input registers unmodified.
         */
        uint64_t val[2] = { lo, hi };
        unsigned pairs = 1;

        if (reps_completed > pairs) {
            warn_report_once("hyperv: fast register read completed %" PRIu64
                             " reps but writes %u output pair(s)",
                             reps_completed, pairs);
        }
        if (!hv_arm_fast_out(env->xregs, val, pairs)) {
            warn_report_once("hyperv: %u fast output pair(s) do not fit"
                             " x1 to x16", pairs);
        }
    }
}

int kvm_arch_handle_exit(CPUState *cs, struct kvm_run *run)
{
    ARMCPU *cpu = ARM_CPU(cs);
    int ret = 0;

    /* HVC #2/#3 (VSM VTL call/return) before the SMCCC hypercall path */
    if (run->exit_reason == KVM_EXIT_HYPERCALL &&
        (run->hypercall.flags & KVM_HYPERCALL_EXIT_HVC_IMM)) {
        return kvm_arm_handle_hypercall(cs, run);
    }

    switch (run->exit_reason) {
    case KVM_EXIT_DEBUG:
        if (kvm_arm_handle_debug(cpu, &run->debug.arch)) {
            ret = EXCP_DEBUG;
        } /* otherwise return to guest */
        break;
    case KVM_EXIT_ARM_NISV:
        /* External DABT with no valid iss to decode */
        ret = kvm_arm_handle_dabt_nisv(cpu, run->arm_nisv.esr_iss,
                                       run->arm_nisv.fault_ipa);
        break;
    case KVM_EXIT_MEMORY_FAULT:
        /* RWX fault on a VTL-protected page (kvm-all.c keeps the others) */
        if (!(run->memory_fault.flags & KVM_MEMORY_EXIT_FLAG_PLANE) ||
            run->memory_fault.plane != cs->kvm_plane) {
            error_report("KVM_EXIT_MEMORY_FAULT: access fault outside the "
                         "plane attributes (flags 0x%" PRIx64 ", plane %u on "
                         "plane %d)", (uint64_t)run->memory_fault.flags,
                         run->memory_fault.plane, cs->kvm_plane);
            ret = -1;
            break;
        }
        ret = kvm_hv_handle_fault(cs, run->memory_fault.gpa,
                                  run->memory_fault.size,
                                  run->memory_fault.flags);
        break;
    case KVM_EXIT_PLANE_EVENT:
        ret = hv_plane_vtl_event(cs, run);
        break;
    case KVM_EXIT_HYPERCALL:
        r1_hv_hcall_log(cs, run);
        break;
    default:
        qemu_log_mask(LOG_UNIMP, "%s: un-handled exit reason %d\n",
                      __func__, run->exit_reason);
        break;
    }
    return ret;
}

bool kvm_arch_stop_on_emulation_error(CPUState *cs)
{
    return true;
}

int kvm_arch_process_async_events(CPUState *cs)
{
    return 0;
}

/**
 * kvm_arm_hw_debug_active:
 * @cpu: ARMCPU
 *
 * Return: TRUE if any hardware breakpoints in use.
 */
static bool kvm_arm_hw_debug_active(ARMCPU *cpu)
{
    return ((cur_hw_wps > 0) || (cur_hw_bps > 0));
}

/**
 * kvm_arm_copy_hw_debug_data:
 * @ptr: kvm_guest_debug_arch structure
 *
 * Copy the architecture specific debug registers into the
 * kvm_guest_debug ioctl structure.
 */
static void kvm_arm_copy_hw_debug_data(struct kvm_guest_debug_arch *ptr)
{
    int i;
    memset(ptr, 0, sizeof(struct kvm_guest_debug_arch));

    for (i = 0; i < max_hw_wps; i++) {
        HWWatchpoint *wp = get_hw_wp(i);
        ptr->dbg_wcr[i] = wp->wcr;
        ptr->dbg_wvr[i] = wp->wvr;
    }
    for (i = 0; i < max_hw_bps; i++) {
        HWBreakpoint *bp = get_hw_bp(i);
        ptr->dbg_bcr[i] = bp->bcr;
        ptr->dbg_bvr[i] = bp->bvr;
    }
}

void kvm_arch_update_guest_debug(CPUState *cs, struct kvm_guest_debug *dbg)
{
    if (kvm_sw_breakpoints_active(cs)) {
        dbg->control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP;
    }
    if (kvm_arm_hw_debug_active(ARM_CPU(cs))) {
        dbg->control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW;
        kvm_arm_copy_hw_debug_data(&dbg->arch);
    }
}

void kvm_arch_init_irq_routing(KVMState *s)
{
}

int kvm_arch_irqchip_create(KVMState *s)
{
    if (kvm_kernel_irqchip_split()) {
        error_report("-machine kernel_irqchip=split is not supported on ARM.");
        exit(1);
    }

    /* If we can create the VGIC using the newer device control API, we
     * let the device do this when it initializes itself, otherwise we
     * fall back to the old API */
    return kvm_check_extension(s, KVM_CAP_DEVICE_CTRL);
}

int kvm_arm_vgic_probe(void)
{
    int val = 0;

    if (kvm_create_device(kvm_state,
                          KVM_DEV_TYPE_ARM_VGIC_V3, true) == 0) {
        val |= KVM_ARM_VGIC_V3;
    }
    if (kvm_create_device(kvm_state,
                          KVM_DEV_TYPE_ARM_VGIC_V2, true) == 0) {
        val |= KVM_ARM_VGIC_V2;
    }
    return val;
}

int kvm_arm_set_irq(int cpu, int irqtype, int irq, int level)
{
    int kvm_irq = (irqtype << KVM_ARM_IRQ_TYPE_SHIFT) | irq;
    int cpu_idx1 = cpu % 256;
    int cpu_idx2 = cpu / 256;

    kvm_irq |= (cpu_idx1 << KVM_ARM_IRQ_VCPU_SHIFT) |
               (cpu_idx2 << KVM_ARM_IRQ_VCPU2_SHIFT);

    return kvm_set_irq(kvm_state, kvm_irq, !!level);
}

int kvm_arch_fixup_msi_route(struct kvm_irq_routing_entry *route,
                             uint64_t address, uint32_t data, PCIDevice *dev)
{
    AddressSpace *as = pci_device_iommu_address_space(dev);
    hwaddr xlat, len, doorbell_gpa;
    MemoryRegionSection mrs;
    MemoryRegion *mr;

    if (as == &address_space_memory) {
        return 0;
    }

    /*
     * We do have an IOMMU address space, but for some vIOMMU implementations
     * (e.g. accelerated SMMUv3) the translation tables are programmed into
     * the physical SMMUv3 in the host (nested S1=guest, S2=host). QEMU cannot
     * walk these tables in a safe way, so in that case we obtain the MSI
     * doorbell GPA directly from the vIOMMU backend and ignore the gIOVA
     * @address.
     */
    if (pci_device_iommu_msi_direct_gpa(dev, &doorbell_gpa)) {
        goto set_doorbell;
    }

    /* MSI doorbell address is translated by an IOMMU */

    rcu_read_lock();

    mr = address_space_translate(as, address, &xlat, &len, true,
                                 MEMTXATTRS_UNSPECIFIED);

    if (!mr) {
        rcu_read_unlock();
        return 1;
    }

    mrs = memory_region_find(mr, xlat, 1);

    if (!mrs.mr) {
        rcu_read_unlock();
        return 1;
    }

    doorbell_gpa = mrs.offset_within_address_space;
    memory_region_unref(mrs.mr);
    rcu_read_unlock();

set_doorbell:
    route->u.msi.address_lo = doorbell_gpa;
    route->u.msi.address_hi = doorbell_gpa >> 32;

    trace_kvm_arm_fixup_msi_route(address, doorbell_gpa);

    return 0;
}

int kvm_arch_add_msi_route_post(struct kvm_irq_routing_entry *route,
                                int vector, PCIDevice *dev)
{
    return 0;
}

int kvm_arch_release_virq_post(int virq)
{
    return 0;
}

int kvm_arch_msi_data_to_gsi(uint32_t data)
{
    return (data - 32) & 0xffff;
}

static void kvm_arch_get_eager_split_size(Object *obj, Visitor *v,
                                          const char *name, void *opaque,
                                          Error **errp)
{
    KVMState *s = KVM_STATE(obj);
    uint64_t value = s->kvm_eager_split_size;

    visit_type_size(v, name, &value, errp);
}

static void kvm_arch_set_eager_split_size(Object *obj, Visitor *v,
                                          const char *name, void *opaque,
                                          Error **errp)
{
    KVMState *s = KVM_STATE(obj);
    uint64_t value;

    if (s->fd != -1) {
        error_setg(errp, "Unable to set early-split-size after KVM has been initialized");
        return;
    }

    if (!visit_type_size(v, name, &value, errp)) {
        return;
    }

    if (value && !is_power_of_2(value)) {
        error_setg(errp, "early-split-size must be a power of two");
        return;
    }

    s->kvm_eager_split_size = value;
}

void kvm_arch_accel_class_init(ObjectClass *oc)
{
    object_class_property_add(oc, "eager-split-size", "size",
                              kvm_arch_get_eager_split_size,
                              kvm_arch_set_eager_split_size, NULL, NULL);

    object_class_property_set_description(oc, "eager-split-size",
        "Eager Page Split chunk size for hugepages. (default: 0, disabled)");
}

int kvm_arch_insert_gdbstub_hw_breakpoint(vaddr addr, vaddr len,
                                          GdbBreakpointType type)
{
    switch (type) {
    case GDB_BREAKPOINT_HW:
        return insert_hw_breakpoint(addr);
        break;
    case GDB_WATCHPOINT_READ:
    case GDB_WATCHPOINT_WRITE:
    case GDB_WATCHPOINT_ACCESS:
        return insert_gdbstub_hw_watchpoint(addr, len, type);
    default:
        return -ENOSYS;
    }
}

int kvm_arch_remove_gdbstub_hw_breakpoint(vaddr addr, vaddr len,
                                          GdbBreakpointType type)
{
    switch (type) {
    case GDB_BREAKPOINT_HW:
        return delete_hw_breakpoint(addr);
    case GDB_WATCHPOINT_READ:
    case GDB_WATCHPOINT_WRITE:
    case GDB_WATCHPOINT_ACCESS:
        return delete_gdbstub_hw_watchpoint(addr, len, type);
    default:
        return -ENOSYS;
    }
}

void kvm_arch_remove_all_gdbstub_hw_breakpoints(void)
{
    if (cur_hw_wps > 0) {
        g_array_remove_range(hw_watchpoints, 0, cur_hw_wps);
    }
    if (cur_hw_bps > 0) {
        g_array_remove_range(hw_breakpoints, 0, cur_hw_bps);
    }
}

static bool kvm_arm_set_device_attr(ARMCPU *cpu, struct kvm_device_attr *attr,
                                    const char *name)
{
    int err;

    err = kvm_vcpu_ioctl(CPU(cpu), KVM_HAS_DEVICE_ATTR, attr);
    if (err != 0) {
        error_report("%s: KVM_HAS_DEVICE_ATTR: %s", name, strerror(-err));
        return false;
    }

    err = kvm_vcpu_ioctl(CPU(cpu), KVM_SET_DEVICE_ATTR, attr);
    if (err != 0) {
        error_report("%s: KVM_SET_DEVICE_ATTR: %s", name, strerror(-err));
        return false;
    }

    return true;
}

void kvm_arm_pmu_init(ARMCPU *cpu)
{
    struct kvm_device_attr attr = {
        .group = KVM_ARM_VCPU_PMU_V3_CTRL,
        .attr = KVM_ARM_VCPU_PMU_V3_INIT,
    };

    if (!cpu->has_pmu) {
        return;
    }
    if (!kvm_arm_set_device_attr(cpu, &attr, "PMU")) {
        error_report("failed to init PMU");
        abort();
    }
}

void kvm_arm_pmu_set_irq(ARMCPU *cpu, int irq)
{
    struct kvm_device_attr attr = {
        .group = KVM_ARM_VCPU_PMU_V3_CTRL,
        .addr = (intptr_t)&irq,
        .attr = KVM_ARM_VCPU_PMU_V3_IRQ,
    };

    if (!cpu->has_pmu) {
        return;
    }
    if (!kvm_arm_set_device_attr(cpu, &attr, "PMU")) {
        error_report("failed to set irq for PMU");
        abort();
    }
    cpu->kvm_pmu_irq = irq;
}

void kvm_arm_pvtime_init(ARMCPU *cpu, uint64_t ipa)
{
    struct kvm_device_attr attr = {
        .group = KVM_ARM_VCPU_PVTIME_CTRL,
        .attr = KVM_ARM_VCPU_PVTIME_IPA,
        .addr = (uint64_t)&ipa,
    };

    if (cpu->kvm_steal_time == ON_OFF_AUTO_OFF) {
        return;
    }
    if (!kvm_arm_set_device_attr(cpu, &attr, "PVTIME IPA")) {
        error_report("failed to init PVTIME IPA");
        abort();
    }
}

void kvm_arm_steal_time_finalize(ARMCPU *cpu, Error **errp)
{
    bool has_steal_time = kvm_check_extension(kvm_state, KVM_CAP_STEAL_TIME);

    if (cpu->kvm_steal_time == ON_OFF_AUTO_AUTO) {
        if (!has_steal_time || !arm_feature(&cpu->env, ARM_FEATURE_AARCH64)) {
            cpu->kvm_steal_time = ON_OFF_AUTO_OFF;
        } else {
            cpu->kvm_steal_time = ON_OFF_AUTO_ON;
        }
    } else if (cpu->kvm_steal_time == ON_OFF_AUTO_ON) {
        if (!has_steal_time) {
            error_setg(errp, "'kvm-steal-time' cannot be enabled "
                             "on this host");
            return;
        } else if (!arm_feature(&cpu->env, ARM_FEATURE_AARCH64)) {
            /*
             * DEN0057A chapter 2 says "This specification only covers
             * systems in which the Execution state of the hypervisor
             * as well as EL1 of virtual machines is AArch64.". And,
             * to ensure that, the smc/hvc calls are only specified as
             * smc64/hvc64.
             */
            error_setg(errp, "'kvm-steal-time' cannot be enabled "
                             "for AArch32 guests");
            return;
        }
    }
}

bool kvm_arm_aarch32_supported(void)
{
    return kvm_check_extension(kvm_state, KVM_CAP_ARM_EL1_32BIT);
}

bool kvm_arm_el2_supported(void)
{
    return kvm_check_extension(kvm_state, KVM_CAP_ARM_EL2);
}

bool kvm_arm_mte_supported(void)
{
    return kvm_check_extension(kvm_state, KVM_CAP_ARM_MTE);
}

QEMU_BUILD_BUG_ON(KVM_ARM64_SVE_VQ_MIN != 1);

static int kvm_arm_sve_set_vls(ARMCPU *cpu)
{
    uint64_t vls[KVM_ARM64_SVE_VLS_WORDS] = { cpu->sve_vq.map };

    assert(cpu->sve_max_vq <= KVM_ARM64_SVE_VQ_MAX);

    return kvm_set_one_reg(CPU(cpu), KVM_REG_ARM64_SVE_VLS, &vls[0]);
}

#define ARM_CPU_ID_MPIDR       3, 0, 0, 0, 5

int kvm_arch_pre_create_vcpu(CPUState *cpu, Error **errp)
{
    return 0;
}

int kvm_arch_init_vcpu(CPUState *cs)
{
    int ret;
    uint64_t mpidr;
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;
    uint64_t psciver;

    if (cpu->kvm_target == QEMU_KVM_ARM_TARGET_NONE) {
        error_report("KVM is not supported for this guest CPU type");
        return -EINVAL;
    }

    /* The planes of a VP share one virtual counter; its leader adjusts it. */
    if (!cpu_is_plane_sibling(cs)) {
        qemu_add_vm_change_state_handler(kvm_arm_vm_state_change, cpu);
    }

    /* Determine init features for this CPU */
    memset(cpu->kvm_init_features, 0, sizeof(cpu->kvm_init_features));
    if (cs->start_powered_off) {
        cpu->kvm_init_features[0] |= 1 << KVM_ARM_VCPU_POWER_OFF;
    }
    if (cpu->psci_version != QEMU_PSCI_VERSION_0_1 &&
        kvm_check_extension(cs->kvm_state, KVM_CAP_ARM_PSCI_0_2)) {
        /*
         * Versions >= v0.2 are backward compatible with v0.2
         * omit the feature flag for v0.1 .
         */
        cpu->kvm_init_features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
    }
    if (!arm_feature(env, ARM_FEATURE_AARCH64)) {
        cpu->kvm_init_features[0] |= 1 << KVM_ARM_VCPU_EL1_32BIT;
    }
    if (cpu->has_pmu) {
        cpu->kvm_init_features[0] |= 1 << KVM_ARM_VCPU_PMU_V3;
    }
    if (cpu_isar_feature(aa64_sve, cpu)) {
        cpu->kvm_init_features[0] |= 1 << KVM_ARM_VCPU_SVE;
    }
    if (cpu_isar_feature(aa64_pauth, cpu)) {
        cpu->kvm_init_features[0] |= (1 << KVM_ARM_VCPU_PTRAUTH_ADDRESS |
                                      1 << KVM_ARM_VCPU_PTRAUTH_GENERIC);
    }
    if (cpu->has_el2 && kvm_arm_el2_supported()) {
        cpu->kvm_init_features[0] |= 1 << KVM_ARM_VCPU_HAS_EL2;
    }

    /* Do KVM_ARM_VCPU_INIT ioctl */
    ret = kvm_arm_vcpu_init(cpu);
    if (ret) {
        return ret;
    }

    if (cpu_isar_feature(aa64_sve, cpu)) {
        ret = kvm_arm_sve_set_vls(cpu);
        if (ret) {
            return ret;
        }
        ret = kvm_arm_vcpu_finalize(cpu, KVM_ARM_VCPU_SVE);
        if (ret) {
            return ret;
        }
    }

    /*
     * The machine gives a plane-0 vCPU its PMU after KVM_ARM_VCPU_INIT. A
     * sibling is created later, by a hypercall, so it inherits the PMU
     * feature bit and no PMU. KVM then refuses its first KVM_RUN.
     */
    if (cpu_is_plane_sibling(cs) && cpu->has_pmu) {
        ARMCPU *leader = ARM_CPU(cs->kvm_plane_leader);

        if (leader->kvm_pmu_irq) {
            kvm_arm_pmu_set_irq(cpu, leader->kvm_pmu_irq);
        }
        kvm_arm_pmu_init(cpu);
    }

    if (cpu->psci_version) {
        psciver = cpu->psci_version;
        ret = kvm_set_one_reg(cs, KVM_REG_ARM_PSCI_VERSION, &psciver);
        if (ret) {
            error_report("KVM in this kernel does not support PSCI version %d.%d",
                         (int) PSCI_VERSION_MAJOR(psciver),
                         (int) PSCI_VERSION_MINOR(psciver));
            error_printf("Consider setting the kvm-psci-version property on the "
                         "migration source.\n");
            return ret;
        }
    }
    /*
     * KVM reports the exact PSCI version it is implementing via a
     * special sysreg. If it is present, use its contents to determine
     * what to report to the guest in the dtb (it is the PSCI version,
     * in the same 15-bits major 16-bits minor format that PSCI_VERSION
     * returns).
     */
    if (!kvm_get_one_reg(cs, KVM_REG_ARM_PSCI_VERSION, &psciver)) {
        cpu->psci_version = psciver;
    }

    /*
     * When KVM is in use, PSCI is emulated in-kernel and not by qemu.
     * Currently KVM has its own idea about MPIDR assignment, so we
     * override our defaults with what we get from KVM.
     */
    ret = kvm_get_one_reg(cs, ARM64_SYS_REG(ARM_CPU_ID_MPIDR), &mpidr);
    if (ret) {
        return ret;
    }
    cpu->mp_affinity = mpidr & ARM64_AFFINITY_MASK;

    ret = hyperv_vsm_arm_init_vcpu(cs);
    if (ret) {
        return ret;
    }

    return kvm_arm_init_cpreg_list(cpu);
}

int kvm_arch_destroy_vcpu(CPUState *cs)
{
    return 0;
}

/* Callers must hold the iothread mutex lock */
static void kvm_inject_arm_sea(CPUState *c)
{
    ARMCPU *cpu = ARM_CPU(c);
    CPUARMState *env = &cpu->env;
    uint32_t esr;
    bool same_el;

    c->exception_index = EXCP_DATA_ABORT;
    env->exception.target_el = 1;

    /*
     * Set the DFSC to synchronous external abort and set FnV to not valid,
     * this will tell guest the FAR_ELx is UNKNOWN for this abort.
     */
    same_el = arm_current_el(env) == env->exception.target_el;
    esr = syn_data_abort_no_iss(same_el, 1, 0, 0, 0, 0, 0x10);

    env->exception.syndrome = esr;

    arm_cpu_do_interrupt(c);
}

#define AARCH64_CORE_REG(x)   (KVM_REG_ARM64 | KVM_REG_SIZE_U64 | \
                 KVM_REG_ARM_CORE | KVM_REG_ARM_CORE_REG(x))

#define AARCH64_SIMD_CORE_REG(x)   (KVM_REG_ARM64 | KVM_REG_SIZE_U128 | \
                 KVM_REG_ARM_CORE | KVM_REG_ARM_CORE_REG(x))

#define AARCH64_SIMD_CTRL_REG(x)   (KVM_REG_ARM64 | KVM_REG_SIZE_U32 | \
                 KVM_REG_ARM_CORE | KVM_REG_ARM_CORE_REG(x))

static int kvm_arch_put_fpsimd(CPUState *cs)
{
    CPUARMState *env = &ARM_CPU(cs)->env;
    int i, ret;

    for (i = 0; i < 32; i++) {
        uint64_t *q = aa64_vfp_qreg(env, i);
#if HOST_BIG_ENDIAN
        uint64_t fp_val[2] = { q[1], q[0] };
        ret = kvm_set_one_reg(cs, AARCH64_SIMD_CORE_REG(fp_regs.vregs[i]),
                                                        fp_val);
#else
        ret = kvm_set_one_reg(cs, AARCH64_SIMD_CORE_REG(fp_regs.vregs[i]), q);
#endif
        if (ret) {
            return ret;
        }
    }

    return 0;
}

/*
 * KVM SVE registers come in slices where ZREGs have a slice size of 2048 bits
 * and PREGS and the FFR have a slice size of 256 bits. However we simply hard
 * code the slice index to zero for now as it's unlikely we'll need more than
 * one slice for quite some time.
 */
static int kvm_arch_put_sve(CPUState *cs, uint32_t vq, bool have_ffr)
{
    CPUARMState *env = cpu_env(cs);
    uint64_t tmp[ARM_MAX_VQ * 2];
    uint64_t *r;
    int n, ret;

    for (n = 0; n < KVM_ARM64_SVE_NUM_ZREGS; ++n) {
        r = sve_bswap64(tmp, &env->vfp.zregs[n].d[0], vq * 2);
        ret = kvm_set_one_reg(cs, KVM_REG_ARM64_SVE_ZREG(n, 0), r);
        if (ret) {
            return ret;
        }
    }

    for (n = 0; n < KVM_ARM64_SVE_NUM_PREGS; ++n) {
        r = sve_bswap64(tmp, &env->vfp.pregs[n].p[0], DIV_ROUND_UP(vq * 2, 8));
        ret = kvm_set_one_reg(cs, KVM_REG_ARM64_SVE_PREG(n, 0), r);
        if (ret) {
            return ret;
        }
    }

    if (have_ffr) {
        r = sve_bswap64(tmp, &env->vfp.pregs[FFR_PRED_NUM].p[0],
                        DIV_ROUND_UP(vq * 2, 8));
        ret = kvm_set_one_reg(cs, KVM_REG_ARM64_SVE_FFR(0), r);
        if (ret) {
            return ret;
        }
    }

    return 0;
}

int kvm_arch_put_registers(CPUState *cs, KvmPutState level, Error **errp)
{
    uint64_t val;
    uint32_t fpr;
    int i, ret;
    unsigned int el;

    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;

    /* If we are in AArch32 mode then we need to copy the AArch32 regs to the
     * AArch64 registers before pushing them out to 64-bit KVM.
     */
    if (!is_a64(env)) {
        aarch64_sync_32_to_64(env);
    }

    for (i = 0; i < 31; i++) {
        ret = kvm_set_one_reg(cs, AARCH64_CORE_REG(regs.regs[i]),
                              &env->xregs[i]);
        if (ret) {
            return ret;
        }
    }

    /* KVM puts SP_EL0 in regs.sp and SP_EL1 in regs.sp_el1. On the
     * QEMU side we keep the current SP in xregs[31] as well.
     */
    aarch64_save_sp(env, 1);

    ret = kvm_set_one_reg(cs, AARCH64_CORE_REG(regs.sp), &env->sp_el[0]);
    if (ret) {
        return ret;
    }

    ret = kvm_set_one_reg(cs, AARCH64_CORE_REG(sp_el1), &env->sp_el[1]);
    if (ret) {
        return ret;
    }

    /* Note that KVM thinks pstate is 64 bit but we use a uint32_t */
    if (is_a64(env)) {
        val = pstate_read(env);
    } else {
        val = cpsr_read(env);
    }
    ret = kvm_set_one_reg(cs, AARCH64_CORE_REG(regs.pstate), &val);
    if (ret) {
        return ret;
    }

    ret = kvm_set_one_reg(cs, AARCH64_CORE_REG(regs.pc), &env->pc);
    if (ret) {
        return ret;
    }

    ret = kvm_set_one_reg(cs, AARCH64_CORE_REG(elr_el1), &env->elr_el[1]);
    if (ret) {
        return ret;
    }

    /* Saved Program State Registers
     *
     * Before we restore from the banked_spsr[] array we need to
     * ensure that any modifications to env->spsr are correctly
     * reflected in the banks.
     */
    el = arm_current_el(env);
    if (el > 0 && !is_a64(env)) {
        i = bank_number(env->uncached_cpsr & CPSR_M);
        env->banked_spsr[i] = env->spsr;
    }

    /* KVM 0-4 map to QEMU banks 1-5 */
    for (i = 0; i < KVM_NR_SPSR; i++) {
        ret = kvm_set_one_reg(cs, AARCH64_CORE_REG(spsr[i]),
                              &env->banked_spsr[i + 1]);
        if (ret) {
            return ret;
        }
    }

    if (cpu_isar_feature(aa64_sve, cpu)) {
        ret = kvm_arch_put_sve(cs, cpu->sve_max_vq, true);
    } else {
        ret = kvm_arch_put_fpsimd(cs);
    }
    if (ret) {
        return ret;
    }

    fpr = vfp_get_fpsr(env);
    ret = kvm_set_one_reg(cs, AARCH64_SIMD_CTRL_REG(fp_regs.fpsr), &fpr);
    if (ret) {
        return ret;
    }

    fpr = vfp_get_fpcr(env);
    ret = kvm_set_one_reg(cs, AARCH64_SIMD_CTRL_REG(fp_regs.fpcr), &fpr);
    if (ret) {
        return ret;
    }

    write_cpustate_to_list(cpu, true);

    if (!write_list_to_kvmstate(cpu, level)) {
        return -EINVAL;
    }

   /*
    * Setting VCPU events should be triggered after syncing the registers
    * to avoid overwriting potential changes made by KVM upon calling
    * KVM_SET_VCPU_EVENTS ioctl
    */
    ret = kvm_put_vcpu_events(cpu);
    if (ret) {
        return ret;
    }

    return kvm_arm_sync_mpstate_to_kvm(cpu);
}

static int kvm_arch_get_fpsimd(CPUState *cs)
{
    CPUARMState *env = &ARM_CPU(cs)->env;
    int i, ret;

    for (i = 0; i < 32; i++) {
        uint64_t *q = aa64_vfp_qreg(env, i);
        ret = kvm_get_one_reg(cs, AARCH64_SIMD_CORE_REG(fp_regs.vregs[i]), q);
        if (ret) {
            return ret;
        } else {
#if HOST_BIG_ENDIAN
            uint64_t t;
            t = q[0], q[0] = q[1], q[1] = t;
#endif
        }
    }

    return 0;
}

/*
 * KVM SVE registers come in slices where ZREGs have a slice size of 2048 bits
 * and PREGS and the FFR have a slice size of 256 bits. However we simply hard
 * code the slice index to zero for now as it's unlikely we'll need more than
 * one slice for quite some time.
 */
static int kvm_arch_get_sve(CPUState *cs, uint32_t vq, bool have_ffr)
{
    CPUARMState *env = cpu_env(cs);
    uint64_t *r;
    int n, ret;

    for (n = 0; n < KVM_ARM64_SVE_NUM_ZREGS; ++n) {
        r = &env->vfp.zregs[n].d[0];
        ret = kvm_get_one_reg(cs, KVM_REG_ARM64_SVE_ZREG(n, 0), r);
        if (ret) {
            return ret;
        }
        sve_bswap64(r, r, vq * 2);
    }

    for (n = 0; n < KVM_ARM64_SVE_NUM_PREGS; ++n) {
        r = &env->vfp.pregs[n].p[0];
        ret = kvm_get_one_reg(cs, KVM_REG_ARM64_SVE_PREG(n, 0), r);
        if (ret) {
            return ret;
        }
        sve_bswap64(r, r, DIV_ROUND_UP(vq * 2, 8));
    }

    if (have_ffr) {
        r = &env->vfp.pregs[FFR_PRED_NUM].p[0];
        ret = kvm_get_one_reg(cs, KVM_REG_ARM64_SVE_FFR(0), r);
        if (ret) {
            return ret;
        }
        sve_bswap64(r, r, DIV_ROUND_UP(vq * 2, 8));
    }

    return 0;
}

int kvm_arch_get_registers(CPUState *cs, Error **errp)
{
    uint64_t val;
    unsigned int el;
    uint32_t fpr;
    int i, ret;

    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;

    for (i = 0; i < 31; i++) {
        ret = kvm_get_one_reg(cs, AARCH64_CORE_REG(regs.regs[i]),
                              &env->xregs[i]);
        if (ret) {
            return ret;
        }
    }

    ret = kvm_get_one_reg(cs, AARCH64_CORE_REG(regs.sp), &env->sp_el[0]);
    if (ret) {
        return ret;
    }

    ret = kvm_get_one_reg(cs, AARCH64_CORE_REG(sp_el1), &env->sp_el[1]);
    if (ret) {
        return ret;
    }

    ret = kvm_get_one_reg(cs, AARCH64_CORE_REG(regs.pstate), &val);
    if (ret) {
        return ret;
    }

    env->aarch64 = ((val & PSTATE_nRW) == 0);
    if (is_a64(env)) {
        pstate_write(env, val);
    } else {
        cpsr_write(env, val, 0xffffffff, CPSRWriteRaw);
    }

    /* KVM puts SP_EL0 in regs.sp and SP_EL1 in regs.sp_el1. On the
     * QEMU side we keep the current SP in xregs[31] as well.
     */
    aarch64_restore_sp(env, 1);

    ret = kvm_get_one_reg(cs, AARCH64_CORE_REG(regs.pc), &env->pc);
    if (ret) {
        return ret;
    }

    /* If we are in AArch32 mode then we need to sync the AArch32 regs with the
     * incoming AArch64 regs received from 64-bit KVM.
     * We must perform this after all of the registers have been acquired from
     * the kernel.
     */
    if (!is_a64(env)) {
        aarch64_sync_64_to_32(env);
    }

    ret = kvm_get_one_reg(cs, AARCH64_CORE_REG(elr_el1), &env->elr_el[1]);
    if (ret) {
        return ret;
    }

    /* Fetch the SPSR registers
     *
     * KVM SPSRs 0-4 map to QEMU banks 1-5
     */
    for (i = 0; i < KVM_NR_SPSR; i++) {
        ret = kvm_get_one_reg(cs, AARCH64_CORE_REG(spsr[i]),
                              &env->banked_spsr[i + 1]);
        if (ret) {
            return ret;
        }
    }

    el = arm_current_el(env);
    if (el > 0 && !is_a64(env)) {
        i = bank_number(env->uncached_cpsr & CPSR_M);
        env->spsr = env->banked_spsr[i];
    }

    if (cpu_isar_feature(aa64_sve, cpu)) {
        ret = kvm_arch_get_sve(cs, cpu->sve_max_vq, true);
    } else {
        ret = kvm_arch_get_fpsimd(cs);
    }
    if (ret) {
        return ret;
    }

    ret = kvm_get_one_reg(cs, AARCH64_SIMD_CTRL_REG(fp_regs.fpsr), &fpr);
    if (ret) {
        return ret;
    }
    vfp_set_fpsr(env, fpr);

    ret = kvm_get_one_reg(cs, AARCH64_SIMD_CTRL_REG(fp_regs.fpcr), &fpr);
    if (ret) {
        return ret;
    }
    vfp_set_fpcr(env, fpr);

    ret = kvm_get_vcpu_events(cpu);
    if (ret) {
        return ret;
    }

    if (!write_kvmstate_to_list(cpu)) {
        return -EINVAL;
    }
    /* Note that it's OK to have registers which aren't in CPUState,
     * so we can ignore a failure return here.
     */
    write_list_to_cpustate(cpu);

    ret = kvm_arm_sync_mpstate_to_qemu(cpu);

    /* TODO: other registers */
    return ret;
}

void kvm_arch_on_sigbus_vcpu(CPUState *c, int code, void *addr)
{
    ram_addr_t ram_addr;
    hwaddr paddr;
    AcpiGhesState *ags;

    assert(code == BUS_MCEERR_AR || code == BUS_MCEERR_AO);

    ags = acpi_ghes_get_state();
    if (ags && addr) {
        ram_addr = qemu_ram_addr_from_host(addr);
        if (ram_addr != RAM_ADDR_INVALID &&
            kvm_physical_memory_addr_from_host(c->kvm_state, addr, &paddr)) {
            kvm_hwpoison_page_add(ram_addr);
            /*
             * If this is a BUS_MCEERR_AR, we know we have been called
             * synchronously from the vCPU thread, so we can easily
             * synchronize the state and inject an error.
             *
             * TODO: we currently don't tell the guest at all about
             * BUS_MCEERR_AO. In that case we might either be being
             * called synchronously from the vCPU thread, or a bit
             * later from the main thread, so doing the injection of
             * the error would be more complicated.
             */
            if (code == BUS_MCEERR_AR) {
                kvm_cpu_synchronize_state(c);
                acpi_ghes_memory_errors(ags, ACPI_HEST_SRC_ID_SYNC,
                                        paddr, &error_fatal);
                kvm_inject_arm_sea(c);
            }
            return;
        }
        if (code == BUS_MCEERR_AO) {
            error_report("Hardware memory error at addr %p for memory used by "
                "QEMU itself instead of guest system!", addr);
        }
    }

    if (code == BUS_MCEERR_AR) {
        error_report("Hardware memory error!");
        exit(1);
    }
}

/* C6.6.29 BRK instruction */
static const uint32_t brk_insn = 0xd4200000;

int kvm_arch_insert_sw_breakpoint(CPUState *cs, struct kvm_sw_breakpoint *bp)
{
    if (cpu_memory_rw_debug(cs, bp->pc, (uint8_t *)&bp->saved_insn, 4, 0) ||
        cpu_memory_rw_debug(cs, bp->pc, (uint8_t *)&brk_insn, 4, 1)) {
        return -EINVAL;
    }
    return 0;
}

int kvm_arch_remove_sw_breakpoint(CPUState *cs, struct kvm_sw_breakpoint *bp)
{
    static uint32_t brk;

    if (cpu_memory_rw_debug(cs, bp->pc, (uint8_t *)&brk, 4, 0) ||
        brk != brk_insn ||
        cpu_memory_rw_debug(cs, bp->pc, (uint8_t *)&bp->saved_insn, 4, 1)) {
        return -EINVAL;
    }
    return 0;
}

void kvm_arm_enable_mte(Object *cpuobj, Error **errp)
{
    static bool tried_to_enable;
    static bool succeeded_to_enable;
    Error *mte_migration_blocker = NULL;
    ARMCPU *cpu = ARM_CPU(cpuobj);
    int ret;

    if (!tried_to_enable) {
        /*
         * MTE on KVM is enabled on a per-VM basis (and retrying doesn't make
         * sense), and we only want a single migration blocker as well.
         */
        tried_to_enable = true;

        ret = kvm_vm_enable_cap(kvm_state, KVM_CAP_ARM_MTE, 0);
        if (ret) {
            error_setg_errno(errp, -ret, "Failed to enable KVM_CAP_ARM_MTE");
            return;
        }

        /* TODO: Add migration support with MTE enabled */
        error_setg(&mte_migration_blocker,
                   "Live migration disabled due to MTE enabled");
        if (migrate_add_blocker(&mte_migration_blocker, errp)) {
            return;
        }

        succeeded_to_enable = true;
    }

    if (succeeded_to_enable) {
        cpu->kvm_mte = true;
    }
}

void arm_cpu_kvm_set_irq(void *arm_cpu, int irq, int level)
{
    ARMCPU *cpu = arm_cpu;
    CPUARMState *env = &cpu->env;
    CPUState *cs = CPU(cpu);
    uint32_t linestate_bit;
    int irq_id;

    switch (irq) {
    case ARM_CPU_IRQ:
        irq_id = KVM_ARM_IRQ_CPU_IRQ;
        linestate_bit = CPU_INTERRUPT_HARD;
        break;
    case ARM_CPU_FIQ:
        irq_id = KVM_ARM_IRQ_CPU_FIQ;
        linestate_bit = CPU_INTERRUPT_FIQ;
        break;
    default:
        g_assert_not_reached();
    }

    if (level) {
        env->irq_line_state |= linestate_bit;
    } else {
        env->irq_line_state &= ~linestate_bit;
    }
    kvm_arm_set_irq(cs->cpu_index, KVM_ARM_IRQ_TYPE_CPU, irq_id, !!level);
}

void arm_gic_cap_kvm_probe(GICCapability *v2, GICCapability *v3)
{
    int fdarray[3];

    if (!kvm_arm_create_scratch_host_vcpu(fdarray, NULL)) {
        return;
    }

    /* Test KVM GICv2 */
    if (kvm_device_supported(fdarray[1], KVM_DEV_TYPE_ARM_VGIC_V2)) {
        v2->kernel = true;
    }

    /* Test KVM GICv3 */
    if (kvm_device_supported(fdarray[1], KVM_DEV_TYPE_ARM_VGIC_V3)) {
        v3->kernel = true;
    }

    kvm_arm_destroy_scratch_host_vcpu(fdarray);
}

/*
 * KVM-based ITS implementation for a GICv3-based system
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd.
 * Written by Pavel Fedin <p.fedin@samsung.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "qemu/error-report.h"
#include "qemu/bitmap.h"
#include "qemu/bswap.h"
#include "hw/intc/arm_gicv3_its_common.h"
#include "hw/intc/arm_gicv3_its_kvm.h"
#include "hw/core/cpu.h"
#include "hw/core/qdev-properties.h"
#include "system/cpus.h"
#include "system/runstate.h"
#include "system/kvm.h"
#include "kvm_arm.h"
#include "gicv3_internal.h"
#include "migration/blocker.h"
#include "qom/object.h"
#include "trace.h"

typedef struct KVMARMITSClass KVMARMITSClass;
/* This is reusing the GICv3ITSState typedef from ARM_GICV3_ITS_COMMON */
DECLARE_OBJ_CHECKERS(GICv3ITSState, KVMARMITSClass,
                     KVM_ARM_ITS, TYPE_KVM_ARM_ITS)

struct KVMARMITSClass {
    GICv3ITSCommonClass parent_class;
    ResettablePhases parent_phases;
};


static int kvm_its_send_msi(GICv3ITSState *s, uint32_t value, uint16_t devid)
{
    struct kvm_msi msi;

    if (unlikely(!s->translater_gpa_known)) {
        MemoryRegion *mr = &s->iomem_its_translation;
        MemoryRegionSection mrs;

        mrs = memory_region_find(mr, 0, 1);
        memory_region_unref(mrs.mr);
        s->gits_translater_gpa = mrs.offset_within_address_space + 0x40;
        s->translater_gpa_known = true;
    }

    msi.address_lo = extract64(s->gits_translater_gpa, 0, 32);
    msi.address_hi = extract64(s->gits_translater_gpa, 32, 32);
    msi.data = value;
    msi.flags = KVM_MSI_VALID_DEVID;
    msi.devid = devid;
    memset(msi.pad, 0, sizeof(msi.pad));

    return kvm_vm_ioctl(kvm_state, KVM_SIGNAL_MSI, &msi);
}

/*
 * QEMU-programmed ITS. KVM reads the tables through memslots and supports
 * only 64 KiB ITS pages. The block mapped as sysbus MMIO 1 holds a two-level
 * device table covering every 16-bit DeviceID, the collection table, the
 * command queue, one ITT per device sized for the MSI-X maximum (so a MAPD
 * needs no device lookup), the LPI configuration and pending tables.
 *
 * KVM returns -EBUSY for GITS register access while a vCPU is in KVM_RUN,
 * so each call pauses all vCPUs. KVM reports command errors only in its own
 * log, so its range checks are repeated here before a command is queued.
 */

#define ITS_KVM_PAGE            0x10000
#define ITS_KVM_DT_L1_OFF       0
#define ITS_KVM_DT_L2_OFF       ITS_KVM_PAGE
#define ITS_KVM_DT_L2_PAGES     8      /* 65536 DeviceIDs, 8192 per page */
#define ITS_KVM_CT_OFF          (ITS_KVM_DT_L2_OFF + \
                                 ITS_KVM_DT_L2_PAGES * ITS_KVM_PAGE)
#define ITS_KVM_CQ_OFF          (ITS_KVM_CT_OFF + ITS_KVM_PAGE)
#define ITS_KVM_CQ_SIZE         ITS_KVM_PAGE
#define ITS_KVM_ITT_OFF         (ITS_KVM_CQ_OFF + ITS_KVM_CQ_SIZE)
#define ITS_KVM_EVENT_BITS      11
#define ITS_KVM_ITE_SIZE        8      /* KVM ABI revision 0 */
#define ITS_KVM_ITT_SIZE        (ITS_KVM_ITE_SIZE << ITS_KVM_EVENT_BITS)
#define ITS_KVM_DEVICES         64
#define ITS_KVM_COLLECTIONS     (ITS_KVM_PAGE / 8)
#define ITS_KVM_MAX_DEVID       0x10000
#define ITS_KVM_LPI_BASE        8192
#define ITS_KVM_CMD_SIZE        32
/* GICR_PENDBASER holds PA[51:16], so each vCPU's pending table takes 64K */
#define ITS_KVM_IDBITS          16
#define ITS_KVM_PROP_OFF        (ITS_KVM_ITT_OFF + \
                                 ITS_KVM_DEVICES * ITS_KVM_ITT_SIZE)
#define ITS_KVM_PROP_SIZE       ((1 << ITS_KVM_IDBITS) - ITS_KVM_LPI_BASE)
#define ITS_KVM_PEND_OFF        (ITS_KVM_PROP_OFF + ITS_KVM_PAGE)
#define ITS_KVM_PEND_SIZE       ITS_KVM_PAGE
#define ITS_KVM_MAX_CPUS        ((ITS_KVM_TABLES_SIZE - ITS_KVM_PEND_OFF) / \
                                 ITS_KVM_PEND_SIZE)
/* LPI configuration byte: enable, res1, priority in [7:2] (GICv3 6.1.1) */
#define ITS_KVM_LPI_PROP_ON     (0xa0 | 0x2 | 0x1)
#define ITS_KVM_LPI_PROP_OFF    0x2

QEMU_BUILD_BUG_ON(ITS_KVM_PROP_SIZE > ITS_KVM_PAGE);
QEMU_BUILD_BUG_ON(ITS_KVM_PEND_OFF + ITS_KVM_PEND_SIZE > ITS_KVM_TABLES_SIZE);

/* GITS_BASER/GITS_CBASER attribute bits (GICv3, 12.18.4 and 12.18.5) */
#define ITS_KVM_INNER_SHAREABLE (1ULL << 10)
#define ITS_KVM_BASER_RAWAWB    (7ULL << 59)

/* KVM_DEV_ARM_VGIC_GRP_REDIST_REGS attribute: MPIDR in the top half */
#define ITS_KVM_REDIST_ATTR(reg, typer) \
    (((typer) & KVM_DEV_ARM_VGIC_V3_MPIDR_MASK) | (reg))

typedef struct ItsKvm {
    GICv3ITSState *its;
    MemoryRegion tables;
    hwaddr base;                        /* GPA of @tables once mapped */
    bool programmed;
    uint32_t cwriter;
    unsigned cmds;                      /* queued since the last flush */
    unsigned long itts[BITS_TO_LONGS(ITS_KVM_DEVICES)];
    unsigned long collections[BITS_TO_LONGS(ITS_KVM_COLLECTIONS)];
    GHashTable *dev_itt;                /* devid -> ITT slot + 1 */
    GHashTable *lpis;                   /* devid << 16 | event -> lpi */
} ItsKvm;

static ItsKvm its_kvm;

static void *its_kvm_ram(hwaddr off)
{
    return (uint8_t *)memory_region_get_ram_ptr(&its_kvm.tables) + off;
}

/* hash keys: never 0, so a lookup miss is distinct from a stored value */
static gpointer its_kvm_dev_key(uint32_t devid)
{
    return GUINT_TO_POINTER(devid + 1);
}

static gpointer its_kvm_lpi_key(uint32_t devid, uint32_t event)
{
    return GUINT_TO_POINTER((devid << 16 | event) + 1);
}

static bool its_kvm_init(GICv3ITSState *s, Error **errp)
{
    if (its_kvm.its) {
        error_setg(errp, "only one ITS can be programmed by QEMU");
        return false;
    }
    if (s->gicv3->num_cpu > ITS_KVM_MAX_CPUS) {
        error_setg(errp, "its-kvm-tables hold LPI pending tables for %d vCPUs",
                   ITS_KVM_MAX_CPUS);
        return false;
    }
    if (!memory_region_init_ram(&its_kvm.tables, OBJECT(s), "its-kvm-tables",
                                ITS_KVM_TABLES_SIZE, errp)) {
        return false;
    }
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &its_kvm.tables);

    its_kvm.its = s;
    its_kvm.dev_itt = g_hash_table_new(NULL, NULL);
    its_kvm.lpis = g_hash_table_new(NULL, NULL);
    return true;
}

static void its_kvm_reset(GICv3ITSState *s)
{
    if (its_kvm.its != s) {
        return;
    }
    its_kvm.programmed = false;
    its_kvm.cwriter = 0;
    its_kvm.cmds = 0;
    bitmap_zero(its_kvm.itts, ITS_KVM_DEVICES);
    bitmap_zero(its_kvm.collections, ITS_KVM_COLLECTIONS);
    g_hash_table_remove_all(its_kvm.dev_itt);
    g_hash_table_remove_all(its_kvm.lpis);
    memset(its_kvm_ram(ITS_KVM_PROP_OFF), ITS_KVM_LPI_PROP_OFF,
           ITS_KVM_PROP_SIZE);
    memset(its_kvm_ram(ITS_KVM_PEND_OFF), 0,
           s->gicv3->num_cpu * ITS_KVM_PEND_SIZE);
}

static bool its_kvm_find_base(void)
{
    MemoryRegionSection mrs;

    if (its_kvm.base) {
        return true;
    }
    mrs = memory_region_find(&its_kvm.tables, 0, 1);
    memory_region_unref(mrs.mr);
    if (!mrs.mr) {
        error_report("its-kvm-tables is not mapped");
        return false;
    }
    its_kvm.base = mrs.offset_within_address_space;
    return true;
}

static uint64_t its_kvm_propbaser(void)
{
    return (its_kvm.base + ITS_KVM_PROP_OFF) |
           FIELD_DP64(0, GICR_PROPBASER, IDBITS, ITS_KVM_IDBITS - 1) |
           FIELD_DP64(0, GICR_PROPBASER, INNERCACHE, 7) |
           FIELD_DP64(0, GICR_PROPBASER, SHAREABILITY, 1);
}

static uint64_t its_kvm_pendbaser(int cpu)
{
    return (its_kvm.base + ITS_KVM_PEND_OFF + cpu * ITS_KVM_PEND_SIZE) |
           FIELD_DP64(0, GICR_PENDBASER, INNERCACHE, 7) |
           FIELD_DP64(0, GICR_PENDBASER, SHAREABILITY, 1) |
           FIELD_DP64(0, GICR_PENDBASER, PTZ, 1);
}

/* KVM_DEV_ARM_VGIC_GRP_REDIST_REGS takes 32-bit halves */
static int its_kvm_redist_access(int cpu, uint32_t reg, uint64_t *val,
                                 bool write)
{
    GICv3State *gic = its_kvm.its->gicv3;
    uint64_t typer = gic->cpu[cpu].gicr_typer;
    uint32_t lo = *val, hi = *val >> 32;
    Error *err = NULL;
    int ret;

    ret = kvm_device_access(gic->dev_fd, KVM_DEV_ARM_VGIC_GRP_REDIST_REGS,
                            ITS_KVM_REDIST_ATTR(reg, typer), &lo, write, &err);
    if (ret == 0) {
        ret = kvm_device_access(gic->dev_fd, KVM_DEV_ARM_VGIC_GRP_REDIST_REGS,
                                ITS_KVM_REDIST_ATTR(reg + 4, typer), &hi,
                                write, &err);
    }
    if (ret < 0) {
        error_report_err(err);
        return ret;
    }
    *val = (uint64_t)hi << 32 | lo;
    return 0;
}

/*
 * KVM ignores the write once GICR_CTLR.EnableLPIs is set, so this runs at
 * reset, after the GIC (the earlier sysbus child) cleared GICR_CTLR. The
 * GICv3CPUState copies make kvm_arm_gicv3_put() write the same values.
 */
static bool its_kvm_write_lpi_tables(void)
{
    GICv3State *gic = its_kvm.its->gicv3;
    int cpu;

    if (!its_kvm_find_base()) {
        return false;
    }
    for (cpu = 0; cpu < gic->num_cpu; cpu++) {
        GICv3CPUState *c = &gic->cpu[cpu];
        uint64_t val;

        c->gicr_propbaser = its_kvm_propbaser();
        c->gicr_pendbaser = its_kvm_pendbaser(cpu);
        val = c->gicr_propbaser;
        if (its_kvm_redist_access(cpu, GICR_PROPBASER, &val, true) < 0) {
            return false;
        }
        val = c->gicr_pendbaser;
        if (its_kvm_redist_access(cpu, GICR_PENDBASER, &val, true) < 0) {
            return false;
        }
    }
    trace_its_kvm_lpi_tables(its_kvm.base + ITS_KVM_PROP_OFF,
                             its_kvm.base + ITS_KVM_PEND_OFF, gic->num_cpu);
    return true;
}

/*
 * A guest that wrote GICR_PROPBASER itself drives its own LPIs, which this
 * helper cannot serve, so exit. A zero means the reset-time write was lost;
 * KVM accepts the rewrite only while EnableLPIs is clear.
 */
static ItsKvmStatus its_kvm_check_lpi_tables(void)
{
    GICv3State *gic = its_kvm.its->gicv3;
    int cpu;

    for (cpu = 0; cpu < gic->num_cpu; cpu++) {
        uint64_t prop = 0, want = its_kvm_propbaser();

        if (its_kvm_redist_access(cpu, GICR_PROPBASER, &prop, false) < 0) {
            return ITS_KVM_EINVAL;
        }
        if (FIELD_EX64(prop, GICR_PROPBASER, PHYADDR) ==
            FIELD_EX64(want, GICR_PROPBASER, PHYADDR)) {
            continue;
        }
        if (FIELD_EX64(prop, GICR_PROPBASER, PHYADDR)) {
            error_report("its-kvm-program: vCPU %d GICR_PROPBASER is 0x%"
                         PRIx64 ", the guest programs its own LPI tables",
                         cpu, prop);
            exit(1);
        }
        if (!its_kvm_write_lpi_tables()) {
            return ITS_KVM_EINVAL;
        }
        if (its_kvm_redist_access(cpu, GICR_PROPBASER, &prop, false) < 0 ||
            FIELD_EX64(prop, GICR_PROPBASER, PHYADDR) !=
            FIELD_EX64(want, GICR_PROPBASER, PHYADDR)) {
            error_report("its-kvm-program: vCPU %d GICR_PROPBASER 0x%" PRIx64
                         " cannot be set, LPIs already enabled", cpu, prop);
            return ITS_KVM_EINVAL;
        }
    }
    return ITS_KVM_OK;
}

static void its_kvm_set_lpi_prop(uint32_t lpi, uint8_t prop)
{
    uint8_t *table = its_kvm_ram(ITS_KVM_PROP_OFF);

    table[lpi - ITS_KVM_LPI_BASE] = prop;
}

static ItsKvmStatus its_kvm_errno(int err)
{
    return err == -EBUSY ? ITS_KVM_EBUSY : ITS_KVM_EINVAL;
}

static ItsKvmStatus its_kvm_reg_access(uint32_t off, uint64_t *val, bool write)
{
    Error *err = NULL;
    int ret;

    ret = kvm_device_access(its_kvm.its->dev_fd, KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                            off, val, write, &err);
    if (ret < 0) {
        error_report_err(err);
        return its_kvm_errno(ret);
    }
    return ITS_KVM_OK;
}

static ItsKvmStatus its_kvm_reg_write(uint32_t off, uint64_t val)
{
    return its_kvm_reg_access(off, &val, true);
}

/*
 * KVM fills in the BASER entry size and type and sanitises the attributes.
 * It ignores GITS_CTLR.Enable unless all three bases are valid, so read
 * GITS_CTLR back.
 */
static ItsKvmStatus its_kvm_program(void)
{
    uint64_t *l1 = its_kvm_ram(ITS_KVM_DT_L1_OFF);
    uint64_t ctlr = 0;
    ItsKvmStatus st;
    int i;

    if (its_kvm.programmed) {
        return ITS_KVM_OK;
    }
    if (!its_kvm_find_base()) {
        return ITS_KVM_EINVAL;
    }
    st = its_kvm_check_lpi_tables();
    if (st != ITS_KVM_OK) {
        return st;
    }
    /* level-1 device table: valid bit and the level-2 page's frame */
    for (i = 0; i < ITS_KVM_DT_L2_PAGES; i++) {
        stq_le_p(&l1[i], (1ULL << 63) |
                 (its_kvm.base + ITS_KVM_DT_L2_OFF + i * ITS_KVM_PAGE));
    }

    st = its_kvm_reg_write(GITS_BASER, R_GITS_BASER_VALID_MASK |
                           R_GITS_BASER_INDIRECT_MASK | ITS_KVM_BASER_RAWAWB |
                           ITS_KVM_INNER_SHAREABLE |
                           (its_kvm.base + ITS_KVM_DT_L1_OFF));
    if (st == ITS_KVM_OK) {
        st = its_kvm_reg_write(GITS_BASER + 8, R_GITS_BASER_VALID_MASK |
                               ITS_KVM_BASER_RAWAWB | ITS_KVM_INNER_SHAREABLE |
                               (its_kvm.base + ITS_KVM_CT_OFF));
    }
    if (st == ITS_KVM_OK) {
        /* resets GITS_CREADR and GITS_CWRITER to 0 */
        st = its_kvm_reg_write(GITS_CBASER, R_GITS_CBASER_VALID_MASK |
                               ITS_KVM_BASER_RAWAWB | ITS_KVM_INNER_SHAREABLE |
                               (its_kvm.base + ITS_KVM_CQ_OFF) |
                               (ITS_KVM_CQ_SIZE / 4096 - 1));
        its_kvm.cwriter = 0;
    }
    if (st == ITS_KVM_OK) {
        st = its_kvm_reg_write(GITS_CTLR, R_GITS_CTLR_ENABLED_MASK);
    }
    if (st == ITS_KVM_OK) {
        st = its_kvm_reg_access(GITS_CTLR, &ctlr, false);
    }
    if (st == ITS_KVM_OK && !(ctlr & R_GITS_CTLR_ENABLED_MASK)) {
        error_report("KVM did not enable the ITS");
        st = ITS_KVM_EINVAL;
    }
    its_kvm.programmed = st == ITS_KVM_OK;
    trace_its_kvm_program(its_kvm.base, st);
    return st;
}

static void its_kvm_enqueue(const uint64_t cmd[4])
{
    uint64_t *q = its_kvm_ram(ITS_KVM_CQ_OFF + its_kvm.cwriter);
    int i;

    /* the ring is never filled: a call queues a handful of commands */
    assert(its_kvm.cmds < ITS_KVM_CQ_SIZE / ITS_KVM_CMD_SIZE - 1);
    for (i = 0; i < 4; i++) {
        stq_le_p(&q[i], cmd[i]);
    }
    trace_its_kvm_cmd(its_kvm.cwriter, cmd[0], cmd[1], cmd[2]);
    its_kvm.cwriter = (its_kvm.cwriter + ITS_KVM_CMD_SIZE) % ITS_KVM_CQ_SIZE;
    its_kvm.cmds++;
}

/* KVM processes the queue in the GITS_CWRITER write */
static ItsKvmStatus its_kvm_flush(void)
{
    its_kvm.cmds = 0;
    return its_kvm_reg_write(GITS_CWRITER, its_kvm.cwriter);
}

/* field layout as KVM's its_cmd_get_*() decode it */
static void its_kvm_mapd(uint32_t devid, hwaddr itt)
{
    uint64_t cmd[4] = {
        GITS_CMD_MAPD | (uint64_t)devid << 32,
        ITS_KVM_EVENT_BITS - 1,
        (1ULL << 63) | itt,
        0,
    };
    its_kvm_enqueue(cmd);
}

static void its_kvm_mapc(uint32_t icid, uint64_t vcpu_id)
{
    uint64_t cmd[4] = {
        GITS_CMD_MAPC,
        0,
        (1ULL << 63) | vcpu_id << 16 | icid,
        0,
    };
    its_kvm_enqueue(cmd);
}

static void its_kvm_mapti(uint32_t devid, uint32_t event, uint32_t lpi,
                          uint32_t icid)
{
    uint64_t cmd[4] = {
        GITS_CMD_MAPTI | (uint64_t)devid << 32,
        event | (uint64_t)lpi << 32,
        icid,
        0,
    };
    its_kvm_enqueue(cmd);
}

static void its_kvm_event_cmd(uint8_t op, uint32_t devid, uint32_t event,
                              uint32_t icid)
{
    uint64_t cmd[4] = { op | (uint64_t)devid << 32, event, icid, 0 };

    its_kvm_enqueue(cmd);
}

/* KVM bounds MAPTI's pINTID by PROPBASER.IDbits */
static ItsKvmStatus its_kvm_check_lpi(uint32_t lpi)
{
    if (lpi < ITS_KVM_LPI_BASE || lpi >= 1U << ITS_KVM_IDBITS) {
        return ITS_KVM_EPHYSID_OOR;
    }
    return ITS_KVM_OK;
}

static ItsKvmStatus its_kvm_check_target(int target_vcpu, uint64_t *vcpu_id)
{
    CPUState *cs = target_vcpu < 0 ? NULL : qemu_get_cpu(target_vcpu);

    if (!cs) {
        return ITS_KVM_ECOLLECTION_OOR;
    }
    *vcpu_id = kvm_arch_vcpu_id(cs);
    if (*vcpu_id >= ITS_KVM_COLLECTIONS) {
        return ITS_KVM_ECOLLECTION_OOR;
    }
    return ITS_KVM_OK;
}

static ItsKvmStatus its_kvm_check_mapping(uint32_t devid, uint32_t event)
{
    if (!its_kvm.its) {
        return ITS_KVM_EINVAL;
    }
    if (devid >= ITS_KVM_MAX_DEVID) {
        return ITS_KVM_EDEVICE_OOR;
    }
    if (event >= 1U << ITS_KVM_EVENT_BITS) {
        return ITS_KVM_EEVENT_OOR;
    }
    return ITS_KVM_OK;
}

static bool its_kvm_mapped(uint32_t devid, uint32_t event)
{
    return g_hash_table_contains(its_kvm.lpis, its_kvm_lpi_key(devid, event));
}

/* the collection of a vCPU is its own id (GITS_TYPER.PTA is 0 under KVM) */
static void its_kvm_need_collection(uint64_t vcpu_id)
{
    if (!test_bit(vcpu_id, its_kvm.collections)) {
        its_kvm_mapc(vcpu_id, vcpu_id);
        set_bit(vcpu_id, its_kvm.collections);
    }
}

ItsKvmStatus its_kvm_map_device_interrupt(uint32_t devid, uint32_t event,
                                          uint32_t lpi, int target_vcpu)
{
    uint64_t vcpu_id;
    ItsKvmStatus st;
    unsigned slot;

    st = its_kvm_check_mapping(devid, event);
    if (st == ITS_KVM_OK) {
        st = its_kvm_check_lpi(lpi);
    }
    if (st == ITS_KVM_OK) {
        st = its_kvm_check_target(target_vcpu, &vcpu_id);
    }
    if (st != ITS_KVM_OK) {
        goto out;
    }

    pause_all_vcpus();
    st = its_kvm_program();
    if (st != ITS_KVM_OK) {
        goto resume;
    }

    slot = GPOINTER_TO_UINT(g_hash_table_lookup(its_kvm.dev_itt,
                                                its_kvm_dev_key(devid)));
    if (!slot) {
        slot = find_first_zero_bit(its_kvm.itts, ITS_KVM_DEVICES);
        if (slot >= ITS_KVM_DEVICES) {
            st = ITS_KVM_EDEVICE_OOR;
            goto resume;
        }
        set_bit(slot, its_kvm.itts);
        slot++;
        g_hash_table_insert(its_kvm.dev_itt, its_kvm_dev_key(devid),
                            GUINT_TO_POINTER(slot));
        its_kvm_mapd(devid, its_kvm.base + ITS_KVM_ITT_OFF +
                     (slot - 1) * ITS_KVM_ITT_SIZE);
    }
    its_kvm_need_collection(vcpu_id);
    if (its_kvm_mapped(devid, event)) {
        /* KVM keeps the old translation on a second MAPTI */
        its_kvm_event_cmd(GITS_CMD_DISCARD, devid, event, 0);
    }
    its_kvm_mapti(devid, event, lpi, vcpu_id);
    its_kvm_set_lpi_prop(lpi, ITS_KVM_LPI_PROP_ON);
    its_kvm_event_cmd(GITS_CMD_INV, devid, event, 0);
    st = its_kvm_flush();
    if (st == ITS_KVM_OK) {
        g_hash_table_insert(its_kvm.lpis, its_kvm_lpi_key(devid, event),
                            GUINT_TO_POINTER(lpi));
    }
resume:
    resume_all_vcpus();
out:
    trace_its_kvm_map(devid, event, lpi, target_vcpu, st);
    return st;
}

ItsKvmStatus its_kvm_unmap_device_interrupt(uint32_t devid, uint32_t event)
{
    ItsKvmStatus st;

    st = its_kvm_check_mapping(devid, event);
    if (st == ITS_KVM_OK && !its_kvm_mapped(devid, event)) {
        st = ITS_KVM_EINVAL;
    }
    if (st != ITS_KVM_OK) {
        goto out;
    }

    pause_all_vcpus();
    its_kvm_set_lpi_prop(GPOINTER_TO_UINT(g_hash_table_lookup(its_kvm.lpis,
                         its_kvm_lpi_key(devid, event))), ITS_KVM_LPI_PROP_OFF);
    its_kvm_event_cmd(GITS_CMD_INV, devid, event, 0);
    its_kvm_event_cmd(GITS_CMD_DISCARD, devid, event, 0);
    st = its_kvm_flush();
    if (st == ITS_KVM_OK) {
        g_hash_table_remove(its_kvm.lpis, its_kvm_lpi_key(devid, event));
    }
    resume_all_vcpus();
out:
    trace_its_kvm_unmap(devid, event, st);
    return st;
}

ItsKvmStatus its_kvm_retarget_device_interrupt(uint32_t devid, uint32_t event,
                                               int target_vcpu)
{
    uint64_t vcpu_id;
    ItsKvmStatus st;

    st = its_kvm_check_mapping(devid, event);
    if (st == ITS_KVM_OK && !its_kvm_mapped(devid, event)) {
        st = ITS_KVM_EINVAL;
    }
    if (st == ITS_KVM_OK) {
        st = its_kvm_check_target(target_vcpu, &vcpu_id);
    }
    if (st != ITS_KVM_OK) {
        goto out;
    }

    pause_all_vcpus();
    its_kvm_need_collection(vcpu_id);
    its_kvm_event_cmd(GITS_CMD_MOVI, devid, event, vcpu_id);
    st = its_kvm_flush();
    resume_all_vcpus();
out:
    trace_its_kvm_retarget(devid, event, target_vcpu, st);
    return st;
}

/**
 * vm_change_state_handler - VM change state callback aiming at flushing
 * ITS tables into guest RAM
 *
 * The tables get flushed to guest RAM whenever the VM gets stopped.
 */
static void vm_change_state_handler(void *opaque, bool running,
                                    RunState state)
{
    GICv3ITSState *s = (GICv3ITSState *)opaque;
    Error *err = NULL;

    if (running) {
        return;
    }

    kvm_device_access(s->dev_fd, KVM_DEV_ARM_VGIC_GRP_CTRL,
                      KVM_DEV_ARM_ITS_SAVE_TABLES, NULL, true, &err);
    if (err) {
        error_report_err(err);
    }
}

static void kvm_arm_its_realize(DeviceState *dev, Error **errp)
{
    GICv3ITSState *s = ARM_GICV3_ITS_COMMON(dev);

    s->dev_fd = kvm_create_device(kvm_state, KVM_DEV_TYPE_ARM_VGIC_ITS, false);
    if (s->dev_fd < 0) {
        error_setg_errno(errp, -s->dev_fd, "error creating in-kernel ITS");
        return;
    }

    /* explicit init of the ITS */
    kvm_device_access(s->dev_fd, KVM_DEV_ARM_VGIC_GRP_CTRL,
                      KVM_DEV_ARM_VGIC_CTRL_INIT, NULL, true, &error_abort);

    /* register the base address */
    kvm_arm_register_device(&s->iomem_its_cntrl, -1, KVM_DEV_ARM_VGIC_GRP_ADDR,
                            KVM_VGIC_ITS_ADDR_TYPE, s->dev_fd, 0);

    gicv3_add_its(s->gicv3, dev);

    gicv3_its_init_mmio(s, NULL, NULL);

    if (s->kvm_program && !its_kvm_init(s, errp)) {
        return;
    }

    if (!kvm_device_check_attr(s->dev_fd, KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
        GITS_CTLR)) {
        error_setg(&s->migration_blocker, "This operating system kernel "
                   "does not support vITS migration");
        if (migrate_add_blocker(&s->migration_blocker, errp) < 0) {
            return;
        }
    } else {
        qemu_add_vm_change_state_handler(vm_change_state_handler, s);
    }

    kvm_msi_use_devid = true;
    kvm_gsi_direct_mapping = false;
    kvm_msi_via_irqfd_allowed = true;
}

/**
 * kvm_arm_its_pre_save - handles the saving of ITS registers.
 * ITS tables are flushed into guest RAM separately and earlier,
 * through the VM change state handler, since at the moment pre_save()
 * is called, the guest RAM has already been saved.
 */
static void kvm_arm_its_pre_save(GICv3ITSState *s)
{
    int i;

    for (i = 0; i < 8; i++) {
        kvm_device_access(s->dev_fd, KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                          GITS_BASER + i * 8, &s->baser[i], false,
                          &error_abort);
    }

    kvm_device_access(s->dev_fd, KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                      GITS_CTLR, &s->ctlr, false, &error_abort);

    kvm_device_access(s->dev_fd, KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                      GITS_CBASER, &s->cbaser, false, &error_abort);

    kvm_device_access(s->dev_fd, KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                      GITS_CREADR, &s->creadr, false, &error_abort);

    kvm_device_access(s->dev_fd, KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                      GITS_CWRITER, &s->cwriter, false, &error_abort);

    kvm_device_access(s->dev_fd, KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                      GITS_IIDR, &s->iidr, false, &error_abort);
}

/**
 * kvm_arm_its_post_load - Restore both the ITS registers and tables
 */
static void kvm_arm_its_post_load(GICv3ITSState *s)
{
    int i;

    kvm_device_access(s->dev_fd, KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                      GITS_IIDR, &s->iidr, true, &error_abort);

    /*
     * must be written before GITS_CREADR since GITS_CBASER write
     * access resets GITS_CREADR.
     */
    kvm_device_access(s->dev_fd, KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                      GITS_CBASER, &s->cbaser, true, &error_abort);

    kvm_device_access(s->dev_fd, KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                      GITS_CREADR, &s->creadr, true, &error_abort);

    kvm_device_access(s->dev_fd, KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                      GITS_CWRITER, &s->cwriter, true, &error_abort);


    for (i = 0; i < 8; i++) {
        kvm_device_access(s->dev_fd, KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                          GITS_BASER + i * 8, &s->baser[i], true,
                          &error_abort);
    }

    kvm_device_access(s->dev_fd, KVM_DEV_ARM_VGIC_GRP_CTRL,
                      KVM_DEV_ARM_ITS_RESTORE_TABLES, NULL, true,
                      &error_abort);

    kvm_device_access(s->dev_fd, KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                      GITS_CTLR, &s->ctlr, true, &error_abort);
}

static void kvm_arm_its_reset_hold(Object *obj, ResetType type)
{
    GICv3ITSState *s = ARM_GICV3_ITS_COMMON(obj);
    KVMARMITSClass *c = KVM_ARM_ITS_GET_CLASS(s);
    int i;

    if (c->parent_phases.hold) {
        c->parent_phases.hold(obj, type);
    }

    its_kvm_reset(s);
    if (its_kvm.its == s && !its_kvm_write_lpi_tables()) {
        error_report("its-kvm-program: cannot program the LPI tables");
    }

    if (kvm_device_check_attr(s->dev_fd, KVM_DEV_ARM_VGIC_GRP_CTRL,
                               KVM_DEV_ARM_ITS_CTRL_RESET)) {
        kvm_device_access(s->dev_fd, KVM_DEV_ARM_VGIC_GRP_CTRL,
                          KVM_DEV_ARM_ITS_CTRL_RESET, NULL, true, &error_abort);
        return;
    }

    warn_report("ITS KVM: full reset is not supported by the host kernel");

    if (!kvm_device_check_attr(s->dev_fd, KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                               GITS_CTLR)) {
        return;
    }

    kvm_device_access(s->dev_fd, KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                      GITS_CTLR, &s->ctlr, true, &error_abort);

    kvm_device_access(s->dev_fd, KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                      GITS_CBASER, &s->cbaser, true, &error_abort);

    for (i = 0; i < 8; i++) {
        kvm_device_access(s->dev_fd, KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
                          GITS_BASER + i * 8, &s->baser[i], true,
                          &error_abort);
    }
}

static const Property kvm_arm_its_props[] = {
    DEFINE_PROP_LINK("parent-gicv3", GICv3ITSState, gicv3, "kvm-arm-gicv3",
                     GICv3State *),
    DEFINE_PROP_BOOL("kvm-program", GICv3ITSState, kvm_program, false),
};

static void kvm_arm_its_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);
    GICv3ITSCommonClass *icc = ARM_GICV3_ITS_COMMON_CLASS(klass);
    KVMARMITSClass *ic = KVM_ARM_ITS_CLASS(klass);

    dc->realize = kvm_arm_its_realize;
    device_class_set_props(dc, kvm_arm_its_props);
    resettable_class_set_parent_phases(rc, NULL, kvm_arm_its_reset_hold, NULL,
                                       &ic->parent_phases);
    icc->send_msi = kvm_its_send_msi;
    icc->pre_save = kvm_arm_its_pre_save;
    icc->post_load = kvm_arm_its_post_load;
}

static const TypeInfo kvm_arm_its_info = {
    .name = TYPE_KVM_ARM_ITS,
    .parent = TYPE_ARM_GICV3_ITS_COMMON,
    .instance_size = sizeof(GICv3ITSState),
    .class_init = kvm_arm_its_class_init,
    .class_size = sizeof(KVMARMITSClass),
};

static void kvm_arm_its_register_types(void)
{
    type_register_static(&kvm_arm_its_info);
}

type_init(kvm_arm_its_register_types)

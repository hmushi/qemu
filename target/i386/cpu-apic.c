/*
 * QEMU x86 CPU <-> APIC
 *
 * Copyright (c) 2003-2004 Fabrice Bellard
 *
 * SPDX-License-Identifier: MIT
 */

#include "qemu/osdep.h"
#include "qobject/qdict.h"
#include "qapi/error.h"
#include "monitor/monitor.h"
#include "monitor/hmp.h"
#include "system/hw_accel.h"
#include "system/kvm.h"
#include "system/xen.h"
#include "system/mshv.h"
#include "system/address-spaces.h"
#include "hw/core/qdev-properties.h"
#include "hw/i386/apic_internal.h"
#include "cpu-internal.h"

APICCommonClass *apic_get_class(Error **errp)
{
    const char *apic_type = "apic";

    /* TODO: in-kernel irqchip for hvf */
    if (kvm_enabled()) {
        if (!kvm_irqchip_in_kernel()) {
            error_setg(errp, "KVM does not support userspace APIC");
            return NULL;
        }
        apic_type = "kvm-apic";
    } else if (xen_enabled()) {
        apic_type = "xen-apic";
    } else if (whpx_irqchip_in_kernel()) {
        apic_type = "whpx-apic";
    } else if (mshv_enabled()) {
        apic_type = "mshv-apic";
    }

    return APIC_COMMON_CLASS(object_class_by_name(apic_type));
}

void x86_cpu_apic_create(X86CPU *cpu, Error **errp)
{
    APICCommonClass *apic_class = apic_get_class(errp);

    if (!apic_class) {
        return;
    }

    cpu->apic_state = APIC_COMMON(object_new_with_class(OBJECT_CLASS(apic_class)));
    object_property_add_child(OBJECT(cpu), "lapic",
                              OBJECT(cpu->apic_state));
    object_unref(OBJECT(cpu->apic_state));

    /* TODO: convert to link<> */
    cpu->apic_state->cpu = cpu;
    cpu->apic_state->apicbase = APIC_DEFAULT_ADDRESS | MSR_IA32_APICBASE_ENABLE;

    /* cpu must be set before realize, which validates the APIC ID */
    qdev_prop_set_uint32(DEVICE(cpu->apic_state), "id", cpu->apic_id);
}

void x86_cpu_apic_realize(X86CPU *cpu, Error **errp)
{
    static bool apic_mmio_map_once;

    if (cpu->apic_state == NULL) {
        return;
    }
    qdev_realize(DEVICE(cpu->apic_state), NULL, errp);

    /* Map APIC MMIO area */
    if (!apic_mmio_map_once) {
        memory_region_add_subregion_overlap(get_system_memory(),
                                            cpu->apic_state->apicbase &
                                            MSR_IA32_APICBASE_BASE,
                                            &cpu->apic_state->io_memory,
                                            0x1000);
        apic_mmio_map_once = true;
     }
}

#ifdef CONFIG_HMP
void hmp_info_local_apic(MonitorHMP *hmp, const QDict *qdict)
{
    CPUState *cs;

    if (qdict_haskey(qdict, "apic-id")) {
        int id = qdict_get_try_int(qdict, "apic-id", 0);

        cs = cpu_by_arch_id(id);
        if (cs) {
            cpu_synchronize_state(cs);
        }
    } else {
        cs = monitor_hmp_get_cpu(hmp);
    }


    if (!cs) {
        monitor_hmp_printf(hmp, "No CPU available\n");
        return;
    }
    x86_cpu_dump_local_apic_state(cs, CPU_DUMP_FPU);
}

/* KVM's per-VP synthetic controller state, as of the caller's synchronise */
static void dump_synic_state(MonitorHMP *hmp, CPUState *cs)
{
    CPUX86State *env = &X86_CPU(cs)->env;
    int i;

    monitor_hmp_printf(hmp, "SynIC: scontrol 0x%016" PRIx64 " siefp 0x%016"
                       PRIx64 " simp 0x%016" PRIx64 " vp_assist 0x%016"
                       PRIx64 "\n", env->msr_hv_synic_control,
                       env->msr_hv_synic_evt_page, env->msr_hv_synic_msg_page,
                       env->msr_hv_vapic);

    for (i = 0; i < ARRAY_SIZE(env->msr_hv_synic_sint); i++) {
        monitor_hmp_printf(hmp, "SINT%-2d 0x%08" PRIx64 "%s", i,
                           env->msr_hv_synic_sint[i],
                           (i % 4) == 3 ? "\n" : " ");
    }
}

/*
 * The VTLs of a VP are separate CPUStates that share a cpu_index and an
 * APIC ID, so neither "info registers" nor "info lapic" can name one. Dump
 * them all, the plane vCPUs included.
 */
void hmp_info_vtl(MonitorHMP *hmp, const QDict *qdict)
{
    CPUState *cs;

    CPU_FOREACH(cs) {
        cpu_synchronize_state(cs);
        monitor_hmp_printf(hmp, "\nVP %d VTL %d: halted %d mp_state %d\n",
                           cs->cpu_index, cs->kvm_plane, cs->halted,
                           X86_CPU(cs)->env.mp_state);
        cpu_dump_state(cs, NULL, 0);
        x86_cpu_dump_local_apic_state(cs, 0);
        dump_synic_state(hmp, cs);
    }
}
#endif

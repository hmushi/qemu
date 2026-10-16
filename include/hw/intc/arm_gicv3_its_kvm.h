/*
 * KVM in-kernel ITS programmed by QEMU on a guest's behalf
 *
 * A Hyper-V child partition on ARM64 leaves the ITS and the LPI tables to
 * the root, which maps device interrupts for it (HvCallMapDeviceInterrupt).
 * With "kvm-program" set, the KVM ITS device keeps its tables in a RAM block
 * outside the guest memory map and maps (DeviceID, EventID) to an LPI on
 * request through this API.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef HW_INTC_ARM_GICV3_ITS_KVM_H
#define HW_INTC_ARM_GICV3_ITS_KVM_H

#define TYPE_KVM_ARM_ITS "arm-its-kvm"

/* Size of the RAM block the machine maps as the ITS tables (sysbus MMIO 1). */
#define ITS_KVM_TABLES_SIZE 0x800000

typedef enum ItsKvmStatus {
    ITS_KVM_OK = 0,
    ITS_KVM_EDEVICE_OOR,       /* DeviceID beyond the device table */
    ITS_KVM_EEVENT_OOR,        /* EventID beyond the device's ITT */
    ITS_KVM_EPHYSID_OOR,       /* LPI outside [8192, 1 << ITS_KVM_IDBITS) */
    ITS_KVM_ECOLLECTION_OOR,   /* no vCPU with that index */
    ITS_KVM_EBUSY,             /* KVM refused the access, vCPUs still running */
    ITS_KVM_EINVAL,            /* not programming, no such mapping, KVM error */
} ItsKvmStatus;

/*
 * All take the BQL held and run on a vCPU thread or the main loop.
 * @devid is the PCI requester ID, @event the MSI data, @lpi the INTID the
 * guest expects (>= 8192), @target_vcpu the cpu_index of the target vCPU.
 */
ItsKvmStatus its_kvm_map_device_interrupt(uint32_t devid, uint32_t event,
                                          uint32_t lpi, int target_vcpu);
ItsKvmStatus its_kvm_unmap_device_interrupt(uint32_t devid, uint32_t event);
ItsKvmStatus its_kvm_retarget_device_interrupt(uint32_t devid, uint32_t event,
                                               int target_vcpu);

#endif

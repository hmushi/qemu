/*
 * Hyper-V VSM: the plane-side interface the VTL handlers in hw/hyperv/hyperv.c
 * call into.
 *
 * Nicolas Saenz Julienne's series implemented these with "CPU namespaces":
 * one X86CPU object per VTL per VP, each namespace backed by its own KVM VM
 * (companion VM) with its own memslots, irqchip and memory attributes. The
 * planes re-targeting must provide the same operations on top of
 * KVM_CREATE_PLANE / per-plane vCPU fds. Every function here is a stub that
 * documents the operation and fails loudly; nothing in this header is
 * behaviour.
 */
#ifndef HW_HYPERV_VSM_PLANE_API_H
#define HW_HYPERV_VSM_PLANE_API_H

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "hw/core/cpu.h"
#include "system/kvm.h"
#include "system/memory.h"
#include "system/address-spaces.h"

/*
 * plane API: VTL (plane level) a vCPU object runs in.
 * Was: X86_CPU(cs)->namespace. Planes: the plane the vCPU fd belongs to.
 */
static inline int hv_plane_active_vtl(CPUState *cs)
{
    return 0;
}

/*
 * plane API: sibling lookup, the vCPU object of @vp_index at @vtl.
 * Was: cpu_by_arch_id(vp_index, vtl). Planes: plane-0 vCPU for vtl 0, else
 * the per-plane vCPU created with KVM_CREATE_VCPU on the plane fd (same id).
 */
static inline CPUState *hv_plane_vcpu(uint32_t vp_index, int vtl)
{
    return vtl == 0 ? cpu_by_arch_id(vp_index) : NULL;
}

/*
 * plane API: create the plane for @vtl (EnablePartitionVtl).
 * Was: kvm_init_companion_vm() + hyperv_kvm_init_vsm(): a second KVM VM
 * sharing the RAM backend through a second memory listener, clock synced.
 * Planes: KVM_CREATE_PLANE(vtl) on the VM fd; memory is shared by design.
 */
static inline int hv_plane_create(int vtl)
{
    error_report("hyperv-vsm: plane API hv_plane_create(%d) not implemented", vtl);
    return -ENOSYS;
}

/*
 * plane API: create the vCPU of @vp_index in plane @vtl (EnableVpVtl).
 * Was: x86_cpu_new(x86ms, ns=vtl, kvm_state[vtl], apic_id) then
 * kvm_arch_put_registers() to seed KVM from the QEMU object.
 * Planes: KVM_CREATE_VCPU on the plane fd (plane-0 vCPU must exist), then a
 * QEMU CPUState/X86CPU wrapper that runs that fd. Open question for the
 * re-targeting: whether this is a second X86CPU object (Nicolas's model) or a
 * second register file inside the plane-0 X86CPU.
 */
static inline CPUState *hv_plane_vcpu_create(uint32_t vp_index, int vtl)
{
    error_report("hyperv-vsm: plane API hv_plane_vcpu_create(%u, %d) not implemented",
                 vp_index, vtl);
    return NULL;
}

/*
 * plane API: KVM state used for irq routing / MSI delivery toward @cs.
 * Was: cs->kvm_state (per-namespace KVMState). Planes: one KVMState; GSI
 * routing and KVM_SIGNAL_MSI are accepted on the plane fd, so this must
 * select the plane fd for @cs's plane.
 */
static inline KVMState *hv_plane_kvm_state(CPUState *cs)
{
    return kvm_state;
}

/*
 * plane API: memory root for SynIC overlay pages of plane @vtl.
 * Was: hv_vsm.root[vtl] (separate MemoryRegion tree per companion VM).
 * Planes: the system memory tree; overlay pages are per vCPU, not per plane.
 */
static inline MemoryRegion *hv_plane_memory_root(int vtl)
{
    return get_system_memory();
}

/*
 * plane API: restrict plane @vtl's access to [addr, addr+size)
 * (ModifyVtlProtectionMask). @attrs are KVM_MEMORY_ATTRIBUTE_NR/NW/NX.
 * Was: KVM_SET_MEMORY_ATTRIBUTES on the companion VM fd of @vtl.
 * Planes v7.2-rc5: no userspace ioctl sets per-plane access attributes; only
 * the in-guest KVM_HC_VBS_SET_MEM_ATTRS hypercall reaches
 * kvm_plane_set_access_attrs(). Needs a new vm/plane ioctl (W3 gap).
 */
static inline int hv_plane_set_memory_attrs(int vtl, hwaddr addr, hwaddr size,
                                            uint64_t attrs)
{
    error_report("hyperv-vsm: plane API hv_plane_set_memory_attrs(%d) not implemented",
                 vtl);
    return -ENOSYS;
}

#endif /* HW_HYPERV_VSM_PLANE_API_H */

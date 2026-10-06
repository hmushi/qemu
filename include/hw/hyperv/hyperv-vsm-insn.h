/*
 * Hyper-V VSM: x86 instruction length decoder
 * (target/i386/kvm/hyperv-vsm-insn.c)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef HW_HYPERV_HYPERV_VSM_INSN_H
#define HW_HYPERV_HYPERV_VSM_INSN_H

/* length of the x86 instruction at @buf in @mode (16, 32, 64); 0 if unknown */
int hyperv_vsm_insn_len(const uint8_t *buf, int len, int mode);

#endif

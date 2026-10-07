/*
 * Hyper-V VSM: x86 instruction length decoder
 * (target/i386/kvm/hyperv-vsm-insn.c)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef HW_HYPERV_HYPERV_VSM_INSN_H
#define HW_HYPERV_HYPERV_VSM_INSN_H

/*
 * Length of the x86 instruction at @buf in @mode (16, 32, 64). 0 for a
 * truncated sequence, an encoding past the architectural 15-byte limit, or a
 * form invalid in @mode. An unrecognised opcode is sized as one byte rather
 * than refused, so a non-zero result is a best effort and not a validation.
 */
int hyperv_vsm_insn_len(const uint8_t *buf, int len, int mode);

#endif

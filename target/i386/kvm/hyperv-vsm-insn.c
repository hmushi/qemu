/*
 * Hyper-V VSM: x86 instruction length decoder for the GPA intercept message
 *
 * KVM_EXIT_MEMORY_FAULT carries no instruction length and the TLFS memory
 * intercept needs one, so the length is decoded from the bytes at RIP.
 * This only sizes instructions; it does not interpret them. Covered: legacy
 * prefixes, REX, the one-byte, 0F, 0F 38 and 0F 3A maps, 3DNow, VEX, XOP and
 * EVEX encodings, ModRM/SIB/displacement and immediate forms in 16, 32 and
 * 64-bit mode.
 *
 * This is a best effort and not a validation. 0 means a truncated sequence,
 * an encoding past the architectural 15-byte limit, or a form invalid in the
 * mode. An unrecognised one-byte opcode is sized as a single byte instead,
 * because every defined one that carries a ModRM byte or an immediate is
 * enumerated here and the rest take no operands. So a non-zero result does
 * not prove the bytes are an instruction.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/hyperv/hyperv-vsm-insn.h"

typedef struct {
    const uint8_t *buf;
    int len;
    int pos;
    bool opsize16;      /* effective operand size is 16 bits */
    int addrsize;       /* effective address size in bytes */
    bool rex_w;
    int mode;           /* 16, 32 or 64 */
} InsnDecoder;

static int next(InsnDecoder *d)
{
    if (d->pos >= d->len) {
        return -1;
    }
    return d->buf[d->pos++];
}

static bool skip(InsnDecoder *d, int n)
{
    if (d->pos + n > d->len) {
        return false;
    }
    d->pos += n;
    return true;
}

/* ModRM byte already consumed in @modrm: skip SIB and displacement */
static bool skip_modrm_tail(InsnDecoder *d, int modrm)
{
    int mod = modrm >> 6, rm = modrm & 7;

    if (mod == 3) {
        return true;
    }
    if (d->addrsize == 2) {
        if (mod == 0) {
            return rm == 6 ? skip(d, 2) : true;
        }
        return skip(d, mod == 1 ? 1 : 2);
    }
    if (rm == 4) {
        int sib = next(d);

        if (sib < 0) {
            return false;
        }
        if (mod == 0 && (sib & 7) == 5) {
            return skip(d, 4);
        }
    }
    if (mod == 0) {
        return rm == 5 ? skip(d, 4) : true;
    }
    return skip(d, mod == 1 ? 1 : 4);
}

static bool modrm(InsnDecoder *d)
{
    int m = next(d);

    return m >= 0 && skip_modrm_tail(d, m);
}

/* immediate of operand size: 16 or 32 bits (64 only for MOV r64, imm64) */
static bool imm_z(InsnDecoder *d)
{
    return skip(d, d->opsize16 ? 2 : 4);
}

static bool one_byte_has_modrm(int op)
{
    if (op < 0x40 && (op & 7) < 4) {
        return true;                            /* ALU r/m forms */
    }
    switch (op) {
    case 0x62: case 0x63: case 0x69: case 0x6b:
    case 0x80: case 0x81: case 0x82: case 0x83: case 0x84: case 0x85:
    case 0x86: case 0x87: case 0x88: case 0x89: case 0x8a: case 0x8b:
    case 0x8c: case 0x8d: case 0x8e: case 0x8f:
    case 0xc0: case 0xc1: case 0xc4: case 0xc5: case 0xc6: case 0xc7:
    case 0xd0: case 0xd1: case 0xd2: case 0xd3:
    case 0xd8: case 0xd9: case 0xda: case 0xdb:
    case 0xdc: case 0xdd: case 0xde: case 0xdf:
    case 0xf6: case 0xf7: case 0xfe: case 0xff:
        return true;
    default:
        return false;
    }
}

static bool decode_one_byte(InsnDecoder *d, int op)
{
    int m;

    if (op < 0x40 && (op & 7) == 4) {
        return skip(d, 1);                      /* ALU AL, imm8 */
    }
    if (op < 0x40 && (op & 7) == 5) {
        return imm_z(d);                        /* ALU eAX, imm */
    }
    if (op >= 0x70 && op <= 0x7f) {
        return skip(d, 1);                      /* Jcc rel8 */
    }
    if (op >= 0xb0 && op <= 0xb7) {
        return skip(d, 1);                      /* MOV r8, imm8 */
    }
    if (op >= 0xb8 && op <= 0xbf) {
        return d->rex_w ? skip(d, 8) : imm_z(d); /* MOV r, imm */
    }
    if (op >= 0xd8 && op <= 0xdf) {
        return modrm(d);                        /* x87 */
    }
    if (op >= 0xe0 && op <= 0xe7) {
        return skip(d, 1);                      /* LOOPcc, JCXZ, IN/OUT imm8 */
    }

    switch (op) {
    case 0x69:                                  /* IMUL r, r/m, imm */
    case 0x81:                                  /* ALU r/m, imm */
    case 0xc7:                                  /* MOV r/m, imm */
        return modrm(d) && imm_z(d);
    case 0x6b: case 0x80: case 0x82: case 0x83: case 0xc0: case 0xc1:
    case 0xc6:
        return modrm(d) && skip(d, 1);
    case 0xf6: case 0xf7:                       /* TEST r/m, imm when /0 /1 */
        m = next(d);
        if (m < 0 || !skip_modrm_tail(d, m)) {
            return false;
        }
        if (((m >> 3) & 7) < 2) {
            return op == 0xf6 ? skip(d, 1) : imm_z(d);
        }
        return true;
    case 0x68: case 0xa9: case 0xe8: case 0xe9:
        return imm_z(d);
    case 0x6a: case 0xa8: case 0xcd: case 0xd4: case 0xd5: case 0xeb:
        return skip(d, 1);
    case 0xc2: case 0xca:                       /* RET imm16 */
        return skip(d, 2);
    case 0xc8:                                  /* ENTER imm16, imm8 */
        return skip(d, 3);
    case 0xa0: case 0xa1: case 0xa2: case 0xa3: /* MOV moffs */
        return skip(d, d->addrsize);
    case 0x9a: case 0xea:                       /* far CALL/JMP ptr */
        if (d->mode == 64) {
            return false;
        }
        return skip(d, d->opsize16 ? 4 : 6);
    default:
        return one_byte_has_modrm(op) ? modrm(d) : true;
    }
}

static bool decode_0f(InsnDecoder *d)
{
    int op = next(d);

    if (op < 0) {
        return false;
    }
    switch (op) {
    case 0x0f:                                  /* 3DNow: ModRM + imm8 */
        return modrm(d) && skip(d, 1);
    case 0x38:                                  /* 0F 38 map */
        return next(d) >= 0 && modrm(d);
    case 0x3a:                                  /* 0F 3A map: ModRM + imm8 */
        return next(d) >= 0 && modrm(d) && skip(d, 1);
    case 0x20: case 0x21: case 0x22: case 0x23:
        /* MOV to/from CR/DR: mod is ignored, the operand is always a reg */
        return next(d) >= 0;
    case 0x80 ... 0x8f:                         /* Jcc rel32 */
        return imm_z(d);
    case 0x70: case 0x71: case 0x72: case 0x73:
    case 0xa4: case 0xac: case 0xba: case 0xc2: case 0xc4: case 0xc5:
    case 0xc6:
        return modrm(d) && skip(d, 1);
    case 0x05: case 0x06: case 0x07: case 0x08: case 0x09: case 0x0b:
    case 0x0e: case 0x30: case 0x31: case 0x32: case 0x33: case 0x34:
    case 0x35: case 0x37: case 0x77: case 0xa0: case 0xa1: case 0xa2:
    case 0xa8: case 0xa9: case 0xaa: case 0xc8: case 0xc9: case 0xca:
    case 0xcb: case 0xcc: case 0xcd: case 0xce: case 0xcf:
        return true;
    default:
        return modrm(d);
    }
}

/* 15 bytes is the architectural maximum; a longer encoding raises #GP */
static int capped_len(const InsnDecoder *d)
{
    return d->pos <= 15 ? d->pos : 0;
}

/* VEX/XOP/EVEX: @map is the opcode map (1 = 0F, 2 = 0F 38, 3 = 0F 3A) */
static bool decode_vex_opcode(InsnDecoder *d, int map)
{
    int op = next(d);

    if (op < 0) {
        return false;
    }
    if (map == 1 && op == 0x77) {
        return true;                            /* VZEROUPPER/VZEROALL */
    }
    if (!modrm(d)) {
        return false;
    }
    if (map == 3 || map >= 8) {                 /* 0F 3A and XOP maps: imm8 */
        return skip(d, 1);
    }
    if (map == 1) {
        switch (op) {
        case 0x70: case 0x71: case 0x72: case 0x73: case 0xc2: case 0xc4:
        case 0xc5: case 0xc6:
            return skip(d, 1);
        }
    }
    return true;
}

/*
 * Length of the instruction at @buf, or 0 when the bytes do not form one
 * this decoder understands. @mode is the code segment's mode: 16, 32 or 64.
 */
int hyperv_vsm_insn_len(const uint8_t *buf, int len, int mode)
{
    InsnDecoder d = {
        .buf = buf, .len = len, .mode = mode,
        .opsize16 = mode == 16, .addrsize = mode / 8,
    };
    int op;

    for (;;) {
        op = next(&d);
        if (op < 0) {
            return 0;
        }
        switch (op) {
        case 0x26: case 0x2e: case 0x36: case 0x3e: case 0x64: case 0x65:
        case 0xf0: case 0xf2: case 0xf3:
            continue;
        case 0x66:
            d.opsize16 = mode != 16;
            continue;
        case 0x67:
            d.addrsize = mode == 16 ? 4 : mode == 32 ? 2 : 4;
            continue;
        }
        break;
    }

    if (mode == 64 && op >= 0x40 && op <= 0x4f) {
        d.rex_w = op & 8;
        if (d.rex_w) {
            d.opsize16 = false;         /* REX.W wins over a 66 prefix */
        }
        op = next(&d);
        if (op < 0) {
            return 0;
        }
    }

    /* VEX, XOP and EVEX share bytes with LES/LDS/BOUND/POP outside 64-bit */
    if (op == 0xc4 || op == 0xc5 || op == 0x62 || op == 0x8f) {
        int p0 = d.pos < len ? buf[d.pos] : -1;
        bool is_vex = mode == 64 || (p0 >= 0 && (p0 & 0xc0) == 0xc0);

        if (op == 0x8f && (p0 < 0 || (p0 & 0x1f) < 8)) {
            is_vex = false;                     /* POP r/m */
        }
        if (is_vex) {
            int map;

            if (op == 0xc5) {
                if (!skip(&d, 1)) {
                    return 0;
                }
                map = 1;
            } else if (op == 0x62) {
                if (!skip(&d, 3)) {
                    return 0;
                }
                map = p0 & 7;
            } else {
                if (!skip(&d, 2)) {
                    return 0;
                }
                map = p0 & 0x1f;
            }
            if (!decode_vex_opcode(&d, map)) {
                return 0;
            }
            return capped_len(&d);
        }
    }

    if (op == 0x0f) {
        if (!decode_0f(&d)) {
            return 0;
        }
    } else if (!decode_one_byte(&d, op)) {
        return 0;
    }
    return capped_len(&d);
}

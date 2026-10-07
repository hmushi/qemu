/*
 * Unit tests for the Hyper-V VSM x86 instruction length decoder
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/hyperv/hyperv-vsm-insn.h"

typedef struct {
    const char *name;
    int mode;
    int len;
    uint8_t b[16];
} InsnCase;

static const InsnCase cases[] = {
    { "add %al,(%rax) on a zero page", 64, 2, { 0x00, 0x00 } },
    { "mov (%rax),%rax", 64, 3, { 0x48, 0x8b, 0x00 } },
    { "nopl (%rax)", 64, 3, { 0x0f, 0x1f, 0x00 } },
    { "ret", 64, 1, { 0xc3 } },
    { "call *%rax", 64, 2, { 0xff, 0xd0 } },
    { "mov (%rsp),%rax", 64, 4, { 0x48, 0x8b, 0x04, 0x24 } },
    { "mov disp32(%rip),%rax", 64, 7,
      { 0x48, 0x8b, 0x05, 0x78, 0x56, 0x34, 0x12 } },
    { "movb $imm8,disp32(%rbx)", 64, 7,
      { 0xc6, 0x83, 0x78, 0x56, 0x34, 0x12, 0x55 } },
    { "movl $imm32,(%rax)", 64, 6, { 0xc7, 0x00, 1, 2, 3, 4 } },
    { "movabs $imm64,%rax", 64, 10, { 0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8 } },
    { "movaps (%rax),%xmm0", 64, 3, { 0x0f, 0x28, 0x00 } },
    { "vmovdqa (%rax),%ymm0", 64, 4, { 0xc5, 0xfd, 0x6f, 0x00 } },
    { "vpshufd $imm8,(%rax),%ymm0", 64, 5, { 0xc5, 0xfd, 0x70, 0x00, 0x1b } },
    { "vmovdqa64 (%rax),%zmm0", 64, 6,
      { 0x62, 0xf1, 0xfd, 0x48, 0x6f, 0x00 } },
    { "lock cmpxchg %ecx,8(%rdx)", 64, 5, { 0xf0, 0x0f, 0xb1, 0x4a, 0x08 } },
    { "rep movsb", 64, 2, { 0xf3, 0xa4 } },
    { "movzbl (%rbx,%rcx,4),%eax", 64, 4, { 0x0f, 0xb6, 0x04, 0x8b } },
    { "testl $imm32,(%rax)", 64, 6, { 0xf7, 0x00, 1, 2, 3, 4 } },
    { "testb $imm8,(%rax)", 64, 3, { 0xf6, 0x00, 0x55 } },
    { "mull (%rax)", 64, 2, { 0xf7, 0x20 } },
    { "movabs moffs64,%al", 64, 9, { 0xa0, 1, 2, 3, 4, 5, 6, 7, 8 } },
    { "mov moffs32,%eax (32-bit)", 32, 5, { 0xa1, 1, 2, 3, 4 } },
    { "mov disp16(%bx,%si),%ax (16-bit)", 16, 4, { 0x8b, 0x80, 1, 2 } },
    { "les (%ebx),%eax (32-bit)", 32, 2, { 0xc4, 0x03 } },
    { "crc32 (%rax),%eax", 64, 5, { 0xf2, 0x0f, 0x38, 0xf1, 0x00 } },
    { "palignr $imm8,(%rax),%xmm0", 64, 6,
      { 0x66, 0x0f, 0x3a, 0x0f, 0x00, 0x03 } },
    { "addq $imm32,(%rax)", 64, 7, { 0x48, 0x81, 0x00, 1, 2, 3, 4 } },
    { "fldl (%rax)", 64, 2, { 0xdd, 0x00 } },
    { "add %eax,(%r8)", 64, 3, { 0x41, 0x01, 0x00 } },

    /*
     * Encodings the kvm-unit-tests suite never produced, from a differential
     * sweep of the decoder against objdump over 457822 distinct instructions
     * in compiler-generated x86-64 objects plus 27695 swept opcode forms.
     *
     * REX.W overrides a 66 operand-size prefix, so the immediate stays 32-bit.
     * The data16 forms below are real encodings taken from libc and libcrypto,
     * where 66 66 is alignment padding ahead of a REX.W instruction.
     */
    { "data16 addq $imm32,(%rax)", 64, 8,
      { 0x66, 0x48, 0x81, 0x00, 0x12, 0x34, 0x56, 0x78 } },
    { "data16 data16 callq rel32", 64, 8,
      { 0x66, 0x66, 0x48, 0xe8, 0x0c, 0xc9, 0xff, 0xff } },
    { "data16 data16 xorq $imm32,%rax", 64, 8,
      { 0x66, 0x66, 0x4b, 0x35, 0x57, 0x88, 0x90, 0xf6 } },
    { "data16 movabs $imm64,%rax", 64, 11,
      { 0x66, 0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8 } },
    /* without REX.W the 66 prefix still shortens the immediate */
    { "addw $imm16,(%rax)", 64, 5, { 0x66, 0x81, 0x00, 0x12, 0x34 } },
    { "addw $imm16,(%eax) (32-bit)", 32, 5, { 0x66, 0x81, 0x00, 0x12, 0x34 } },
    { "addl $imm32,(%eax) (16-bit)", 16, 7,
      { 0x66, 0x81, 0x00, 0x12, 0x34, 0x56, 0x78 } },
};

static void test_lengths(void)
{
    for (int i = 0; i < ARRAY_SIZE(cases); i++) {
        const InsnCase *c = &cases[i];
        int n = hyperv_vsm_insn_len(c->b, sizeof(c->b), c->mode);

        g_assert_cmpint(n, ==, c->len);
    }
}

/* the buffer ends inside the instruction: no length, never a read past it */
static void test_truncated(void)
{
    const uint8_t mov[] = { 0x48, 0x8b, 0x05, 0x78, 0x56, 0x34, 0x12 };

    g_assert_cmpint(hyperv_vsm_insn_len(mov, 3, 64), ==, 0);
    g_assert_cmpint(hyperv_vsm_insn_len(mov, 7, 64), ==, 7);
    g_assert_cmpint(hyperv_vsm_insn_len(mov, 0, 64), ==, 0);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/hyperv-vsm-insn/lengths", test_lengths);
    g_test_add_func("/hyperv-vsm-insn/truncated", test_truncated);
    return g_test_run();
}

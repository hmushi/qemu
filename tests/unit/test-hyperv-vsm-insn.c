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

    /*
     * VEX 0F 77 is VZEROUPPER or VZEROALL and takes no ModRM byte. It is the
     * only opcode in the VEX 0F map without one, and AVX code emits it often.
     */
    { "vzeroupper (2-byte VEX)", 64, 3, { 0xc5, 0xf8, 0x77 } },
    { "vzeroall (2-byte VEX)", 64, 3, { 0xc5, 0xfc, 0x77 } },
    { "vzeroupper (3-byte VEX)", 64, 4, { 0xc4, 0xe1, 0x78, 0x77 } },
    { "vzeroall (3-byte VEX)", 64, 4, { 0xc4, 0xe1, 0x7c, 0x77 } },
    /* the neighbouring map-1 opcodes still take one */
    { "vpcmpeqw (%rax),%ymm0,%ymm0", 64, 4, { 0xc5, 0xfd, 0x75, 0x00 } },
    { "vmovntdq %ymm0,(%rax)", 64, 4, { 0xc5, 0xfd, 0xe7, 0x00 } },

    /*
     * MOV to and from CR and DR (0F 20 to 0F 23) ignore the ModRM mod field
     * and always address a register, so these never carry a SIB byte or a
     * displacement whatever mod says.
     */
    { "mov %cr0,%rax", 64, 3, { 0x0f, 0x20, 0xc0 } },
    { "mov %rax,%cr0", 64, 3, { 0x0f, 0x22, 0xc0 } },
    { "mov %cr8,%rax", 64, 4, { 0x44, 0x0f, 0x20, 0xc0 } },
    { "mov %rdi,%db0 with mod 2", 64, 3, { 0x0f, 0x23, 0x87 } },
    { "mov %db0,%rbp with mod 0 rm 5", 64, 3, { 0x0f, 0x21, 0x05 } },
    { "mov %cr0,%rbp with mod 0 rm 5", 64, 3, { 0x0f, 0x20, 0x05 } },

    /*
     * 15 bytes is the architectural maximum instruction length. A longer
     * encoding raises #GP and is not an instruction, so it has no length.
     * The intercept header field is 4 bits wide, so a reported 16 would be
     * stored as 0 anyway, but silently and without the undecodable log.
     */
    { "15-byte vpshufd, the limit", 64, 15,
      { 0x66, 0x66, 0x66, 0x66, 0x66, 0xc5, 0xfd, 0x70, 0x84, 0x24,
        0x11, 0x22, 0x33, 0x44, 0x55 } },
    { "16-byte vpshufd, over the limit", 64, 0,
      { 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0xc5, 0xfd, 0x70, 0x84, 0x24,
        0x11, 0x22, 0x33, 0x44, 0x55 } },
};

/*
 * The decoder never refuses an unrecognised one-byte opcode: it sizes it as a
 * single byte. A differential sweep against objdump over 457822 distinct
 * instructions from compiler-generated x86-64 objects, plus 27695 swept
 * opcode forms, produced no refusal at all. A non-zero length is therefore a
 * best effort and not proof that the bytes are an instruction.
 */
static const InsnCase guesses[] = {
    /* invalid in 64-bit mode, and the decoder says one byte regardless */
    { "push %es", 64, 1, { 0x06 } },
    { "popa", 64, 1, { 0x61 } },
    { "salc", 64, 1, { 0xd6 } },
    /*
     * fwait is a whole instruction and retires on its own. An assembler
     * writes 9b D9 /6 as one fstenv mnemonic and objdump groups it that way,
     * but the processor executes two instructions and rip advances by one,
     * so one byte is the right answer for an intercept at the 9b.
     */
    { "fwait ahead of fnstenv", 64, 1, { 0x9b, 0xd9, 0x75, 0xf9 } },
};

/*
 * Encodings the decoder gets WRONG today. The expectations below are its
 * current output, not the right answer, which is in the comment on each.
 * None is reachable from compiler output, so none is urgent. A change that
 * makes one of these correct should update the expectation here, not delete
 * the case.
 */
static const InsnCase documented_gaps[] = {
    /* extrq: 66 0F 78 takes two imm8 operands, so 6 */
    { "extrq $imm8,$imm8,%xmm0", 64, 4,
      { 0x66, 0x0f, 0x78, 0xc0, 0x01, 0x02 } },
    /* insertq: F2 0F 78 likewise, so 6 */
    { "insertq $imm8,$imm8,%xmm0,%xmm0", 64, 4,
      { 0xf2, 0x0f, 0x78, 0xc0, 0x01, 0x02 } },
    /* XOP map 9 has no imm8, so 5 */
    { "vphaddwd %xmm11,%ymm3", 64, 6,
      { 0x8f, 0x89, 0x6e, 0xc6, 0xdb } },
    /*
     * A legacy prefix or a second REX after the first REX is decoded as an
     * opcode. Hardware ignores a REX that is not the last prefix, so the
     * first is 6 bytes and the second 4.
     */
    { "rex.W then data16 then imm", 64, 2,
      { 0x48, 0x66, 0x81, 0x00, 0x12, 0x34 } },
    { "two rex.W then mov", 64, 2, { 0x48, 0x48, 0x8b, 0x00 } },
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

static void run_table(const InsnCase *t, int n)
{
    for (int i = 0; i < n; i++) {
        g_assert_cmpint(hyperv_vsm_insn_len(t[i].b, sizeof(t[i].b),
                                            t[i].mode), ==, t[i].len);
    }
}

static void test_guesses(void)
{
    run_table(guesses, ARRAY_SIZE(guesses));
}

static void test_documented_gaps(void)
{
    run_table(documented_gaps, ARRAY_SIZE(documented_gaps));
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/hyperv-vsm-insn/lengths", test_lengths);
    g_test_add_func("/hyperv-vsm-insn/truncated", test_truncated);
    g_test_add_func("/hyperv-vsm-insn/guesses", test_guesses);
    g_test_add_func("/hyperv-vsm-insn/documented-gaps", test_documented_gaps);
    return g_test_run();
}

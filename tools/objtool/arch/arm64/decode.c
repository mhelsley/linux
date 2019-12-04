// SPDX-License-Identifier: GPL-2.0-or-later

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "insn_decode.h"
#include "cfi_regs.h"
#include "bit_operations.h"

#include "../../check.h"
#include "../../arch.h"
#include "../../elf.h"
#include "../../warn.h"

static bool stack_related_reg(int reg)
{
	return reg == CFI_SP || reg == CFI_BP;
}

bool arch_callee_saved_reg(unsigned char reg)
{
	switch (reg) {
	case CFI_R19:
	case CFI_R20:
	case CFI_R21:
	case CFI_R22:
	case CFI_R23:
	case CFI_R24:
	case CFI_R25:
	case CFI_R26:
	case CFI_R27:
	case CFI_R28:
	case CFI_FP:
	case CFI_R30:
		return true;
	default:
		return false;
	}
}

void arch_initial_func_cfi_state(struct cfi_state *state)
{
	int i;

	for (i = 0; i < CFI_NUM_REGS; i++) {
		state->regs[i].base = CFI_UNDEFINED;
		state->regs[i].offset = 0;
	}

	/* initial CFA (call frame address) */
	state->cfa.base = CFI_SP;
	state->cfa.offset = 0;
}

unsigned long arch_dest_rela_offset(int addend)
{
	return addend;
}

unsigned long arch_jump_destination(struct instruction *insn)
{
	return insn->offset + insn->immediate;
}

static int is_arm64(struct elf *elf)
{
	switch (elf->ehdr.e_machine) {
	case EM_AARCH64: //0xB7
		return 1;
	default:
		WARN("unexpected ELF machine type %x",
		     elf->ehdr.e_machine);
		return 0;
	}
}

/*
 * static int (*arm_decode_class)(u32 instr,
 *				 unsigned int *len,
 *				 enum insn_type *type,
 *				 unsigned long *immediate,
 *				 struct list_head *ops_list);
 */
static arm_decode_class aarch64_insn_class_decode_table[NR_INSN_CLASS] = {
	[INSN_RESERVED]			= arm_decode_unknown,
	[INSN_UNKNOWN]			= arm_decode_unknown,
	[INSN_UNALLOC]			= arm_decode_unknown,
	[0b1000 ... INSN_DP_IMM]	= arm_decode_dp_imm,
};

/*
 * Arm A64 Instruction set' decode groups (based on op0 bits[28:25]):
 * Ob0000 - Reserved
 * 0b0001/0b001x - Unallocated
 * 0b100x - Data Processing -- Immediate
 * 0b101x - Branch, Exception Gen., System Instructions.
 * 0bx1x0 - Loads and Stores
 * 0bx101 - Data Processing -- Registers
 * 0bx111 - Data Processing -- Scalar Floating-Points, Advanced SIMD
 */

int arch_decode_instruction(struct elf *elf, struct section *sec,
			    unsigned long offset, unsigned int maxlen,
			    unsigned int *len, enum insn_type *type,
			    unsigned long *immediate,
			    struct list_head *ops_list)
{
	arm_decode_class decode_fun;
	int arm64 = 0;
	u32 insn = 0;
	int res;

	*len = 4;
	*immediate = 0;

	//test architucture (make sure it is arm64)
	arm64 = is_arm64(elf);
	if (arm64 != 1)
		return -1;

	//retrieve instruction (from sec->data->offset)
	insn = *(u32 *)(sec->data->d_buf + offset);

	//dispatch according to encoding classes
	decode_fun = aarch64_insn_class_decode_table[INSN_CLASS(insn)];
	if (decode_fun)
		res = decode_fun(insn, type, immediate, ops_list);
	else
		res = -1;

	if (res)
		WARN_FUNC("Unsupported instruction", sec, offset);
	return res;
}

int arm_decode_unknown(u32 instr, enum insn_type *type,
		       unsigned long *immediate, struct list_head *ops_list)
{
	/*
	 * There are a few reasons we might have non-valid opcodes in
	 * code sections:
	 * - For load literal, assembler can generate the data to be loaded in
	 *   the code section
	 * - Compiler/assembler can generate zeroes to pad function that do not
	 *   end on 8-byte alignment
	 * - Hand written assembly code might contain constants in the code
	 *   section
	 */
	*type = INSN_INVALID;

	return 0;
}

#define NR_DP_IMM_SUBCLASS	8
#define INSN_DP_IMM_SUBCLASS(opcode)			\
	(((opcode) >> 23) & (NR_DP_IMM_SUBCLASS - 1))

static arm_decode_class aarch64_insn_dp_imm_decode_table[NR_DP_IMM_SUBCLASS] = {
	[0 ... INSN_PCREL]	= arm_decode_pcrel,
	[INSN_ADD_SUB]		= arm_decode_add_sub,
	[INSN_ADD_TAG]		= arm_decode_add_sub_tags,
	[INSN_MOVE_WIDE]	= arm_decode_move_wide,
	[INSN_BITFIELD]		= arm_decode_bitfield,
	[INSN_EXTRACT]		= arm_decode_extract,
};

int arm_decode_dp_imm(u32 instr, enum insn_type *type,
		      unsigned long *immediate, struct list_head *ops_list)
{
	arm_decode_class decode_fun;

	decode_fun = aarch64_insn_dp_imm_decode_table[INSN_DP_IMM_SUBCLASS(instr)];
	if (!decode_fun)
		return -1;
	return decode_fun(instr, type, immediate, ops_list);
}

int arm_decode_pcrel(u32 instr, enum insn_type *type,
		     unsigned long *immediate, struct list_head *ops_list)
{
	unsigned char page = 0;
	u32 immhi = 0, immlo = 0;

	page = EXTRACT_BIT(instr, 31);
	immhi = (instr >> 5) & ONES(19);
	immlo = (instr >> 29) & ONES(2);

	*immediate = SIGN_EXTEND((immhi << 2) | immlo, 21);

	if (page)
		*immediate = SIGN_EXTEND(*immediate << 12, 33);

	*type = INSN_OTHER;

	return 0;
}

int arm_decode_add_sub(u32 instr, enum insn_type *type,
		       unsigned long *immediate, struct list_head *ops_list)
{
	unsigned long imm12 = 0, imm = 0;
	unsigned char sf = 0, sh = 0, S = 0, op_bit = 0;
	unsigned char rn = 0, rd = 0;

	S = EXTRACT_BIT(instr, 29);
	op_bit = EXTRACT_BIT(instr, 30);
	sf = EXTRACT_BIT(instr, 31);
	sh = EXTRACT_BIT(instr, 22);
	rd = instr & ONES(5);
	rn = (instr >> 5) & ONES(5);
	imm12 = (instr >> 10) & ONES(12);
	imm = ZERO_EXTEND(imm12 << (sh * 12), (sf + 1) * 32);

	*type = INSN_OTHER;

	if (rd == CFI_BP || (!S && rd == CFI_SP) || stack_related_reg(rn)) {
		struct stack_op *op;

		*type = INSN_STACK;

		op = calloc(1, sizeof(*op));
		list_add_tail(&op->list, ops_list);

		op->dest.type = OP_DEST_REG;
		op->dest.offset = 0;
		op->dest.reg = rd;
		op->src.type = OP_SRC_ADD;
		op->src.offset = op_bit ? -1 * imm : imm;
		op->src.reg = rn;
	}
	return 0;
}

int arm_decode_add_sub_tags(u32 instr, enum insn_type *type,
			    unsigned long *immediate,
			    struct list_head *ops_list)
{
	unsigned char decode_field = 0, rn = 0, rd = 0, uimm6 = 0;

	decode_field = (instr >> 29) & ONES(3);
	rd = instr & ONES(5);
	rn = (instr >> 5) & ONES(5);
	uimm6 = (instr >> 16) & ONES(6);

	*immediate = uimm6;
	*type = INSN_OTHER;

#define ADDG_DECODE	4
#define SUBG_DECODE	5
	if (decode_field != ADDG_DECODE && decode_field != SUBG_DECODE)
		return arm_decode_unknown(instr, type, immediate, ops_list);

#undef ADDG_DECODE
#undef SUBG_DECODE

	if (stack_related_reg(rd)) {
		struct stack_op *op;

		*type = INSN_STACK;

		op = calloc(1, sizeof(*op));
		list_add_tail(&op->list, ops_list);

		op->dest.type = OP_DEST_REG;
		op->dest.offset = 0;
		op->dest.reg = rd;
		op->src.type = OP_SRC_ADD;
		op->src.offset = 0;
		op->src.reg = rn;
	}

	return 0;
}

int arm_decode_move_wide(u32 instr, enum insn_type *type,
			 unsigned long *immediate, struct list_head *ops_list)
{
	u32 imm16 = 0;
	unsigned char hw = 0, opc = 0, sf = 0;

	sf = EXTRACT_BIT(instr, 31);
	opc = (instr >> 29) & ONES(2);
	hw = (instr >> 21) & ONES(2);
	imm16 = (instr >> 5) & ONES(16);

	if ((sf == 0 && (hw & 0x2)) || opc == 0x1)
		return arm_decode_unknown(instr, type, immediate, ops_list);

	*type = INSN_OTHER;
	*immediate = imm16;

	return 0;
}

int arm_decode_bitfield(u32 instr, enum insn_type *type,
			unsigned long *immediate, struct list_head *ops_list)
{
	unsigned char sf = 0, opc = 0, N = 0;

	sf = EXTRACT_BIT(instr, 31);
	opc = (instr >> 29) & ONES(2);
	N = EXTRACT_BIT(instr, 22);

	if (opc == 0x3 || sf != N)
		return arm_decode_unknown(instr, type, immediate, ops_list);

	*type = INSN_OTHER;

	return 0;
}

int arm_decode_extract(u32 instr, enum insn_type *type,
		       unsigned long *immediate, struct list_head *ops_list)
{
	unsigned char sf = 0, op21 = 0, N = 0, o0 = 0;
	unsigned char imms = 0;
	unsigned char decode_field = 0;

	sf = EXTRACT_BIT(instr, 31);
	op21 = (instr >> 29) & ONES(2);
	N = EXTRACT_BIT(instr, 22);
	o0 = EXTRACT_BIT(instr, 21);
	imms = (instr >> 10) & ONES(6);

	decode_field = (sf << 4) | (op21 << 2) | (N << 1) | o0;
	*type = INSN_OTHER;
	*immediate = imms;

	if ((decode_field == 0 && !EXTRACT_BIT(imms, 5)) ||
	    decode_field == 0b10010)
		return 0;

	return arm_decode_unknown(instr, type, immediate, ops_list);
}

/*
 * Copyright (C) 2019 Raphael Gault <raphael.gault@arm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "insn_decode.h"
#include "cfi.h"
#include "bit_operations.h"

#include "../../check.h"
#include "../../arch.h"
#include "../../elf.h"
#include "../../warn.h"

/*
 * static int (*arm_decode_class)(u32 instr,
 *				 unsigned int *len,
 *				 enum insn_type *type,
 *				 unsigned long *immediate,
 *				 struct stack_op *op);
 */
static arm_decode_class aarch64_insn_class_decode_table[] = {
	[INSN_RESERVED]			= arm_decode_reserved,
	[INSN_UNALLOC_1]		= arm_decode_unknown,
	[INSN_SVE_ENC]			= arm_decode_sve_encoding,
	[INSN_UNALLOC_2]		= arm_decode_unknown,
	[INSN_LD_ST_4]			= arm_decode_ld_st,
	[INSN_DP_REG_5]			= arm_decode_dp_reg,
	[INSN_LD_ST_6]			= arm_decode_ld_st,
	[INSN_DP_SIMD_7]		= arm_decode_dp_simd,
	[0b1000 ... INSN_DP_IMM]	= arm_decode_dp_imm,
	[0b1010 ... INSN_BRANCH]	= arm_decode_br_sys,
	[INSN_LD_ST_C]			= arm_decode_ld_st,
	[INSN_DP_REG_D]			= arm_decode_dp_reg,
	[INSN_LD_ST_E]			= arm_decode_ld_st,
	[INSN_DP_SIMD_F]		= arm_decode_dp_simd,
};

static arm_decode_class aarch64_insn_dp_imm_decode_table[] = {
	[0 ... INSN_PCREL]	= arm_decode_pcrel,
	[INSN_ADD_SUB]		= arm_decode_add_sub,
	[INSN_ADD_TAG]		= arm_decode_add_sub_tags,
	[INSN_LOGICAL]		= arm_decode_logical,
	[INSN_MOVE_WIDE]	= arm_decode_move_wide,
	[INSN_BITFIELD]		= arm_decode_bitfield,
	[INSN_EXTRACT]		= arm_decode_extract,
};

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

/*
 * In order to know if we are in presence of a sibling
 * call and not in presence of a switch table we look
 * back at the previous instructions and see if we are
 * jumping inside the same function that we are already
 * in.
 */
bool arch_is_insn_sibling_call(struct instruction *insn)
{
	struct instruction *prev;
	struct list_head *l;
	struct symbol *sym;
	list_for_each_prev(l, &insn->list) {
		prev = list_entry(l, struct instruction, list);
		if (!prev->func ||
		    prev->func->pfunc != insn->func->pfunc)
			return false;
		if (prev->stack_op.src.reg != ADR_SOURCE)
			continue;
		sym = find_symbol_containing(insn->sec, insn->immediate);
		if (!sym || sym->type != STT_FUNC)
			return false;
		else if (sym->type == STT_FUNC)
			return true;
		break;
	}
	return false;
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
			    unsigned long *immediate, struct stack_op *op)
{
	int arm64 = 0;
	u32 insn = 0;

	*len = 4;
	*immediate = 0;

	op->dest.type = 0;
	op->dest.reg = 0;
	op->dest.offset = 0;
	op->src.type = 0;
	op->src.reg = 0;
	op->src.offset = 0;

	//test architucture (make sure it is arm64)
	arm64 = is_arm64(elf);
	if (arm64 != 1)
		return -1;

	//retrieve instruction (from sec->data->offset)
	insn = *(u32 *)(sec->data->d_buf + offset);

	//dispatch according to encoding classes
	return aarch64_insn_class_decode_table[(insn >> 25) & 0xf](insn, type,
							immediate, op);
}

int arm_decode_unknown(u32 instr, enum insn_type *type,
		       unsigned long *immediate, struct stack_op *op)
{
	*type = INSN_UNKNOWN;
	return 0;
}

int arm_decode_dp_simd(u32 instr, enum insn_type *type,
		       unsigned long *immediate, struct stack_op *op)
{
	*type = INSN_OTHER;
	return 0;
}

int arm_decode_reserved(u32 instr, enum insn_type *type,
			unsigned long *immediate, struct stack_op *op)
{
	*immediate = instr & ONES(16);
	*type = INSN_UNKNOWN;
	return 0;
}

int arm_decode_dp_imm(u32 instr, enum insn_type *type,
		      unsigned long *immediate, struct stack_op *op)
{
	return aarch64_insn_dp_imm_decode_table[(instr >> 23) & 0x7](instr,
							type, immediate, op);
}

int arm_decode_pcrel(u32 instr, enum insn_type *type,
		     unsigned long *immediate, struct stack_op *op)
{
	unsigned char rd = 0, page = 0;
	u32 immhi = 0, immlo = 0;

	page = EXTRACT_BIT(instr, 31);
	rd = instr & 0x1F;
	immhi = (instr >> 5) & ONES(19);
	immlo = (instr >> 29) & ONES(2);

	*immediate = SIGN_EXTEND((immhi << 2) | immlo, 21);

	if (page)
		*immediate = SIGN_EXTEND(*immediate << 12, 33);

	*type = INSN_OTHER;
	op->src.reg = ADR_SOURCE;
	op->dest.reg = rd;

	return 0;
}

int arm_decode_add_sub(u32 instr, enum insn_type *type,
		       unsigned long *immediate, struct stack_op *op)
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

	if ((!S && rd == CFI_SP) || rn == CFI_SP) {
		*type = INSN_STACK;
		op->dest.type = OP_DEST_REG;
		op->dest.offset = 0;
		op->dest.reg = rd;
		op->src.type = imm12 ? OP_SRC_ADD : OP_SRC_REG;
		op->src.offset = op_bit ? -1 * imm : imm;
		op->src.reg = rn;
	}
	return 0;
}

int arm_decode_add_sub_tags(u32 instr, enum insn_type *type,
			    unsigned long *immediate, struct stack_op *op)
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
		return arm_decode_unknown(instr, type, immediate, op);

#undef ADDG_DECODE
#undef SUBG_DECODE
	op->dest.type = OP_DEST_REG;
	op->dest.offset = 0;
	op->dest.reg = rd;
	op->src.type = OP_SRC_ADD;
	op->src.offset = 0;
	op->src.reg = rn;

	if (rd == CFI_SP)
		*type = INSN_STACK;

	return 0;
}

int arm_decode_logical(u32 instr, enum insn_type *type,
		       unsigned long *immediate, struct stack_op *op)
{
	unsigned char sf = 0, opc = 0, N = 0;
	unsigned char imms = 0, immr = 0, rn = 0, rd = 0;

	rd = instr & ONES(5);
	rn = (instr >> 5) & ONES(5);

	imms = (instr >> 10) & ONES(6);
	immr = (instr >> 16) & ONES(6);

	N = EXTRACT_BIT(instr, 22);
	opc = (instr >> 29) & ONES(2);
	sf = EXTRACT_BIT(instr, 31);

	if (N == 1 && sf == 0)
		return arm_decode_unknown(instr, type, immediate, op);

	*type = INSN_OTHER;
	*immediate = (decode_bit_masks(N, imms, immr, true) >> 64);
#define ANDS_DECODE	0b11
	if (opc == ANDS_DECODE)
		return 0;
#undef ANDS_DECODE
	if (rd == CFI_SP) {
		*type = INSN_STACK;
		op->dest.type = OP_DEST_REG;
		op->dest.offset = 0;
		op->dest.reg = CFI_SP;

		op->src.type = OP_SRC_AND;
		op->src.offset = 0;
		op->src.reg = rn;
	}

	return 0;
}

int arm_decode_move_wide(u32 instr, enum insn_type *type,
			 unsigned long *immediate, struct stack_op *op)
{
	u32 imm16 = 0;
	unsigned char hw = 0, opc = 0, sf = 0;

	sf = EXTRACT_BIT(instr, 31);
	opc = (instr >> 29) & ONES(2);
	hw = (instr >> 21) & ONES(2);
	imm16 = (instr >> 5) & ONES(16);

	if ((sf == 0 && (hw & 0x2)) || opc == 0x1)
		return arm_decode_unknown(instr, type, immediate, op);

	*type = INSN_OTHER;
	*immediate = imm16;

	return 0;
}

int arm_decode_bitfield(u32 instr, enum insn_type *type,
			unsigned long *immediate, struct stack_op *op)
{
	unsigned char sf = 0, opc = 0, N = 0;

	sf = EXTRACT_BIT(instr, 31);
	opc = (instr >> 29) & ONES(2);
	N = EXTRACT_BIT(instr, 22);

	if (opc == 0x3 || sf != N)
		return arm_decode_unknown(instr, type, immediate, op);

	*type = INSN_OTHER;

	return 0;
}

int arm_decode_extract(u32 instr, enum insn_type *type,
		       unsigned long *immediate, struct stack_op *op)
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

	return arm_decode_unknown(instr, type, immediate, op);
}

static struct aarch64_insn_decoder br_sys_decoder[] = {
	{
		.mask = 0b1111000000000000000000,
		.value = 0b0100000000000000000000,
		.decode_func = arm_decode_br_cond_imm,
	},
	{
		.mask = 0b1111100000000000000000,
		.value = 0b1100000000000000000000,
		.decode_func = arm_decode_except_gen,
	},
	{
		.mask = 0b1111111111111111111111,
		.value = 0b1100100000011001011111,
		.decode_func = arm_decode_hints,
	},
	{
		.mask = 0b1111111111111111100000,
		.value = 0b1100100000011001100000,
		.decode_func = arm_decode_barriers,
	},
	{
		.mask = 0b1111111111000111100000,
		.value = 0b1100100000000010000000,
		.decode_func = arm_decode_pstate,
	},
	{
		.mask = 0b1111111011000000000000,
		.value = 0b1100100001000000000000,
		.decode_func = arm_decode_system_insn,
	},
	{
		.mask = 0b1111111010000000000000,
		.value = 0b1100100010000000000000,
		.decode_func = arm_decode_system_regs,
	},
	{
		.mask = 0b1111000000000000000000,
		.value = 0b1101000000000000000000,
		.decode_func = arm_decode_br_uncond_reg,
	},
	{
		.mask = 0b0110000000000000000000,
		.value = 0b0000000000000000000000,
		.decode_func = arm_decode_br_uncond_imm,
	},
	{
		.mask = 0b0111000000000000000000,
		.value = 0b0010000000000000000000,
		.decode_func = arm_decode_br_comp_imm,
	},
	{
		.mask = 0b0111000000000000000000,
		.value = 0b0011000000000000000000,
		.decode_func = arm_decode_br_tst_imm,
	},

};

int arm_decode_br_sys(u32 instr, enum insn_type *type,
		      unsigned long *immediate, struct stack_op *op)
{
	u32 decode_field = 0, op1 = 0;
	unsigned char op0 = 0, op2 = 0;
	int i = 0;

	op0 = (instr >> 29) & ONES(3);
	op1 = (instr >> 12) & ONES(14);
	op2 = instr & ONES(5);

	decode_field = op0;
	decode_field = (decode_field << 19) | (op1 << 5) | op2;

	for (i = 0; i < ARRAY_SIZE(br_sys_decoder); i++) {
		if ((decode_field & br_sys_decoder[i].mask) ==
		    br_sys_decoder[i].value) {
			return br_sys_decoder[i].decode_func(instr,
							     type,
							     immediate,
							     op);
		}
	}

	return arm_decode_unknown(instr, type, immediate, op);
}

int arm_decode_br_cond_imm(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op)
{
	unsigned char o0 = 0, o1 = 0;
	u32 imm19;

	o0 = EXTRACT_BIT(instr, 4);
	o1 = EXTRACT_BIT(instr, 24);
	imm19 = (instr >> 5) & ONES(19);

	*immediate = SIGN_EXTEND(imm19 << 2, 19);

	if ((o1 << 1) | o0)
		return arm_decode_unknown(instr, type, immediate, op);

	*type = INSN_JUMP_CONDITIONAL;

	return 0;
}

static struct aarch64_insn_decoder except_gen_decoder[] = {
	{
		.mask = 0b00000100,
		.value = 0b00000100,
	},
	{
		.mask = 0b00001000,
		.value = 0b00001000,
	},
	{
		.mask = 0b00010000,
		.value = 0b00010000,
	},
	{
		.mask = 0b11111111,
		.value = 0b00000000,
	},
	{
		.mask = 0b11111101,
		.value = 0b00100001,
	},
	{
		.mask = 0b11111110,
		.value = 0b00100010,
	},
	{
		.mask = 0b11111101,
		.value = 0b01000001,
	},
	{
		.mask = 0b11111110,
		.value = 0b01000010,
	},
	{
		.mask = 0b11111111,
		.value = 0b01100001,
	},
	{
		.mask = 0b11111110,
		.value = 0b01100010,
	},
	{
		.mask = 0b11111111,
		.value = 0b10000000,
	},
	{
		.mask = 0b11111111,
		.value = 0b10100000,
	},
	{
		.mask = 0b11111100,
		.value = 0b11000000,
	},
	{
		.mask = 0b11111111,
		.value = 0b11100001,
	},
	{
		.mask = 0b11111110,
		.value = 0b11100010,
	},
};

int arm_decode_except_gen(u32 instr, enum insn_type *type,
			  unsigned long *immediate, struct stack_op *op)
{
	u32 imm16 = 0;
	unsigned char opc = 0, op2 = 0, LL = 0, decode_field = 0;
	int i = 0;

	imm16 = (instr >> 5) & ONES(16);
	opc = (instr >> 21) & ONES(3);
	op2 = (instr >> 2) & ONES(3);
	LL = instr & ONES(2);
	decode_field = (opc << 5) | (op2 << 2) | LL;

	for (i = 0; i < ARRAY_SIZE(except_gen_decoder); i++) {
		if ((decode_field & except_gen_decoder[i].mask) ==
		    except_gen_decoder[i].value) {
			return arm_decode_unknown(instr, type, immediate, op);
		}
	}

#define INSN_SVC	0b00000001
#define INSN_HVC	0b00000010
#define INSN_SMC	0b00000011
#define INSN_BRK	0b00100000
#define INSN_HLT	0b01000000
#define INSN_DCPS1	0b10100001
#define INSN_DCPS2	0b10100010
#define INSN_DCPS3	0b10100011

	switch (decode_field) {
	case INSN_SVC:
	case INSN_HVC:
	case INSN_SMC:
		/*
		 * We consider that the context will be restored correctly
		 * with an unchanged sp and the same general registers
		 */
		*type = INSN_NOP;
		return 0;
	case INSN_BRK:
		/*
		 * brk #0x800 is generated by the BUG()/WARN() linux API and is
		 * thus a particular case. Since those are not necessarily
		 * compiled in, the surrounding code should work properly
		 * without it. We thus consider it as a nop.
		 */
		if (imm16 == 0x800)
			*type = INSN_NOP;
		else if (imm16 == 0x100 || imm16 >= 0x900)
			*type = INSN_CONTEXT_SWITCH;
		else
			*type = INSN_OTHER;
		return 0;
	case INSN_HLT:
	case INSN_DCPS1:
	case INSN_DCPS2:
	case INSN_DCPS3:
		*immediate = imm16;
		*type = INSN_OTHER;
		return 0;
	default:
		return arm_decode_unknown(instr, type, immediate, op);
	}

#undef INSN_SVC
#undef INSN_HVC
#undef INSN_SMC
#undef INSN_BRK
#undef INSN_HLT
#undef INSN_DCPS1
#undef INSN_DCPS2
#undef INSN_DCPS3
}

int arm_decode_hints(u32 instr, enum insn_type *type,
		     unsigned long *immediate, struct stack_op *op)
{
	*type = INSN_NOP;
	return 0;
}

int arm_decode_barriers(u32 instr, enum insn_type *type,
			unsigned long *immediate, struct stack_op *op)
{
	/* TODO:check unallocated */
	*type = INSN_OTHER;
	return 0;
}

int arm_decode_pstate(u32 instr, enum insn_type *type,
		      unsigned long *immediate, struct stack_op *op)
{
	/* TODO:check unallocated */
	*type = INSN_OTHER;
	return 0;
}

int arm_decode_system_insn(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op)
{
	/* TODO:check unallocated */
	*type = INSN_OTHER;
	return 0;
}

int arm_decode_system_regs(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op)
{
	/* TODO:check unallocated */
	*type = INSN_OTHER;
	return 0;
}

static struct aarch64_insn_decoder ret_decoder[] = {
	/*
	 * RET, RETAA, RETAB
	 */
	{
		.mask = 0b1111111111111110000011111,
		.value = 0b0010111110000000000000000,
		.decode_func = NULL,
	},
	{
		.mask = 0b1111111111111111111111111,
		.value = 0b0010111110000101111111111,
		.decode_func = NULL,
	},
	{
		.mask = 0b1111111111111111111111111,
		.value = 0b0010111110000111111111111,
		.decode_func = NULL,
	},
};

static struct aarch64_insn_decoder br_decoder[] = {
	/*
	 * BR, BRAA, BRAAZ, BRAB, BRABZ
	 */
	{
		.mask = 0b1111111111111110000011111,
		.value = 0b0000111110000000000000000,
		.decode_func = NULL,
	},
	{
		.mask = 0b1111111111111110000011111,
		.value = 0b0000111110000100000011111,
		.decode_func = NULL,
	},
	{
		.mask = 0b1111111111111110000011111,
		.value = 0b0000111110000110000011111,
		.decode_func = NULL,
	},
	{
		.mask = 0b1111111111111110000000000,
		.value = 0b1000111110000100000000000,
		.decode_func = NULL,
	},
	{
		.mask = 0b1111111111111110000000000,
		.value = 0b1000111110000110000000000,
		.decode_func = NULL,
	},
};

#define INSN_DRPS_FIELD		0b0101111110000001111100000
#define INSN_DRPS_MASK		0b1111111111111111111111111

static struct aarch64_insn_decoder ct_sw_decoder[] = {
	/*
	 * ERET, ERETAA, ERETAB
	 */
	{
		.mask = INSN_DRPS_MASK,
		.value = 0b0100111110000001111100000,
		.decode_func = NULL,
	},
	{
		.mask = INSN_DRPS_MASK,
		.value = 0b0100111110000101111111111,
		.decode_func = NULL,
	},
	{
		.mask = INSN_DRPS_MASK,
		.value = 0b0100111110000111111111111,
		.decode_func = NULL,
	},
};

static struct aarch64_insn_decoder call_decoder[] = {
	/*
	 * BLR, BLRAA, BLRAAZ, BLRAB, BLRABZ
	 */
	{
		.mask = 0b1111111111111110000011111,
		.value =  0b0001111110000000000000000,
		.decode_func = NULL,
	},
	{
		.mask = 0b1111111111111110000011111,
		.value = 0b0001111110000100000011111,
		.decode_func = NULL,
	},
	{
		0b1111111111111110000011111,
		0b0001111110000110000011111,
		.decode_func = NULL,
	},
	{
		.mask = 0b1111111111111110000000000,
		.value = 0b1001111110000100000000000,
		.decode_func = NULL,
	},
	{
		.mask = 0b1111111111111110000000000,
		.value = 0b1001111110000110000000000,
		.decode_func = NULL,
	},
};

int arm_decode_br_uncond_reg(u32 instr, enum insn_type *type,
			     unsigned long *immediate, struct stack_op *op)
{
	u32 decode_field = 0;
	int i = 0;

	decode_field = instr & ONES(25);
	*type = 0;
	for (i = 0; i < ARRAY_SIZE(br_decoder); i++) {
		if ((decode_field & br_decoder[i].mask) == br_decoder[i].value)
			*type = INSN_JUMP_DYNAMIC;
	}
	for (i = 0; i < ARRAY_SIZE(call_decoder); i++) {
		if ((decode_field & call_decoder[i].value) ==
		    call_decoder[i].value)
			*type = INSN_CALL_DYNAMIC;
	}
	for (i = 0; i < ARRAY_SIZE(ret_decoder); i++) {
		if ((decode_field & ret_decoder[i].mask) ==
		    ret_decoder[i].value)
			*type = INSN_RETURN;
	}
	for (i = 0; i < ARRAY_SIZE(ct_sw_decoder); i++) {
		if ((decode_field & ct_sw_decoder[i].mask) ==
		    ct_sw_decoder[i].value)
			*type = INSN_CONTEXT_SWITCH;
	}
	if ((decode_field & INSN_DRPS_MASK) == INSN_DRPS_FIELD)
		*type = INSN_OTHER;
	if (*type == 0)
		return arm_decode_unknown(instr, type, immediate, op);
	return 0;
}

#undef INSN_DRPS_FIELD
#undef INSN_DRPS_MASK

int arm_decode_br_uncond_imm(u32 instr, enum insn_type *type,
			     unsigned long *immediate, struct stack_op *op)
{
	unsigned char decode_field = 0;
	u32 imm26 = 0;

	decode_field = EXTRACT_BIT(instr, 31);
	imm26 = instr & ONES(26);

	*immediate = SIGN_EXTEND(imm26 << 2, 28);
	if (decode_field == 0)
		*type = INSN_JUMP_UNCONDITIONAL;
	else
		*type = INSN_CALL;

	return 0;
}

int arm_decode_br_comp_imm(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op)
{
	u32 imm19 = (instr >> 5) & ONES(19);

	*immediate = SIGN_EXTEND(imm19 << 2, 21);
	*type = INSN_JUMP_CONDITIONAL;
	return 0;
}

int arm_decode_br_tst_imm(u32 instr, enum insn_type *type,
			  unsigned long *immediate, struct stack_op *op)
{
	u32 imm14 = (instr >> 5) & ONES(14);

	*immediate = SIGN_EXTEND(imm14 << 2, 16);
	*type = INSN_JUMP_CONDITIONAL;
	return 0;
}

static struct aarch64_insn_decoder ld_st_decoder[] = {
	{
		.mask = 0b101111111111100,
		.value = 0b000010000000000,
		.decode_func = arm_decode_adv_simd_mult,
	},
	{
		.mask = 0b101111110000000,
		.value = 0b000010100000000,
		.decode_func = arm_decode_adv_simd_mult_post,
	},
	{
		.mask = 0b101111101111100,
		.value = 0b000011000000000,
		.decode_func = arm_decode_adv_simd_single,
	},
	{
		.mask = 0b101111100000000,
		.value = 0b000011100000000,
		.decode_func = arm_decode_adv_simd_single_post,
	},
	{
		.mask = 0b111111010000000,
		.value = 0b110101010000000,
		.decode_func = arm_decode_ld_st_mem_tags,
	},
	{
		.mask = 0b001111000000000,
		.value = 0b000000000000000,
		.decode_func = arm_decode_ld_st_exclusive,
	},
	{
		.mask = 0b001111010000011,
		.value = 0b000101000000000,
		.decode_func = arm_decode_ldapr_stlr_unsc_imm,
	},
	{
		.mask = 0b001101000000000,
		.value = 0b000100000000000,
		.decode_func = arm_decode_ld_regs_literal,
	},
	{
		.mask = 0b001101100000000,
		.value = 0b001000000000000,
		.decode_func = arm_decode_ld_st_noalloc_pair_off,
	},
	{
		.mask = 0b001101100000000,
		.value = 0b001000100000000,
		.decode_func = arm_decode_ld_st_regs_pair_post,
	},
	{
		.mask = 0b001101100000000,
		.value = 0b001001000000000,
		.decode_func = arm_decode_ld_st_regs_pair_off,
	},
	{
		.mask = 0b001101100000000,
		.value = 0b001001100000000,
		.decode_func = arm_decode_ld_st_regs_pair_pre,
	},
	{
		.mask = 0b001101010000011,
		.value = 0b001100000000000,
		.decode_func = arm_decode_ld_st_regs_unsc_imm,
	},
	{
		.mask = 0b001101010000011,
		.value = 0b001100000000001,
		.decode_func = arm_decode_ld_st_imm_post,
	},
	{
		.mask = 0b001101010000011,
		.value = 0b001100000000010,
		.decode_func = arm_decode_ld_st_imm_unpriv,
	},
	{
		.mask = 0b001101010000011,
		.value = 0b001100000000011,
		.decode_func = arm_decode_ld_st_imm_pre,
	},
	{
		.mask = 0b001101010000011,
		.value = 0b001100010000000,
		.decode_func = arm_decode_atomic,
	},
	{
		.mask = 0b001101010000011,
		.value = 0b001100010000010,
		.decode_func = arm_decode_ld_st_regs_off,
	},
	{
		.mask = 0b001101010000001,
		.value = 0b001100010000001,
		.decode_func = arm_decode_ld_st_regs_pac,
	},
	{
		.mask = 0b001101000000000,
		.value = 0b001101000000000,
		.decode_func = arm_decode_ld_st_regs_unsigned,
	},
};

int arm_decode_ld_st(u32 instr, enum insn_type *type,
		     unsigned long *immediate, struct stack_op *op)
{
	u32 decode_field = 0;
	int i = 0;
	unsigned char op0 = 0, op1 = 0, op2 = 0, op3 = 0, op4 = 0;

	op0 = (instr >> 28) & ONES(4);
	op1 = EXTRACT_BIT(instr, 26);
	op2 = (instr >> 23) & ONES(2);
	op3 = (instr >> 16) & ONES(6);
	op4 = (instr >> 10) & ONES(2);
	decode_field = (op0 << 3) | (op1 << 2) | op2;
	decode_field = (decode_field << 8) | (op3 << 2) | op4;

	for (i = 0; i < ARRAY_SIZE(ld_st_decoder); i++) {
		if ((decode_field & ld_st_decoder[i].mask) ==
		    ld_st_decoder[i].value) {
			return ld_st_decoder[i].decode_func(instr,
							    type,
							    immediate,
							    op);
		}
	}
	return arm_decode_unknown(instr, type, immediate, op);
}

static int adv_simd_mult_fields[] = {
	0b00000,
	0b00010,
	0b00100,
	0b00110,
	0b00111,
	0b01000,
	0b01010,
	0b10000,
	0b10010,
	0b10100,
	0b10110,
	0b10111,
	0b11000,
	0b11010,
};

int arm_decode_adv_simd_mult(u32 instr, enum insn_type *type,
			     unsigned long *immediate, struct stack_op *op)
{
	unsigned char L = 0, opcode = 0, rn = 0, rt = 0;
	unsigned char decode_field = 0;
	int i = 0;

	L = EXTRACT_BIT(instr, 22);
	opcode = (instr >> 12) & ONES(4);

	decode_field = (L << 4) | opcode;
	rn = (instr >> 5) & ONES(5);
	rt = instr & ONES(5);
	*type = INSN_OTHER;

	for (i = 0; i < ARRAY_SIZE(adv_simd_mult_fields); i++) {
		if ((decode_field & 0b11111) == adv_simd_mult_fields[i]) {
			if (rn != 31)
				return 0;
			*type = INSN_STACK;
		}
	}
	if (*type != INSN_STACK)
		return arm_decode_unknown(instr, type, immediate, op);

	if (!L) {
		op->dest.type = OP_DEST_REG_INDIRECT;
		op->dest.reg = CFI_SP;
		op->dest.offset = 0;
		op->src.type = OP_SRC_REG;
		op->src.reg = rt;
		op->src.offset = 0;
	} else {
		op->src.type = OP_SRC_REG_INDIRECT;
		op->src.reg = CFI_SP;
		op->src.offset = 0;
		op->dest.type = OP_SRC_REG;
		op->dest.reg = rt;
		op->dest.offset = 0;
	}

	return 0;
}

int arm_decode_adv_simd_mult_post(u32 instr, enum insn_type *type,
				  unsigned long *immediate,
				  struct stack_op *op)
{
	/* same opcode as for the no offset variant */
	unsigned char rm = 0;
	int ret = 0;

	rm = (instr >> 16) & ONES(5);

	ret = arm_decode_adv_simd_mult(instr, type, immediate, op);

	/*
	 * This is actually irrelevant if the offset is given by a register
	 * however there is no way to know the offset value from the encoding
	 * in such a case.
	 */
	if (op->dest.type == OP_DEST_REG_INDIRECT)
		op->dest.offset = rm;
	if (op->src.type == OP_SRC_REG_INDIRECT)
		op->src.offset = rm;
	return ret;
}

static struct aarch64_insn_decoder simd_single_decoder[] = {
	{
		.mask = 0b11111000,
		.value = 0b00000000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111000,
		.value = 0b00001000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111001,
		.value = 0b00010000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111001,
		.value = 0b00011000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111011,
		.value = 0b00100000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111111,
		.value = 0b00100001,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111011,
		.value = 0b00101000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111111,
		.value = 0b00101001,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111000,
		.value = 0b01000000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111000,
		.value = 0b01001000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111001,
		.value = 0b01010000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111001,
		.value = 0b01011000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111011,
		.value = 0b01100000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111111,
		.value = 0b01100001,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111011,
		.value = 0b01101000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111111,
		.value = 0b01101001,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111000,
		.value = 0b10000000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111000,
		.value = 0b10001000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111001,
		.value = 0b10010000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111001,
		.value = 0b10011000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111011,
		.value = 0b10100000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111111,
		.value = 0b10100001,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111011,
		.value = 0b10101000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111111,
		.value = 0b10101001,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111100,
		.value = 0b10110000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111100,
		.value = 0b10111000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11000000,
		.value = 0b11111000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111000,
		.value = 0b11001000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111001,
		.value = 0b11010000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111001,
		.value = 0b11011000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111011,
		.value = 0b11100000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111111,
		.value = 0b11100001,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111011,
		.value = 0b11101000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111111,
		.value = 0b11101001,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111100,
		.value = 0b11110000,
		.decode_func = NULL,
	},
	{
		.mask = 0b11111100,
		.value = 0b11111000,
		.decode_func = NULL,
	},
};

int arm_decode_adv_simd_single(u32 instr, enum insn_type *type,
			       unsigned long *immediate, struct stack_op *op)
{
	unsigned char L = 0, R = 0, S = 0, opcode = 0, size = 0;
	unsigned char rn = 0, rt = 0, dfield = 0;
	int i = 0;

	L = EXTRACT_BIT(instr, 22);
	R = EXTRACT_BIT(instr, 21);
	S = EXTRACT_BIT(instr, 12);
	opcode = (instr >> 13) & ONES(3);
	size = (instr >> 10) & ONES(2);

	dfield = (L << 7) | (R << 6) | (opcode << 3) | (S << 2) | size;

	*type = INSN_OTHER;
	rn = (instr << 5) & ONES(5);

	for (i = 0; i < ARRAY_SIZE(simd_single_decoder); i++) {
		if ((dfield & simd_single_decoder[i].mask) ==
		    simd_single_decoder[i].value) {
			if (rn != CFI_SP)
				return 0;
			*type = INSN_STACK;
		}
	}

	if (*type == INSN_OTHER)
		return arm_decode_unknown(instr, type, immediate, op);

	rt = instr & ONES(5);
	if (!L) {
		op->dest.type = OP_DEST_REG_INDIRECT;
		op->dest.reg = CFI_SP;
		op->dest.offset = 0;
		op->src.type = OP_SRC_REG;
		op->src.reg = rt;
		op->src.offset = 0;
	} else {
		op->src.type = OP_SRC_REG_INDIRECT;
		op->src.reg = CFI_SP;
		op->src.offset = 0;
		op->dest.type = OP_DEST_REG;
		op->dest.reg = rt;
		op->dest.offset = 0;
	}
	return 0;
}

int arm_decode_adv_simd_single_post(u32 instr, enum insn_type *type,
				    unsigned long *immediate,
				    struct stack_op *op)
{
	/* same opcode as for the no offset variant */
	unsigned char rm = 0;
	int ret = 0;

	rm = (instr >> 16) & ONES(5);

	ret = arm_decode_adv_simd_single(instr, type, immediate, op);

	/*
	 * This is actually irrelevant if the offset is given by a register
	 * however there is no way to know the offset value from the encoding
	 * in such a case.
	 */
	if (op->dest.type == OP_DEST_REG_INDIRECT)
		op->dest.offset = rm;
	if (op->src.type == OP_SRC_REG_INDIRECT)
		op->src.offset = rm;
	return ret;
}

int arm_decode_ld_st_mem_tags(u32 instr, enum insn_type *type,
			      unsigned long *immediate, struct stack_op *op)
{
	u32 imm9 = 0;
	unsigned char opc = 0, op2 = 0, rn = 0, rt = 0, decode_field = 0;

	imm9 = (instr >> 12) & ONES(9);
	opc = (instr >> 22) & ONES(2);
	op2 = (instr >> 10) & ONES(2);
	rn = (instr >> 5) & ONES(5);
	rt = instr & ONES(6);

	decode_field = (opc << 2) | op2;

	if (decode_field == 0x0 ||
	    (decode_field == 0x8 && imm9 != 0) ||
	    (decode_field == 0xC && imm9 != 0)) {
		return arm_decode_unknown(instr, type, immediate, op);
	}

	if (rn != CFI_SP) {
		*type = INSN_OTHER;
		return 0;
	}
	*type = INSN_STACK;
	*immediate = imm9;

	/*
	 * Offset should normally be shifted to the
	 * left of LOG2_TAG_GRANULE
	 */
	switch (decode_field) {
	case 1:
	case 5:
	case 9:
	case 13:
		/* post index */
	case 3:
	case 7:
	case 8:
	case 11:
	case 15:
		/* pre index */
		op->dest.reg = CFI_SP;
		op->dest.type = OP_DEST_PUSH;
		op->dest.offset = SIGN_EXTEND(imm9, 9);
		op->src.reg = rt;
		op->src.type = OP_SRC_REG;
		op->src.offset = 0;
		return 0;
	case 2:
	case 6:
	case 10:
	case 14:
		/* store */
		op->dest.reg = CFI_SP;
		op->dest.type = OP_DEST_REG_INDIRECT;
		op->dest.offset = SIGN_EXTEND(imm9, 9);
		op->src.reg = rt;
		op->src.type = OP_SRC_REG;
		op->src.offset = 0;
		return 0;
	case 4:
	case 12:
		/* load */
		op->src.reg = CFI_SP;
		op->src.type = OP_SRC_REG_INDIRECT;
		op->src.offset = SIGN_EXTEND(imm9, 9);
		op->dest.reg = rt;
		op->dest.type = OP_DEST_REG;
		op->dest.offset = 0;
		return 0;
	}

	return -1;
}

#define ST_EXCL_UNALLOC_1 0b001010
#define ST_EXCL_UNALLOC_2 0b000010

#define LDXRB		0b000100
#define LDAXRB		0b000101
#define LDLARB		0b001100
#define LDARB		0b001101
#define LDXRH		0b010100
#define LDAXRH		0b010101
#define LDLARH		0b011100
#define LDARH		0b011101
#define LDXR		0b100100
#define LDAXR		0b100101
#define LDXP		0b100110
#define LDAXP		0b100111
#define LDLAR		0b101100
#define LDAR		0b101101
#define LDXR_64		0b110100
#define LDAXR_64	0b110101
#define LDXP_64		0b110110
#define LDAXP_64	0b110111
#define LDLAR_64	0b111100
#define LDAR_64		0b111101

#define LD_EXCL_NUMBER	20

static int ld_excl_masks[] = {
	LDXRB,
	LDAXRB,
	LDLARB,
	LDARB,
	LDXRH,
	LDAXRH,
	LDLARH,
	LDARH,
	LDXR,
	LDAXR,
	LDXP,
	LDAXP,
	LDLAR,
	LDAR,
	LDXR_64,
	LDAXR_64,
	LDXP_64,
	LDAXP_64,
	LDLAR_64,
	LDAR_64,
};

int arm_decode_ld_st_exclusive(u32 instr, enum insn_type *type,
			       unsigned long *immediate, struct stack_op *op)
{
	unsigned char size = 0, o2 = 0, L = 0, o1 = 0, o0 = 0;
	unsigned char rt = 0, rt2 = 0, rn = 0;
	unsigned char decode_field = 0;
	int i = 0;

	size = (instr >> 30) & ONES(2);
	o2 = EXTRACT_BIT(instr, 23);
	L = EXTRACT_BIT(instr, 22);
	o1 = EXTRACT_BIT(instr, 21);
	o0 = EXTRACT_BIT(instr, 15);

	rt2 = (instr >> 10) & ONES(5);
	rn = (instr >> 5) & ONES(5);
	rt = instr & ONES(5);

	decode_field = (size << 4) | (o2 << 3) | (L << 2) | (o1 << 1) | o0;

	if ((decode_field & ST_EXCL_UNALLOC_1) == ST_EXCL_UNALLOC_1 ||
	    (decode_field & 0b101010) == ST_EXCL_UNALLOC_2) {
		if (rt2 != 31)
			return arm_decode_unknown(instr, type, immediate, op);
	}

	if (rn != 31) {
		*type = INSN_OTHER;
		return 0;
	}

	*type = INSN_STACK;
	for (i = 0; i < LD_EXCL_NUMBER; i++) {
		if ((decode_field & 0b111111) == ld_excl_masks[i]) {
			op->src.type = OP_SRC_REG_INDIRECT;
			op->src.reg = CFI_SP;
			op->src.offset = 0;
			op->dest.type = OP_DEST_REG;
			op->dest.reg = rt;
			op->dest.offset = 0;
			return 0;
		}
	}

	op->dest.type = OP_DEST_REG_INDIRECT;
	op->dest.reg = CFI_SP;
	op->dest.offset = 0;
	op->src.type = OP_SRC_REG;
	op->src.reg = rt;
	op->src.offset = 0;

	return 0;
}

#undef ST_EXCL_UNALLOC_1
#undef ST_EXCL_UNALLOC_2

#undef LD_EXCL_NUMBER

#undef LDXRB
#undef LDAXRB
#undef LDLARB
#undef LDARB
#undef LDXRH
#undef LDAXRH
#undef LDLARH
#undef LDARH
#undef LDXR
#undef LDAXR
#undef LDXP
#undef LDAXP
#undef LDLAR
#undef LDAR
#undef LDXR_64
#undef LDAXR_64
#undef LDXP_64
#undef LDAXP_64
#undef LDLAR_64
#undef LDAR_64

int arm_decode_ldapr_stlr_unsc_imm(u32 instr, enum insn_type *type,
				   unsigned long *immediate,
				   struct stack_op *op)
{
	u32 imm9 = 0;
	unsigned char size = 0, opc = 0, rn = 0, rt = 0, decode_field = 0;

	imm9 = (instr >> 12) & ONES(9);
	size = (instr >> 30) & ONES(2);
	opc = (instr >> 22) & ONES(2);
	rn = (instr >> 5) & ONES(5);
	rt = instr & ONES(5);

	decode_field = (size << 2) | opc;
	if (decode_field == 0xB ||
	    decode_field == 0xE ||
	    decode_field == 0xF) {
		return arm_decode_unknown(instr, type, immediate, op);
	}

	if (rn != 31) {
		*type = INSN_OTHER;
		return 0;
	}
	*type = INSN_STACK;
	*immediate = imm9;
	switch (decode_field) {
	case 1:
	case 2:
	case 3:
	case 5:
	case 6:
	case 7:
	case 9:
	case 10:
	case 13:
		/* load */
		op->src.type = OP_SRC_REG_INDIRECT;
		op->src.reg = CFI_SP;
		op->src.offset = SIGN_EXTEND(imm9, 9);
		op->dest.type = OP_DEST_REG;
		op->dest.reg = rt;
		op->dest.offset = 0;
		break;
	default:
		/* store */
		op->dest.type = OP_SRC_REG_INDIRECT;
		op->dest.reg = CFI_SP;
		op->dest.offset = SIGN_EXTEND(imm9, 9);
		op->src.type = OP_SRC_REG;
		op->src.reg = rt;
		op->src.offset = 0;
		break;
	}

	return 0;
}

int arm_decode_ld_regs_literal(u32 instr, enum insn_type *type,
			       unsigned long *immediate, struct stack_op *op)
{
	unsigned char opc = 0, V = 0;

	opc = (instr >> 30) & ONES(2);
	V = EXTRACT_BIT(instr, 26);

	if (((opc << 1) | V) == 0x7)
		return arm_decode_unknown(instr, type, immediate, op);

	*type = INSN_OTHER;
	return 0;
}

int arm_decode_ld_st_noalloc_pair_off(u32 instr, enum insn_type *type,
				      unsigned long *immediate,
				      struct stack_op *op)
{
	unsigned char opc = 0, V = 0, L = 0;
	unsigned char decode_field = 0;

	opc = (instr >> 30) & ONES(2);
	V = EXTRACT_BIT(instr, 26);
	L = EXTRACT_BIT(instr, 22);

	decode_field = (opc << 2) | (V << 1) | L;

	if (decode_field == 0x4 ||
	    decode_field == 0x5 ||
	    decode_field >= 12) {
		return arm_decode_unknown(instr, type, immediate, op);
	}
	return arm_decode_ld_st_regs_pair_off(instr, type, immediate, op);
}

int arm_decode_ld_st_regs_pair_off(u32 instr, enum insn_type *type,
				   unsigned long *immediate,
				   struct stack_op *op)
{
	unsigned char opc = 0, V = 0, L = 0, bit = 0;
	unsigned char imm7 = 0, rt2 = 0, rt = 0, rn = 0;
	unsigned char decode_field = 0;
	int scale = 0;

	opc = (instr >> 30) & ONES(2);
	V = EXTRACT_BIT(instr, 26);
	L = EXTRACT_BIT(instr, 22);
	imm7 = (instr >> 15) & ONES(7);
	rt2 = (instr >> 10) & ONES(5);
	rn = (instr >> 5) & ONES(5);
	rt = instr & ONES(5);
	bit = EXTRACT_BIT(opc, 1);
	scale = 2 + bit;

	decode_field = (opc << 2) | (V << 1) | L;

	if (decode_field >= 0xC)
		return arm_decode_unknown(instr, type, immediate, op);

	*immediate = (SIGN_EXTEND(imm7, 7)) << scale;

	if (rn != CFI_SP && rn != CFI_BP) {
		*type = INSN_OTHER;
		return 0;
	}

	*type = INSN_STACK;

	switch (decode_field) {
	case 1:
	case 3:
	case 5:
	case 7:
	case 9:
	case 11:
		/* load */
		op->src.type = OP_SRC_REG_INDIRECT;
		op->src.reg = rn;
		op->src.offset = *immediate;
		op->dest.type = OP_DEST_REG;
		op->dest.reg = rt;
		op->dest.offset = 0;
		{
			struct stack_op *extra;

			extra = malloc(sizeof(*extra));
			extra->src.type = OP_SRC_REG_INDIRECT;
			extra->src.reg = rn;
			extra->src.offset = (int) *immediate + 8;
			extra->dest.type = OP_DEST_REG;
			extra->dest.reg = rt2;
			extra->dest.offset = 0;
			extra->next = NULL;

			op->next = extra;
		}
		break;
	default:
		op->dest.type = OP_DEST_REG_INDIRECT;
		op->dest.reg = rn;
		op->dest.offset = (int) *immediate + 8;
		op->src.type = OP_SRC_REG;
		op->src.reg = rt2;
		op->src.offset = 0;
		{
			struct stack_op *extra;

			extra = malloc(sizeof(*extra));
			extra->dest.type = OP_DEST_REG_INDIRECT;
			extra->dest.reg = rn;
			extra->dest.offset = *immediate;
			extra->src.type = OP_SRC_REG;
			extra->src.reg = rt;
			extra->src.offset = 0;
			extra->next = NULL;

			op->next = extra;
		}
		/* store */
	}
	return 0;
}

int arm_decode_ld_st_regs_pair_post(u32 instr, enum insn_type *type,
				    unsigned long *immediate,
				    struct stack_op *op)
{
	int ret = 0;
	unsigned int base_reg;
	bool base_is_src;
	struct stack_op *extra;

	ret = arm_decode_ld_st_regs_pair_off(instr, type, immediate, op);
	if (ret < 0 || *type == INSN_OTHER)
		return ret;

	if (op->dest.type == OP_DEST_REG_INDIRECT) {
		base_reg = op->dest.reg;
		base_is_src = false;
	} else if (op->src.type == OP_SRC_REG_INDIRECT) {
		base_reg = op->src.reg;
		base_is_src = true;
	} else {
		WARN("Unexpected base type");
		return -1;
	}

	extra = malloc(sizeof(*extra));
	extra->dest.type = OP_DEST_REG;
	extra->dest.reg = base_reg;
	extra->src.reg = base_reg;
	extra->src.type = OP_SRC_ADD;
	extra->src.offset = (int) *immediate;
	extra->next = NULL;

	/* Add post increment of base */
	while (1) {
		if (!base_is_src)
			op->dest.offset -= extra->src.offset;
		else
			op->src.offset -= extra->src.offset;

		if (!op->next)
			break;
		op = op->next;
	}
	op->next = extra;

	return ret;
}

int arm_decode_ld_st_regs_pair_pre(u32 instr, enum insn_type *type,
				   unsigned long *immediate,
				   struct stack_op *op)
{
	int ret = 0;
	unsigned int base_reg;
	bool base_is_src;
	struct stack_op *extra;

	ret = arm_decode_ld_st_regs_pair_off(instr, type, immediate, op);
	if (ret < 0 || *type == INSN_OTHER)
		return ret;

	if (op->dest.type == OP_DEST_REG_INDIRECT) {
		base_reg = op->dest.reg;
		base_is_src = false;
	} else if (op->src.type == OP_SRC_REG_INDIRECT) {
		base_reg = op->src.reg;
		base_is_src = true;
	} else {
		WARN("Unexpected base type");
		return -1;
	}

	extra = malloc(sizeof(*extra));
	*extra = *op;
	op->dest.type = OP_DEST_REG;
	op->dest.reg = base_reg;
	op->src.type = OP_SRC_ADD;
	op->src.reg = base_reg;
	op->src.offset = (int) *immediate;
	op->next = extra;

	/* Adapt offsets */
	while (extra) {
		if (!base_is_src)
			extra->dest.offset -= op->src.offset;
		else
			extra->src.offset -= op->src.offset;

		extra = extra->next;
	}
	return 0;
}

int arm_decode_ld_st_regs_unsc_imm(u32 instr, enum insn_type *type,
				   unsigned long *immediate,
				   struct stack_op *op)
{
	u32 imm9 = 0;
	unsigned char size = 0, V = 0, opc = 0, rn = 0, rt = 0;
	unsigned char decode_field = 0;

	size = (instr >> 30) & ONES(2);
	V = EXTRACT_BIT(instr, 26);
	opc = (instr >> 22) & ONES(2);

	imm9 = (instr >> 12) & ONES(9);
	rn = (instr >> 5) & ONES(5);
	rt = instr & ONES(5);

	decode_field = (size << 2) | (V << 2) | opc;

	switch (decode_field) {
	case 0b01110:
	case 0b01111:
	case 0b11110:
	case 0b11111:
	case 0b10011:
	case 0b11011:
	case 0b10110:
	case 0b10111:
		return arm_decode_unknown(instr, type, immediate, op);
	case 26:
		/* prefetch */
		*type = INSN_OTHER;
		return 0;
	case 1:
	case 2:
	case 3:
	case 5:
	case 7:
	case 9:
	case 10:
	case 11:
	case 13:
	case 17:
	case 18:
	case 21:
	case 25:
	case 29:
		/* load */
		if (rn != CFI_SP) {
			*type = INSN_OTHER;
			return 0;
		}
		op->src.type = OP_SRC_REG_INDIRECT;
		op->src.reg = CFI_SP;
		op->src.offset = SIGN_EXTEND(imm9, 9);
		op->dest.type = OP_DEST_REG;
		op->dest.reg = rt;
		op->dest.offset = 0;
		break;
	default:
		if (rn != CFI_SP) {
			*type = INSN_OTHER;
			return 0;
		}
		op->dest.type = OP_DEST_REG_INDIRECT;
		op->dest.reg = CFI_SP;
		op->dest.offset = SIGN_EXTEND(imm9, 9);
		op->src.type = OP_DEST_REG;
		op->src.reg = rt;
		op->src.offset = 0;
		break;
	}

	*type = INSN_STACK;
	return 0;
}

static struct aarch64_insn_decoder ld_unsig_unalloc_decoder[] = {
	{
		.mask = 0b01110,
		.value = 0b01110,
	},
	{
		.mask = 0b10111,
		.value = 0b10011,
	},
	{
		.mask = 0b10110,
		.value = 0b10110,
	},
};

int arm_decode_ld_st_regs_unsigned(u32 instr, enum insn_type *type,
				   unsigned long *immediate,
				   struct stack_op *op)
{
	unsigned char size = 0, V = 0, opc = 0, rn = 0, rt = 0;
	unsigned char decode_field = 0;
	u32 imm12 = 0;
	int i = 0;

	size = (instr >> 30) & ONES(2);
	V = EXTRACT_BIT(instr, 26);
	opc = (instr >> 22) & ONES(2);

	decode_field = (size << 3) | (V << 2) | opc;
	for (i = 0; i < ARRAY_SIZE(ld_unsig_unalloc_decoder); i++) {
		if ((decode_field & ld_unsig_unalloc_decoder[i].mask) ==
		    ld_unsig_unalloc_decoder[i].value) {
			return arm_decode_unknown(instr, type,
						immediate, op);
		}
	}

	imm12 = (instr >> 10) & ONES(12);
	rn = (instr >> 5) & ONES(5);
	rt = instr & ONES(5);

	if ((rn != CFI_SP && rn != CFI_BP) || decode_field == 26) {
		*type = INSN_OTHER;
		return 0;
	}

	*type = INSN_STACK;

	switch (decode_field) {
	case 1:
	case 2:
	case 3:
	case 5:
	case 7:
	case 9:
	case 10:
	case 11:
	case 13:
	case 17:
	case 18:
	case 21:
	case 25:
		/* load */
		op->src.type = OP_SRC_REG_INDIRECT;
		op->src.reg = rn;
		op->src.offset = imm12;
		op->dest.type = OP_DEST_REG;
		op->dest.reg = rt;
		op->dest.offset = 0;
		break;
	default: /* store */
		op->dest.type = OP_DEST_REG_INDIRECT;
		op->dest.reg = rn;
		op->dest.offset = imm12;
		op->src.type = OP_DEST_REG;
		op->src.reg = rt;
		op->src.offset = 0;
	}

	return 0;
}

int arm_decode_ld_st_imm_post(u32 instr, enum insn_type *type,
			      unsigned long *immediate,
			      struct stack_op *op)
{
	unsigned char size = 0, V = 0, opc = 0;
	unsigned char decode_field = 0;
	struct stack_op *post_inc;
	int base_reg;
	u32 imm9 = 0;
	int ret = 0;

	size = (instr >> 30) & ONES(2);
	V = EXTRACT_BIT(instr, 26);
	opc = (instr >> 22) & ONES(2);

	imm9 = (instr >> 12) & ONES(9);

	decode_field = (size << 2) | (V << 2) | opc;

	if (decode_field == 0b11010)
		return arm_decode_unknown(instr, type, immediate, op);

	ret = arm_decode_ld_st_regs_unsigned(instr, type, immediate, op);
	if (ret < 0 || *type == INSN_OTHER)
		return ret;

	if (op->dest.type == OP_DEST_REG_INDIRECT) {
		base_reg = op->dest.reg;
		op->dest.offset = 0;
	} else if (op->src.type == OP_SRC_REG_INDIRECT) {
		base_reg = op->src.reg;
		op->src.offset = 0;
	} else {
		WARN("Cannot find stack op base");
		return -1;
	}

	post_inc = malloc(sizeof(*post_inc));
	post_inc->dest.type = OP_DEST_REG;
	post_inc->dest.reg = base_reg;
	post_inc->src.reg = base_reg;
	post_inc->src.type = OP_SRC_ADD;
	post_inc->src.offset = SIGN_EXTEND(imm9, 9);
	post_inc->next = NULL;
	op->next = post_inc;

	return 0;
}

int arm_decode_ld_st_imm_pre(u32 instr, enum insn_type *type,
			     unsigned long *immediate, struct stack_op *op)
{
	unsigned char size = 0, V = 0, opc = 0;
	unsigned char decode_field = 0;
	struct stack_op *pre_inc;
	int base_reg;
	u32 imm9 = 0;
	int ret = 0;

	size = (instr >> 30) & ONES(2);
	V = EXTRACT_BIT(instr, 26);
	opc = (instr >> 22) & ONES(2);

	imm9 = (instr >> 12) & ONES(9);

	decode_field = (size << 2) | (V << 2) | opc;

	if (decode_field == 0b11010)
		return arm_decode_unknown(instr, type, immediate, op);

	ret = arm_decode_ld_st_regs_unsigned(instr, type, immediate, op);
	if (ret < 0 || *type == INSN_OTHER)
		return ret;

	if (op->dest.type == OP_DEST_REG_INDIRECT) {
		base_reg = op->dest.reg;
		op->dest.offset = 0;
	} else if (op->src.type == OP_SRC_REG_INDIRECT) {
		base_reg = op->src.reg;
		op->src.offset = 0;
	} else {
		WARN("Cannot find stack op base");
		return -1;
	}

	pre_inc = malloc(sizeof(*pre_inc));
	pre_inc->dest.type = OP_DEST_REG;
	pre_inc->dest.reg = base_reg;
	pre_inc->src.reg = base_reg;
	pre_inc->src.type = OP_SRC_ADD;
	pre_inc->src.offset = SIGN_EXTEND(imm9, 9);
	pre_inc->next = op;

	return 0;
}

#define LD_UNPR_UNALLOC_1 0b10011
#define LD_UNPR_UNALLOC_2 0b11010
int arm_decode_ld_st_imm_unpriv(u32 instr, enum insn_type *type,
				unsigned long *immediate, struct stack_op *op)
{
	unsigned char size = 0, V = 0, opc = 0, rn = 0, rt = 0;
	unsigned char decode_field = 0;
	u32 imm9 = 0;

	size = (instr >> 30) & ONES(2);
	V = EXTRACT_BIT(instr, 26);
	opc = (instr >> 22) & ONES(2);

	imm9 = (instr >> 12) & ONES(9);

	decode_field = (size << 3) | (V << 2) | opc;
	if (V == 1 ||
	    (decode_field & 0b10111) == LD_UNPR_UNALLOC_1 ||
	    (decode_field & 0b11111) == LD_UNPR_UNALLOC_2) {
		return arm_decode_unknown(instr, type, immediate, op);
	}
#undef LD_UNPR_UNALLOC_1
#undef LD_UNPR_UNALLOC_2

	if (rn != CFI_SP) {
		*type = INSN_OTHER;
		return 0;
	}
	*type = INSN_STACK;

	switch (decode_field) {
	case 1:
	case 2:
	case 3:
	case 9:
	case 10:
	case 11:
	case 17:
	case 18:
	case 25:
		/* load */
		op->src.type = OP_SRC_REG_INDIRECT;
		op->src.reg = CFI_SP;
		op->src.offset = SIGN_EXTEND(imm9, 9);
		op->dest.type = OP_DEST_REG;
		op->dest.reg = rt;
		op->dest.offset = 0;
		break;
	default:
		/* store */
		op->dest.type = OP_DEST_REG_INDIRECT;
		op->dest.reg = CFI_SP;
		op->dest.offset = SIGN_EXTEND(imm9, 9);
		op->src.type = OP_DEST_REG;
		op->src.reg = rt;
		op->src.offset = 0;
		break;
	}
	return 0;
}

static struct aarch64_insn_decoder atom_unallocs_decoder[] = {
	{
		.mask = 0b1001111,
		.value = 0b0001001,
	},
	{
		.mask = 0b1001110,
		.value = 0b0001010,
	},
	{
		.mask = 0b1001111,
		.value = 0b0001101,
	},
	{
		.mask = 0b1001110,
		.value = 0b0001110,
	},
	{
		.mask = 0b1101111,
		.value = 0b0001100,
	},
	{
		.mask = 0b1111111,
		.value = 0b0111100,
	},
	{
		.mask = 0b1000000,
		.value = 0b1000000,
	},
};

int arm_decode_atomic(u32 instr, enum insn_type *type,
		      unsigned long *immediate,
		      struct stack_op *op)
{
	unsigned char V = 0, A = 0, R = 0, o3 = 0, opc = 0;
	unsigned char rn = 0, rt = 0;
	unsigned char decode_field = 0;
	int i = 0;

	V = EXTRACT_BIT(instr, 26);
	A = EXTRACT_BIT(instr, 23);
	R = EXTRACT_BIT(instr, 22);
	o3 = EXTRACT_BIT(instr, 15);
	opc = (instr >> 12) & ONES(3);

	decode_field = (V << 6) | (A << 5) | (R << 4) | (o3 << 3) | opc;

	for (i = 0; i < ARRAY_SIZE(atom_unallocs_decoder); i++) {
		if ((decode_field & atom_unallocs_decoder[i].mask) ==
		    atom_unallocs_decoder[i].value) {
			return arm_decode_unknown(instr,
						  type,
						  immediate,
						  op);
		}
	}

	rn = (instr >> 5) & ONES(5);
	rt = instr & ONES(5);

	if (rn != CFI_SP) {
		*type = INSN_OTHER;
		return 0;
	}
	*type = INSN_STACK;
	op->src.reg = CFI_SP;
	op->src.type = OP_DEST_REG_INDIRECT;
	op->src.offset = 0;
	op->dest.type = OP_DEST_REG;
	op->dest.reg = rt;
	op->dest.offset = 0;

	return 0;
}

int arm_decode_ld_st_regs_off(u32 instr, enum insn_type *type,
			      unsigned long *immediate, struct stack_op *op)
{
	unsigned char size = 0, V = 0, opc = 0, option = 0;
	unsigned char rm = 0, rn = 0, rt = 0;
	unsigned char decode_field = 0;

	size = (instr >> 30) & ONES(2);
	V = EXTRACT_BIT(instr, 26);
	opc = (instr >> 22) & ONES(2);
	option = (instr >> 13) & ONES(3);

#define LD_ROFF_UNALLOC_1	0b01110
#define LD_ROFF_UNALLOC_2	0b10110
#define LD_ROFF_UNALLOC_3	0b10011
	decode_field = (size << 3) | (V << 2) | opc;
	if (!EXTRACT_BIT(option, 1) ||
	    (decode_field & LD_ROFF_UNALLOC_1) == LD_ROFF_UNALLOC_1 ||
	    (decode_field & LD_ROFF_UNALLOC_2) == LD_ROFF_UNALLOC_2 ||
	    (decode_field & 0b10111) == LD_ROFF_UNALLOC_3) {
		return arm_decode_unknown(instr, type, immediate, op);
	}
#undef LD_ROFF_UNALLOC_1
#undef LD_ROFF_UNALLOC_2
#undef LD_ROFF_UNALLOC_3

	rn = (instr >> 5) & ONES(5);

#define LD_ROFF_PRFM	0b11010
	if (rn != CFI_SP || decode_field == LD_ROFF_PRFM) {
		*type = INSN_OTHER;
		return 0;
	}
#undef LD_ROFF_PRFM

	rt = instr & ONES(5);
	rm = (instr >> 16) & ONES(5);

	switch (decode_field & ONES(3)) {
	case 0b001:
	case 0b010:
	case 0b011:
	case 0b101:
	case 0b111:
		/* load */
		op->src.type = OP_SRC_REG_INDIRECT;
		op->src.reg = CFI_SP;
		op->src.offset = rm;
		op->dest.type = OP_DEST_REG;
		op->dest.reg = rt;
		op->dest.offset = 0;
		break;
	default:
		/* store */
		op->dest.type = OP_DEST_REG_INDIRECT;
		op->dest.reg = CFI_SP;
		op->dest.offset = rm;
		op->src.type = OP_DEST_REG;
		op->src.reg = rt;
		op->src.offset = 0;
		break;
	}

	return 0;
}

int arm_decode_ld_st_regs_pac(u32 instr, enum insn_type *type,
			      unsigned long *immediate, struct stack_op *op)
{
	unsigned char size = 0, V = 0, W = 0, S = 0;
	unsigned char rn = 0, rt = 0;
	u32 imm9 = 0, s10 = 0;

	size = (instr >> 30) & ONES(2);
	V = EXTRACT_BIT(instr, 26);
	W = EXTRACT_BIT(instr, 11);

	if (size != 3 || V == 1)
		return arm_decode_unknown(instr, type, immediate, op);

	rn = (instr >> 5) & ONES(5);

	if (rn != CFI_SP) {
		*type = INSN_OTHER;
		return 0;
	}

	S = EXTRACT_BIT(instr, 22);
	s10 = (S << 9) | imm9;

	op->dest.reg = rt;
	op->dest.type = OP_DEST_REG;
	op->dest.offset = 0;
	op->src.offset = (SIGN_EXTEND(s10, 9) << 3);
	if (W) { /* pre-indexed/writeback */
		op->src.type = OP_SRC_POP;
		op->src.reg = CFI_SP;
	} else {
		op->src.type = OP_SRC_REG_INDIRECT;
		op->src.reg = CFI_SP;
	}

	return 0;
}

static struct aarch64_insn_decoder dp_reg_decoder[] = {
	{
		.mask = 0b111111000000,
		.value = 0b010110000000,
		.decode_func = arm_decode_dp_reg_2src,
	},
	{
		.mask = 0b111111000000,
		.value = 0b110110000000,
		.decode_func = arm_decode_dp_reg_1src,
	},
	{
		.mask = 0b011000000000,
		.value = 0b000000000000,
		.decode_func = arm_decode_dp_reg_logi,
	},
	{
		.mask = 0b011001000000,
		.value = 0b001000000000,
		.decode_func = arm_decode_dp_reg_adds,
	},
	{
		.mask = 0b011001000000,
		.value = 0b001001000000,
		.decode_func = arm_decode_dp_reg_adde,
	},
	{
		.mask = 0b011111111111,
		.value = 0b010000000000,
		.decode_func = arm_decode_dp_reg_addc,
	},
	{
		.mask = 0b011111011111,
		.value = 0b010000000001,
		.decode_func = arm_decode_dp_reg_rota,
	},
	{
		.mask = 0b011111001111,
		.value = 0b010000000010,
		.decode_func = arm_decode_dp_reg_eval,
	},
	{
		.mask = 0b011111000010,
		.value = 0b010010000000,
		.decode_func = arm_decode_dp_reg_cmpr,
	},
	{
		.mask = 0b011111000010,
		.value = 0b010010000010,
		.decode_func = arm_decode_dp_reg_cmpi,
	},
	{
		.mask = 0b011111000000,
		.value = 0b010100000000,
		.decode_func = arm_decode_dp_reg_csel,
	},
	{
		.mask = 0b011000000000,
		.value = 0b011000000000,
		.decode_func = arm_decode_dp_reg_3src,
	},
};

int arm_decode_dp_reg(u32 instr, enum insn_type *type,
		      unsigned long *immediate, struct stack_op *op)
{
	unsigned char op0 = 0, op1 = 0, op2 = 0, op3 = 0;
	u32 decode_field = 0;
	int i = 0;

	op0 = EXTRACT_BIT(instr, 30);
	op1 = EXTRACT_BIT(instr, 28);
	op2 = (instr >> 21) & ONES(4);
	op3 = (instr >> 10) & ONES(6);
	decode_field = (op0 << 5) | (op1 << 4) | op2;
	decode_field = (decode_field << 6) | op3;

	for (i = 0; i < ARRAY_SIZE(dp_reg_decoder); i++) {
		if ((decode_field & dp_reg_decoder[i].mask) ==
		    dp_reg_decoder[i].value) {
			return dp_reg_decoder[i].decode_func(instr, type,
							immediate, op);
		}
	}
	return arm_decode_unknown(instr, type, immediate, op);
}

static struct aarch64_insn_decoder dp_reg_2src_decoder[] = {
	{
		.mask = 0b00111111,
		.value = 0b00000001,
	},
	{
		.mask = 0b00111000,
		.value = 0b00011000,
	},
	{
		.mask = 0b00100000,
		.value = 0b00100000,
	},
	{
		.mask = 0b01111111,
		.value = 0b00000101,
	},
	{
		.mask = 0b01111100,
		.value = 0b00001100,
	},
	{
		.mask = 0b01111110,
		.value = 0b01000010,
	},
	{
		.mask = 0b01111100,
		.value = 0b01000100,
	},
	{
		.mask = 0b01111000,
		.value = 0b01001000,
	},
	{
		.mask = 0b01110000,
		.value = 0b01010000,
	},
	{
		.mask = 0b10111111,
		.value = 0b00000000,
	},
	{
		.mask = 0b11111111,
		.value = 0b00000100,
	},
	{
		.mask = 0b11111110,
		.value = 0b00000110,
	},
	{
		.mask = 0b11111011,
		.value = 0b00010011,
	},
	{
		.mask = 0b11111001,
		.value = 0b10010000,
	},
	{
		.mask = 0b11111010,
		.value = 0b10010000,
	},
};

static int dp_reg_2src_stack_fields[] = {
	0b10000000,
	0b10000100,
	0b10000101,
	0b10001100,
	0b11000000,
};

int arm_decode_dp_reg_2src(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op)
{
	unsigned char sf = 0, S = 0, opcode = 0, rn = 0, rd = 0;
	unsigned char decode_field = 0;
	int i = 0;

	sf = EXTRACT_BIT(instr, 31);
	S = EXTRACT_BIT(instr, 29);
	opcode = (instr >> 10) & ONES(6);

	decode_field = (sf << 7) | (S << 6) | opcode;

	for (i = 0; i < ARRAY_SIZE(dp_reg_2src_decoder); i++) {
		if ((decode_field & dp_reg_2src_decoder[i].mask) ==
		    dp_reg_2src_decoder[i].value) {
			return arm_decode_unknown(instr, type, immediate, op);
		}
	}

	*type = 0;
	for (i = 0; i < ARRAY_SIZE(dp_reg_2src_stack_fields); i++) {
		if (opcode == dp_reg_2src_stack_fields[i]) {
			*type = INSN_OTHER;
			break;
		}
	}
	if (*type == 0) {
		*type = INSN_OTHER;
		return 0;
	}

	rn = (instr >> 5) & ONES(5);
	rd = instr & ONES(5);

#define IRG_OPCODE	0b10000100
	if ((rn != CFI_SP && opcode != IRG_OPCODE) ||
	    (opcode == IRG_OPCODE && rd != CFI_SP &&
	     rn != CFI_SP)) {
		*type = INSN_OTHER;
		return 0;
	}
#undef IRG_OPCODE

	*type = INSN_STACK;
	op->dest.reg = rd;
	op->dest.type = OP_DEST_REG;
	op->dest.offset = 0;

	op->src.reg = rn;
	op->src.type = OP_DEST_REG;
	op->src.offset = 0;

	return 0;
}

static struct aarch64_insn_decoder dp_reg_1src_decoder[] = {
	{
		.mask = 0b0000000001000,
		.value = 0b0000000001000,
	},
	{
		.mask = 0b0000000010000,
		.value = 0b0000000010000,
	},
	{
		.mask = 0b0000000100000,
		.value = 0b0000000100000,
	},
	{
		.mask = 0b0000001000000,
		.value = 0b0000001000000,
	},
	{
		.mask = 0b0000010000000,
		.value = 0b0000010000000,
	},
	{
		.mask = 0b0000100000000,
		.value = 0b0000100000000,
	},
	{
		.mask = 0b0001000000000,
		.value = 0b0001000000000,
	},
	{
		.mask = 0b0010000000000,
		.value = 0b0010000000000,
	},
	{
		.mask = 0b0111111111110,
		.value = 0b0000000000110,
	},
	{
		.mask = 0b0100000000000,
		.value = 0b0100000000000,
	},
};

int arm_decode_dp_reg_1src(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op)
{
	unsigned char sf = 0, S = 0, opcode2 = 0, opcode = 0;
	u32 decode_field = 0;
	int i = 0;

	sf = EXTRACT_BIT(instr, 31);
	S = EXTRACT_BIT(instr, 29);
	opcode2 = (instr >> 16) & ONES(5);
	opcode = (instr >> 10) & ONES(6);

	decode_field = (sf << 6) | (S << 5) | opcode2;
	decode_field = (decode_field << 6) | opcode;

	for (i = 0; i < ARRAY_SIZE(dp_reg_1src_decoder); i++) {
		if ((decode_field & dp_reg_1src_decoder[i].mask) ==
		    dp_reg_1src_decoder[i].value) {
			return arm_decode_unknown(instr, type, immediate, op);
		}
	}
	*type = INSN_OTHER;
	return 0;
}

int arm_decode_dp_reg_logi(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op)
{
	unsigned char sf = 0, imm6 = 0;

	sf = EXTRACT_BIT(instr, 31);
	imm6 = (instr >> 10) & ONES(6);

	if (imm6 >= 0b100000 && !sf)
		return arm_decode_unknown(instr, type, immediate, op);

	*type = INSN_OTHER;
	return 0;
}

int arm_decode_dp_reg_adds(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op)
{
	unsigned char sf = 0, shift = 0, imm6 = 0;

	sf = EXTRACT_BIT(instr, 31);
	shift = (instr >> 22) & ONES(2);
	imm6 = (instr >> 10) & ONES(6);

	if ((imm6 >= 0b100000 && !sf) || shift == 0b11)
		return arm_decode_unknown(instr, type, immediate, op);

	*type = INSN_OTHER;
	return 0;
}

int arm_decode_dp_reg_adde(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op)
{
	unsigned char S = 0, opt = 0, imm3 = 0, rn = 0, rd = 0;

	S = EXTRACT_BIT(instr, 29);
	opt = (instr >> 22) & ONES(2);
	imm3 = (instr >> 10) & ONES(3);
	rn = (instr >> 5) & ONES(5);
	rd = instr & ONES(5);

	if (opt != 0 || imm3 >= 0b101)
		return arm_decode_unknown(instr, type, immediate, op);

	if (rd == CFI_SP && S == 0) {
		*type = INSN_STACK;
		op->dest.reg = CFI_SP;
		op->dest.type = OP_DEST_REG;
		op->src.type = OP_SRC_ADD;
		op->src.reg = rn;

		return 0;
	}
	*type = INSN_OTHER;
	return 0;
}

int arm_decode_dp_reg_addc(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op)
{
	*type = INSN_OTHER;
	return 0;
}

int arm_decode_dp_reg_rota(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op)
{
	unsigned char sf = 0, S = 0, op_bit = 0, o2 = 0;
	unsigned char decode_field = 0;

	sf = EXTRACT_BIT(instr, 31);
	op_bit = EXTRACT_BIT(instr, 30);
	S = EXTRACT_BIT(instr, 29);
	o2 = EXTRACT_BIT(instr, 4);

	decode_field = (sf << 3) | (op_bit << 2) | (S << 1) | o2;

	if (decode_field != 0b1010)
		return arm_decode_unknown(instr, type, immediate, op);

	*type = INSN_OTHER;
	return 0;
}

int arm_decode_dp_reg_eval(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op)
{
	unsigned char sf = 0, S = 0, op_bit = 0, o3 = 0, sz = 0;
	unsigned char opcode2 = 0, mask = 0;
	u32 decode_field = 0;

	sf = EXTRACT_BIT(instr, 31);
	op_bit = EXTRACT_BIT(instr, 30);
	S = EXTRACT_BIT(instr, 29);
	sz = EXTRACT_BIT(instr, 14);
	o3 = EXTRACT_BIT(instr, 4);

	opcode2 = (instr >> 15) & ONES(6);
	mask = instr & ONES(4);

	decode_field = (sf << 2) | (op_bit << 1) | S;
	decode_field = (decode_field << 12) | (opcode2 << 6) | (sz << 5);
	decode_field |= (o3 << 4) | mask;

#define DP_EVAL_SETF_1	0b001000000001101
#define DP_EVAL_SETF_2	0b001000000101101

	if (decode_field != DP_EVAL_SETF_1 &&
	    decode_field != DP_EVAL_SETF_2) {
		return arm_decode_unknown(instr, type, immediate, op);
	}

	*type = INSN_OTHER;
	return 0;
#undef DP_EVAL_SETF_1
#undef DP_EVAL_SETF_2
}

int arm_decode_dp_reg_cmpr(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op)
{
	unsigned char S = 0, o2 = 0, o3 = 0;

	S = EXTRACT_BIT(instr, 29);
	o2 = EXTRACT_BIT(instr, 10);
	o3 = EXTRACT_BIT(instr, 4);

	if (!S || o2 || o3)
		return arm_decode_unknown(instr, type, immediate, op);

	*type = INSN_OTHER;
	return 0;
}

int arm_decode_dp_reg_csel(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op)
{
	unsigned char S = 0, op2 = 0;

	S = EXTRACT_BIT(instr, 29);
	op2 = (instr >> 10) & ONES(2);

	if (S || op2 >= 0b10)
		return arm_decode_unknown(instr, type, immediate, op);

	*type = INSN_OTHER;
	return 0;
}

int arm_decode_dp_reg_cmpi(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op)
{
	return arm_decode_dp_reg_cmpr(instr, type, immediate, op);
}

static int dp_reg_3src_fields[] = {
};

static struct aarch64_insn_decoder dp_reg_3src_decoder[] = {
	{
		.mask = 0b0111111,
		.value = 0b0000101,
	},
	{
		.mask = 0b0111110,
		.value = 0b0000110,
	},
	{
		.mask = 0b0111110,
		.value = 0b0001000,
	},
	{
		.mask = 0b0111111,
		.value = 0b0001101,
	},
	{
		.mask = 0b0111110,
		.value = 0b0001110,
	},
	{
		.mask = 0b0110000,
		.value = 0b0010000,
	},
	{
		.mask = 0b0100000,
		.value = 0b0100000,
	},
	{
		.mask = 0b1111111,
		.value = 0b0000010,
	},
	{
		.mask = 0b1111111,
		.value = 0b0000011,
	},
	{
		.mask = 0b1111111,
		.value = 0b0000100,
	},
	{
		.mask = 0b1111111,
		.value = 0b0001010,
	},
	{
		.mask = 0b1111111,
		.value = 0b0001011,
	},
	{
		.mask = 0b1111111,
		.value = 0b0001100,
	},
};

int arm_decode_dp_reg_3src(u32 instr, enum insn_type *type,
			   unsigned long *immediate, struct stack_op *op)
{
	unsigned char sf = 0, op54 = 0, op31 = 0, o0 = 0;
	unsigned char decode_field = 0;
	int i = 0;

	sf = EXTRACT_BIT(instr, 31);
	op54 = (instr >> 29) & ONES(2);
	op31 = (instr >> 21) & ONES(3);
	o0 = EXTRACT_BIT(instr, 15);

	decode_field = (sf << 6) | (op54 << 4) | (op31 << 1) | o0;

	for (i = 0; i < ARRAY_SIZE(dp_reg_3src_fields); i++) {
		if ((decode_field & dp_reg_3src_decoder[i].mask) ==
		    dp_reg_3src_decoder[i].value) {
			return arm_decode_unknown(instr, type, immediate, op);
		}
	}

	*type = INSN_OTHER;
	return 0;
}

unsigned long arch_jump_destination(struct instruction *insn)
{
	return insn->offset + insn->immediate;
}

static struct aarch64_insn_decoder sve_enc_decoder[] = {
	{
		.mask = 0b1111010000111000,
		.value = 0b0000010000011000,
	},
	{
		.mask = 0b1111110000111000,
		.value = 0b0001110000000000,
	},
	{
		.mask = 0b1111010000110000,
		.value = 0b0011010000010000,
	},
	{
		.mask = 0b1111011100111000,
		.value = 0b0011010100101000,
	},
	{
		.mask = 0b1111011000110000,
		.value = 0b0011011000100000,
	},
	{
		.mask = 0b1111010000100000,
		.value = 0b0100000000100000,
	},
	{
		.mask = 0b1111000000000000,
		.value = 0b0101000000000000,
	},
	{
		.mask = 0b1111011111111000,
		.value = 0b0110000000101000,
	},
	{
		.mask = 0b1111011111110000,
		.value = 0b0110000000110000,
	},
	{
		.mask = 0b1111011111100000,
		.value = 0b0110000001100000,
	},
	{
		.mask = 0b1111011110100000,
		.value = 0b0110000010100000,
	},
	{
		.mask = 0b1111011100100000,
		.value = 0b0110000100100000,
	},
	{
		.mask = 0b1111011000100000,
		.value = 0b0110001000100000,
	},
	{
		.mask = 0b1111010000110110,
		.value = 0b0110010000000010,
	},
	{
		.mask = 0b1111010000111111,
		.value = 0b0110010000001001,
	},
	{
		.mask = 0b1111010000111100,
		.value = 0b0110010000001100,
	},
	{
		.mask = 0b1111010000110000,
		.value = 0b0110010000010000,
	},
	{
		.mask = 0b1111010000100000,
		.value = 0b0110010000100000,
	},
	{
		.mask = 0b1111011100111100,
		.value = 0b0111000100001000,
	},
};

/*
 * Since these instructions are optional (not present on all arm processors)
 * we consider that they will never be used to save/restore stack frame.
 */
int arm_decode_sve_encoding(u32 instr, enum insn_type *type,
			    unsigned long *immediate, struct stack_op *op)
{
	int i = 0;
	unsigned char op0 = 0, op1 = 0, op2 = 0, op3 = 0;
	u32 decode_field = 0;

	op0 = (instr >> 29) & ONES(3);
	op1 = (instr >> 23) & ONES(2);
	op2 = (instr >> 17) & ONES(5);
	op3 = (instr >> 10) & ONES(6);

	decode_field = (op0 << 2) | op1;
	decode_field = (decode_field << 5) | op2;
	decode_field = (decode_field << 6) | op3;

	for (i = 0; i < ARRAY_SIZE(sve_enc_decoder); i++) {
		if ((decode_field & sve_enc_decoder[i].mask) ==
		    sve_enc_decoder[i].value)
			return arm_decode_unknown(instr, type, immediate, op);
	}

	*type = INSN_OTHER;

	return 0;
}

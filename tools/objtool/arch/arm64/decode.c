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

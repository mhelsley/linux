/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdlib.h>

#include "../../special.h"
#include "../../builtin.h"
#include "../../warn.h"

void arch_handle_alternative(unsigned short feature, struct special_alt *alt)
{
	/*
	 * If UACCESS validation is enabled; force that alternative;
	 * otherwise force it the other way.
	 *
	 * What we want to avoid is having both the original and the
	 * alternative code flow at the same time, in that case we can
	 * find paths that see the STAC but take the NOP instead of
	 * CLAC and the other way around.
	 */
	switch (feature) {
	case X86_FEATURE_SMAP:
		if (uaccess)
			alt->skip_orig = true;
		else
			alt->skip_alt = true;
		break;
	case X86_FEATURE_POPCNT:
		/*
		 * It has been requested that we don't validate the !POPCNT
		 * feature path which is a "very very small percentage of
		 * machines".
		 */
		alt->skip_orig = true;
		break;
	default:
		break;
	}
}

int arch_add_jump_table(struct objtool_file *file, struct instruction *insn,
			struct rela *table, struct rela *next_table)
{
	struct rela *rela = table;
	struct instruction *dest_insn;
	struct alternative *alt;
	struct symbol *pfunc = insn->func->pfunc;
	unsigned int prev_offset = 0;

	/*
	 * Each @rela is a switch table relocation which points to the target
	 * instruction.
	 */
	list_for_each_entry_from(rela, &table->sec->rela_list, list) {

		/* Check for the end of the table: */
		if (rela != table && rela->jump_table_start)
			break;

		/* Make sure the table entries are consecutive: */
		if (prev_offset && rela->offset != prev_offset + 8)
			break;

		/* Detect function pointers from contiguous objects: */
		if (rela->sym->sec == pfunc->sec &&
		    rela->addend == pfunc->offset)
			break;

		dest_insn = find_insn(file, rela->sym->sec, rela->addend);
		if (!dest_insn)
			break;

		/* Make sure the destination is in the same function: */
		if (!dest_insn->func || dest_insn->func->pfunc != pfunc)
			break;

		alt = malloc(sizeof(*alt));
		if (!alt) {
			WARN("malloc failed");
			return -1;
		}

		alt->insn = dest_insn;
		list_add_tail(&alt->list, &insn->alts);
		prev_offset = rela->offset;
	}

	if (!prev_offset) {
		WARN_FUNC("can't find switch jump table",
			  insn->sec, insn->offset);
		return -1;
	}

	return 0;
}

struct rela *arch_find_switch_table(struct objtool_file *file,
				  struct rela *text_rela,
				  struct section *rodata_sec,
				  unsigned long table_offset)
{
	struct rela *rodata_rela;

	rodata_rela = find_rela_by_dest(rodata_sec, table_offset);
	if (rodata_rela) {
		/*
		 * Use of RIP-relative switch jumps is quite rare, and
		 * indicates a rare GCC quirk/bug which can leave dead
		 * code behind.
		 */
		if (text_rela->type == R_X86_64_PC32)
			file->ignore_unreachables = true;

		return rodata_rela;
	}

	return NULL;
}

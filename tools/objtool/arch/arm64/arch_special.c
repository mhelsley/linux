/*
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
#include "../../special.h"
#include "arch_special.h"

int arch_add_jump_table(struct objtool_file *file, struct instruction *insn,
			struct rela *table, struct rela *next_table)
{
	return 0;
}

struct rela *arch_find_switch_table(struct objtool_file *file,
				  struct rela *text_rela,
				  struct section *rodata_sec,
				  unsigned long table_offset)
{
	file->ignore_unreachables = true;
	return NULL;
}

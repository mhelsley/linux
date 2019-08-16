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
#ifndef _ARM64_ARCH_SPECIAL_H
#define _ARM64_ARCH_SPECIAL_H

#include <linux/types.h>

#define EX_ENTRY_SIZE		8
#define EX_ORIG_OFFSET		0
#define EX_NEW_OFFSET		4

#define JUMP_ENTRY_SIZE		16
#define JUMP_ORIG_OFFSET	0
#define JUMP_NEW_OFFSET		4

#define ALT_ENTRY_SIZE		12
#define ALT_ORIG_OFFSET		0
#define ALT_NEW_OFFSET		4
#define ALT_FEATURE_OFFSET	8
#define ALT_ORIG_LEN_OFFSET	10
#define ALT_NEW_LEN_OFFSET	11

struct switch_table_info {
	u64 switch_table_label;
	u64 nb_entries;
	u64 offset_unsigned;
} __attribute__((__packed__));

#endif /* _ARM64_ARCH_SPECIAL_H */

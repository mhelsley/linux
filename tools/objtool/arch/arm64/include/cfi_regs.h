/*
 * Copyright (C) 2015-2017 Josh Poimboeuf <jpoimboe@redhat.com>
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

#ifndef _OBJTOOL_CFI_REGS_H
#define _OBJTOOL_CFI_REGS_H

#define CFI_R0			0
#define CFI_R1			1
#define CFI_R2			2
#define CFI_R3			3
#define CFI_R4			4
#define CFI_R5			5
#define CFI_R6			6
#define CFI_R7			7
#define CFI_R8			8
#define CFI_R9			9
#define CFI_R10			10
#define CFI_R11			11
#define CFI_R12			12
#define CFI_R13			13
#define CFI_R14			14
#define CFI_R15			15
#define CFI_R16			16
#define CFI_R17			17
#define CFI_R18			18
#define CFI_R19			19
#define CFI_R20			20
#define CFI_R21			21
#define CFI_R22			22
#define CFI_R23			23
#define CFI_R24			24
#define CFI_R25			25
#define CFI_R26			26
#define CFI_R27			27
#define CFI_R28			28
#define CFI_R29			29
#define CFI_FP			CFI_R29
#define CFI_BP			CFI_FP
#define CFI_R30			30
#define CFI_LR			CFI_R30
#define CFI_SP			31

#define CFI_NUM_REGS		32

#define CFI_BP_FRAME_OFFSET	0

#endif /* _OBJTOOL_CFI_REGS_H */

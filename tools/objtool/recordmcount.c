// SPDX-License-Identifier: GPL-2.0-only
/*
 * recordmcount.c: construct a table of the locations of calls to 'mcount'
 * so that ftrace can find them quickly.
 * Copyright 2009 John F. Reiser <jreiser@BitWagon.com>.  All rights reserved.
 *
 * Restructured to fit Linux format, as well as other updates:
 *  Copyright 2010 Steven Rostedt <srostedt@redhat.com>, Red Hat Inc.
 */

/*
 * Strategy: alter the .o file in-place.
 *
 * Append a new STRTAB that has the new section names, followed by a new array
 * ElfXX_Shdr[] that has the new section headers, followed by the section
 * contents for __mcount_loc and its relocations.  The old shstrtab strings,
 * and the old ElfXX_Shdr[] array, remain as "garbage" (commonly, a couple
 * kilobytes.)  Subsequent processing by /bin/ld (or the kernel module loader)
 * will ignore the garbage regions, because they are not designated by the
 * new .e_shoff nor the new ElfXX_Shdr[].  [In order to remove the garbage,
 * then use "ld -r" to create a new file that omits the garbage.]
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "builtin-mcount.h"

#include "elf.h"

#ifndef EM_AARCH64
#define EM_AARCH64	183
#define R_AARCH64_NONE		0
#define R_AARCH64_ABS64	257
#endif

static int fd_map;	/* File descriptor for file being modified. */
static int mmap_failed; /* Boolean flag. */
static char gpfx;	/* prefix for global symbol name (sometimes '_') */
static struct stat sb;	/* Remember .st_size, etc. */
static const char *altmcount;	/* alternate mcount symbol name */
static int warn_on_notrace_sect; /* warn when section has mcount not being recorded */
static void *file_map;	/* pointer of the mapped file */

static struct elf *lf;

static void mmap_cleanup(void)
{
	if (!mmap_failed)
		munmap(file_map, sb.st_size);
	else
		free(file_map);
	file_map = NULL;
	if (lf)
		elf_close(lf);
	lf = NULL;
}

static void * umalloc(size_t size)
{
	void *const addr = malloc(size);
	if (addr == 0) {
		fprintf(stderr, "malloc failed: %zu bytes\n", size);
		mmap_cleanup();
		return NULL;
	}
	return addr;
}

/*
 * Get the whole file as a programming convenience in order to avoid
 * malloc+lseek+read+free of many pieces.  If successful, then mmap
 * avoids copying unused pieces; else just read the whole file.
 * Open for both read and write; new info will be appended to the file.
 * Use MAP_PRIVATE so that a few changes to the in-memory ElfXX_Ehdr
 * do not propagate to the file until an explicit overwrite at the last.
 * This preserves most aspects of consistency (all except .st_size)
 * for simultaneous readers of the file while we are appending to it.
 * However, multiple writers still are bad.  We choose not to use
 * locking because it is expensive and the use case of kernel build
 * makes multiple writers unlikely.
 */
static void *mmap_file(char const *fname)
{
	/* Avoid problems if early cleanup() */
	fd_map = -1;
	mmap_failed = 1;
	file_map = NULL;
	sb.st_size = 0;

	lf = elf_read(fname, O_RDWR);
	if (!lf) {
		perror(fname);
		return NULL;
	}
	fd_map = lf->fd;
	if (fstat(fd_map, &sb) < 0) {
		perror(fname);
		goto out;
	}
	if (!S_ISREG(sb.st_mode)) {
		fprintf(stderr, "not a regular file: %s\n", fname);
		goto out;
	}
	file_map = mmap(0, sb.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE,
			fd_map, 0);
	if (file_map == MAP_FAILED) {
		mmap_failed = 1;
		file_map = umalloc(sb.st_size);
		if (!file_map) {
			perror(fname);
			goto out;
		}
		if (read(fd_map, file_map, sb.st_size) != sb.st_size) {
			perror(fname);
			mmap_cleanup();
			goto out;
		}
	} else
		mmap_failed = 0;
out:
	fd_map = -1;

	return file_map;
}


static unsigned char ideal_nop5_x86_64[5] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
static unsigned char ideal_nop5_x86_32[5] = { 0x3e, 0x8d, 0x74, 0x26, 0x00 };
static unsigned char *ideal_nop;

static char rel_type_nop;

static int (*make_nop)(struct section *, size_t const offset);

static int make_nop_x86(struct section *txts, size_t const offset)
{
	uint32_t *ptr;
	unsigned char *op;
	void *map = txts->data->d_buf;

	if (offset < 1)
		return -1;

	/* Confirm we have 0xe8 0x0 0x0 0x0 0x0 */
	ptr = map + offset;
	if (*ptr != 0)
		return -1;

	op = map + offset - 1;
	if (*op != 0xe8)
		return -1;

	/* convert to nop */
	memcpy(op, ideal_nop, 5);
	return 0;
}

static unsigned char ideal_nop4_arm_le[4] = { 0x00, 0x00, 0xa0, 0xe1 }; /* mov r0, r0 */
static unsigned char ideal_nop4_arm_be[4] = { 0xe1, 0xa0, 0x00, 0x00 }; /* mov r0, r0 */
static unsigned char *ideal_nop4_arm;

static unsigned char bl_mcount_arm_le[4] = { 0xfe, 0xff, 0xff, 0xeb }; /* bl */
static unsigned char bl_mcount_arm_be[4] = { 0xeb, 0xff, 0xff, 0xfe }; /* bl */
static unsigned char *bl_mcount_arm;

static unsigned char push_arm_le[4] = { 0x04, 0xe0, 0x2d, 0xe5 }; /* push {lr} */
static unsigned char push_arm_be[4] = { 0xe5, 0x2d, 0xe0, 0x04 }; /* push {lr} */
static unsigned char *push_arm;

static unsigned char ideal_nop2_thumb_le[2] = { 0x00, 0xbf }; /* nop */
static unsigned char ideal_nop2_thumb_be[2] = { 0xbf, 0x00 }; /* nop */
static unsigned char *ideal_nop2_thumb;

static unsigned char push_bl_mcount_thumb_le[6] = { 0x00, 0xb5, 0xff, 0xf7, 0xfe, 0xff }; /* push {lr}, bl */
static unsigned char push_bl_mcount_thumb_be[6] = { 0xb5, 0x00, 0xf7, 0xff, 0xff, 0xfe }; /* push {lr}, bl */
static unsigned char *push_bl_mcount_thumb;

static int make_nop_arm(struct section *txts, size_t const offset)
{
	char *ptr;
	int cnt = 1;
	int nop_size;
	size_t off = offset;
	void *map = txts->data->d_buf;

	ptr = map + offset;
	if (memcmp(ptr, bl_mcount_arm, 4) == 0) {
		if (memcmp(ptr - 4, push_arm, 4) == 0) {
			off -= 4;
			cnt = 2;
		}
		ideal_nop = ideal_nop4_arm;
		nop_size = 4;
	} else if (memcmp(ptr - 2, push_bl_mcount_thumb, 6) == 0) {
		cnt = 3;
		nop_size = 2;
		off -= 2;
		ideal_nop = ideal_nop2_thumb;
	} else
		return -1;

	/* Convert to nop */
	do {
		memcpy(map + off, ideal_nop, nop_size);
		off += nop_size;
	} while (--cnt > 0);

	return 0;
}

static unsigned char ideal_nop4_arm64[4] = {0x1f, 0x20, 0x03, 0xd5};
static int make_nop_arm64(struct section *txts, size_t const offset)
{
	uint32_t *ptr;
	void *map = txts->data->d_buf;

	ptr = map + offset;
	/* bl <_mcount> is 0x94000000 before relocation */
	if (*ptr != 0x94000000)
		return -1;

	/* Convert to nop */
	memcpy(map + offset, ideal_nop, 4);
	return 0;
}

/* w8rev, w8nat, ...: Handle endianness. */

static uint64_t w8rev(uint64_t const x)
{
	return   ((0xff & (x >> (0 * 8))) << (7 * 8))
	       | ((0xff & (x >> (1 * 8))) << (6 * 8))
	       | ((0xff & (x >> (2 * 8))) << (5 * 8))
	       | ((0xff & (x >> (3 * 8))) << (4 * 8))
	       | ((0xff & (x >> (4 * 8))) << (3 * 8))
	       | ((0xff & (x >> (5 * 8))) << (2 * 8))
	       | ((0xff & (x >> (6 * 8))) << (1 * 8))
	       | ((0xff & (x >> (7 * 8))) << (0 * 8));
}

static uint32_t w4rev(uint32_t const x)
{
	return   ((0xff & (x >> (0 * 8))) << (3 * 8))
	       | ((0xff & (x >> (1 * 8))) << (2 * 8))
	       | ((0xff & (x >> (2 * 8))) << (1 * 8))
	       | ((0xff & (x >> (3 * 8))) << (0 * 8));
}

static uint32_t w2rev(uint16_t const x)
{
	return   ((0xff & (x >> (0 * 8))) << (1 * 8))
	       | ((0xff & (x >> (1 * 8))) << (0 * 8));
}

static uint64_t w8nat(uint64_t const x)
{
	return x;
}

static uint32_t w4nat(uint32_t const x)
{
	return x;
}

static uint32_t w2nat(uint16_t const x)
{
	return x;
}

static uint64_t (*w8)(uint64_t);
static uint32_t (*w)(uint32_t);
static uint32_t (*w2)(uint16_t);

/* Names of the sections that could contain calls to mcount. */
static int is_mcounted_section_name(char const *const txtname)
{
	return strncmp(".text",          txtname, 5) == 0 ||
		strcmp(".init.text",     txtname) == 0 ||
		strcmp(".ref.text",      txtname) == 0 ||
		strcmp(".sched.text",    txtname) == 0 ||
		strcmp(".spinlock.text", txtname) == 0 ||
		strcmp(".irqentry.text", txtname) == 0 ||
		strcmp(".softirqentry.text", txtname) == 0 ||
		strcmp(".kprobes.text", txtname) == 0 ||
		strcmp(".cpuidle.text", txtname) == 0;
}

static unsigned get_mcountsym(struct rela *rela)
{
	struct symbol *sym = rela->sym;
	char const *symname = sym->name;
	char const *mcount = gpfx == '_' ? "_mcount" : "mcount";
	char const *fentry = "__fentry__";

	if (symname[0] == '.')
		++symname;  /* ppc64 hack */
	if (strcmp(mcount, symname) == 0 ||
	    (altmcount && strcmp(altmcount, symname) == 0) ||
	    (strcmp(fentry, symname) == 0))
		return GELF_R_INFO(rela->sym->idx, rela->type);
	return 0;
}

/*
 * MIPS mcount long call has 2 _mcount symbols, only the position of the 1st
 * _mcount symbol is needed for dynamic function tracer, with it, to disable
 * tracing(ftrace_make_nop), the instruction in the position is replaced with
 * the "b label" instruction, to enable tracing(ftrace_make_call), replace the
 * instruction back. So, here, we set the 2nd one as fake and filter it.
 *
 * c:	3c030000	lui	v1,0x0		<-->	b	label
 *		c: R_MIPS_HI16	_mcount
 *		c: R_MIPS_NONE	*ABS*
 *		c: R_MIPS_NONE	*ABS*
 * 10:	64630000	daddiu	v1,v1,0
 *		10: R_MIPS_LO16	_mcount
 *		10: R_MIPS_NONE	*ABS*
 *		10: R_MIPS_NONE	*ABS*
 * 14:	03e0082d	move	at,ra
 * 18:	0060f809	jalr	v1
 * label:
 */
#define MIPS_FAKEMCOUNT_OFFSET	4

static int MIPS_is_fake_mcount(struct rela const *rela)
{
	unsigned long old_r_offset = ~0UL;
	unsigned long current_r_offset = rela->offset;
	int is_fake;

	is_fake = (old_r_offset != ~0UL) &&
		(current_r_offset - old_r_offset == MIPS_FAKEMCOUNT_OFFSET);
	old_r_offset = current_r_offset;

	return is_fake;
}

/* Functions and pointers that do_file() may override for specific e_machine. */
static int fn_is_fake_mcount(struct rela const *rela)
{
	return 0;
}

static int (*is_fake_mcount)(struct rela const *rela) = fn_is_fake_mcount;

static const unsigned int missing_sym = (unsigned int)-1;


/*
 * Find a symbol in the given section, to be used as the base for relocating
 * the table of offsets of calls to mcount.  A local or global symbol suffices,
 * but avoid a Weak symbol because it may be overridden; the change in value
 * would invalidate the relocations of the offsets of the calls to mcount.
 * Often the found symbol will be the unnamed local symbol generated by
 * GNU 'as' for the start of each section.  For example:
 *    Num:    Value  Size Type    Bind   Vis      Ndx Name
 *      2: 00000000     0 SECTION LOCAL  DEFAULT    1
 */
static unsigned int find_section_sym_index(unsigned const txtndx,
					   char const *const txtname,
					   unsigned long *const recvalp)
{
	struct symbol *sym;
	struct section *txts = find_section_by_index(lf, txtndx);

	if (!txts) {
		fprintf(stderr, "Cannot find section %u: %s.\n",
			txtndx, txtname);
		return missing_sym;
	}

	list_for_each_entry(sym, &txts->symbol_list, list) {
		if ((sym->bind == STB_LOCAL) || (sym->bind == STB_GLOBAL)) {
			/* function symbols on ARM have quirks, avoid them */
			if (lf->ehdr.e_machine == EM_ARM
			    && sym->type == STT_FUNC)
				continue;

			*recvalp = sym->sym.st_value;
			return sym->idx;
		}
	}
	fprintf(stderr, "Cannot find symbol for section %u: %s.\n",
		txtndx, txtname);
	return missing_sym;
}

/*
 * Read the relocation table again, but this time its called on sections
 * that are not going to be traced. The mcount calls here will be converted
 * into nops.
 */
static int nop_mcount(struct section * const rels,
		      const char *const txtname)
{
	struct rela *rela;
	struct section *txts = find_section_by_index(lf, rels->sh.sh_info);
	unsigned mcountsym = 0;
	int once = 0;

	list_for_each_entry(rela, &rels->rela_list, list) {
		int ret = -1;

		if (!mcountsym)
			mcountsym = get_mcountsym(rela);

		if (mcountsym == GELF_R_INFO(rela->sym->idx, rela->type) && !is_fake_mcount(rela)) {
			if (make_nop) {
				ret = make_nop(txts, rela->offset);
				if (ret < 0)
					return -1;
			}
			if (warn_on_notrace_sect && !once) {
				printf("Section %s has mcount callers being ignored\n",
				       txtname);
				once = 1;
				/* just warn? */
				if (!make_nop)
					return 0;
			}
		}

		/*
		 * If we successfully removed the mcount, mark the relocation
		 * as a nop (don't do anything with it).
		 */
		if (!ret) {
			rela->type = rel_type_nop;
			rels->changed = true;
		}
	}
	return 0;
}

/* 32 bit and 64 bit are very similar */
#include "recordmcount.h"
#define RECORD_MCOUNT_64
#include "recordmcount.h"

/* 64-bit EM_MIPS has weird ELF64_Rela.r_info.
 * http://techpubs.sgi.com/library/manuals/4000/007-4658-001/pdf/007-4658-001.pdf
 * We interpret Table 29 Relocation Operation (Elf64_Rel, Elf64_Rela) [p.40]
 * to imply the order of the members; the spec does not say so.
 *	typedef unsigned char Elf64_Byte;
 * fails on MIPS64 because their <elf.h> already has it!
 */

typedef uint8_t myElf64_Byte;		/* Type for a 8-bit quantity.  */

union mips_r_info {
	Elf64_Xword r_info;
	struct {
		Elf64_Word r_sym;		/* Symbol index.  */
		myElf64_Byte r_ssym;		/* Special symbol.  */
		myElf64_Byte r_type3;		/* Third relocation.  */
		myElf64_Byte r_type2;		/* Second relocation.  */
		myElf64_Byte r_type;		/* First relocation.  */
	} r_mips;
};

static void MIPS64_r_info(Elf64_Rel *const rp, unsigned sym, unsigned type)
{
	rp->r_info = ((union mips_r_info){
		.r_mips = { .r_sym = w(sym), .r_type = type }
	}).r_info;
}

static int do_file(char const *const fname)
{
	Elf32_Ehdr *ehdr;
	unsigned int reltype = 0;
	int rc = -1;

	ehdr = mmap_file(fname);
	if (!ehdr)
		goto out;

	w = w4nat;
	w2 = w2nat;
	w8 = w8nat;
	switch (ehdr->e_ident[EI_DATA]) {
		static unsigned int const endian = 1;
	default:
		fprintf(stderr, "unrecognized ELF data encoding %d: %s\n",
			ehdr->e_ident[EI_DATA], fname);
		goto out;
	case ELFDATA2LSB:
		if (*(unsigned char const *)&endian != 1) {
			/* objtool is big endian, file.o is little endian. */
			w = w4rev;
			w2 = w2rev;
			w8 = w8rev;
		}
		ideal_nop4_arm = ideal_nop4_arm_le;
		bl_mcount_arm = bl_mcount_arm_le;
		push_arm = push_arm_le;
		ideal_nop2_thumb = ideal_nop2_thumb_le;
		push_bl_mcount_thumb = push_bl_mcount_thumb_le;
		break;
	case ELFDATA2MSB:
		if (*(unsigned char const *)&endian != 0) {
			/*  objtool is little endian, file.o is big endian. */
			w = w4rev;
			w2 = w2rev;
			w8 = w8rev;
		}
		ideal_nop4_arm = ideal_nop4_arm_be;
		bl_mcount_arm = bl_mcount_arm_be;
		push_arm = push_arm_be;
		ideal_nop2_thumb = ideal_nop2_thumb_be;
		push_bl_mcount_thumb = push_bl_mcount_thumb_be;
		break;
	}  /* end switch */
	if (memcmp(ELFMAG, ehdr->e_ident, SELFMAG) != 0 ||
	    w2(ehdr->e_type) != ET_REL ||
	    ehdr->e_ident[EI_VERSION] != EV_CURRENT) {
		fprintf(stderr, "unrecognized ET_REL file %s\n", fname);
		goto out;
	}

	gpfx = '_';
	switch (w2(ehdr->e_machine)) {
	default:
		fprintf(stderr, "unrecognized e_machine %u %s\n",
			w2(ehdr->e_machine), fname);
		goto out;
	case EM_386:
		reltype = R_386_32;
		rel_type_nop = R_386_NONE;
		make_nop = make_nop_x86;
		ideal_nop = ideal_nop5_x86_32;
		mcount_adjust_32 = -1;
		gpfx = 0;
		break;
	case EM_ARM:
		reltype = R_ARM_ABS32;
		altmcount = "__gnu_mcount_nc";
		make_nop = make_nop_arm;
		rel_type_nop = R_ARM_NONE;
		gpfx = 0;
		break;
	case EM_AARCH64:
		reltype = R_AARCH64_ABS64;
		make_nop = make_nop_arm64;
		rel_type_nop = R_AARCH64_NONE;
		ideal_nop = ideal_nop4_arm64;
		break;
	case EM_IA_64:	reltype = R_IA64_IMM64; break;
	case EM_MIPS:	/* reltype: e_class    */ break;
	case EM_PPC:	reltype = R_PPC_ADDR32; break;
	case EM_PPC64:	reltype = R_PPC64_ADDR64; break;
	case EM_S390:	/* reltype: e_class    */ break;
	case EM_SH:	reltype = R_SH_DIR32; gpfx = 0; break;
	case EM_SPARCV9: reltype = R_SPARC_64; break;
	case EM_X86_64:
		make_nop = make_nop_x86;
		ideal_nop = ideal_nop5_x86_64;
		reltype = R_X86_64_64;
		rel_type_nop = R_X86_64_NONE;
		mcount_adjust_64 = -1;
		gpfx = 0;
		break;
	}  /* end switch */

	switch (ehdr->e_ident[EI_CLASS]) {
	default:
		fprintf(stderr, "unrecognized ELF class %d %s\n",
			ehdr->e_ident[EI_CLASS], fname);
		goto out;
	case ELFCLASS32:
		if (w2(ehdr->e_ehsize) != sizeof(Elf32_Ehdr)
		||  w2(ehdr->e_shentsize) != sizeof(Elf32_Shdr)) {
			fprintf(stderr,
				"unrecognized ET_REL file: %s\n", fname);
			goto out;
		}
		if (w2(ehdr->e_machine) == EM_MIPS) {
			reltype = R_MIPS_32;
			is_fake_mcount = MIPS_is_fake_mcount;
		}
		if (do32(reltype) < 0)
			goto out;
		break;
	case ELFCLASS64: {
		Elf64_Ehdr *const ghdr = (Elf64_Ehdr *)ehdr;
		if (w2(ghdr->e_ehsize) != sizeof(Elf64_Ehdr)
		||  w2(ghdr->e_shentsize) != sizeof(Elf64_Shdr)) {
			fprintf(stderr,
				"unrecognized ET_REL file: %s\n", fname);
			goto out;
		}
		if (w2(ghdr->e_machine) == EM_S390) {
			reltype = R_390_64;
			mcount_adjust_64 = -14;
		}
		if (w2(ghdr->e_machine) == EM_MIPS) {
			reltype = R_MIPS_64;
			Elf64_r_info = MIPS64_r_info;
			is_fake_mcount = MIPS_is_fake_mcount;
		}
		if (do64(reltype) < 0)
			goto out;
		break;
	}
	}  /* end switch */

out:
	mmap_cleanup();
	return rc;
}

int record_mcount(int argc, const char **argv)
{
	const char ftrace[] = "/ftrace.o";
	int ftrace_size = sizeof(ftrace) - 1;
	int n_error = 0;  /* gcc-4.3.0 false positive complaint */
	int i;

	if (argc < 1) {
		fprintf(stderr, "usage: objtool mcount record [-w] file.o...\n");
		return 0;
	}

	/* Process each file in turn, allowing deep failure. */
	for (i = 0; i < argc; i++) {
		const char *file = argv[i];
		int len;

		/*
		 * The file kernel/trace/ftrace.o references the mcount
		 * function but does not call it. Since ftrace.o should
		 * not be traced anyway, we just skip it.
		 */
		len = strlen(file);
		if (len >= ftrace_size &&
		    strcmp(file + (len - ftrace_size), ftrace) == 0)
			continue;

		if (do_file(file)) {
			fprintf(stderr, "%s: failed\n", file);
			++n_error;
		}
	}
	return !!n_error;
}

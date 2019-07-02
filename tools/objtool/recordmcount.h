/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * recordmcount.h
 *
 * This code was taken out of recordmcount.c written by
 * Copyright 2009 John F. Reiser <jreiser@BitWagon.com>.  All rights reserved.
 *
 * The original code had the same algorithms for both 32bit
 * and 64bit ELF files, but the code was duplicated to support
 * the difference in structures that were used. This
 * file creates a macro of everything that is different between
 * the 64 and 32 bit code, such that by including this header
 * twice we can create both sets of functions by including this
 * header once with RECORD_MCOUNT_64 undefined, and again with
 * it defined.
 *
 * This conversion to macros was done by:
 * Copyright 2010 Steven Rostedt <srostedt@redhat.com>, Red Hat Inc.
 */
#undef append_func
#undef is_fake_mcount
#undef fn_is_fake_mcount
#undef MIPS_is_fake_mcount
#undef mcount_adjust
#undef sift_rel_mcount
#undef nop_mcount
#undef missing_sym
#undef find_section_sym_index
#undef has_rel_mcount
#undef tot_relsize
#undef get_mcountsym
#undef get_relp
#undef do_func
#undef Elf_Addr
#undef Elf_Ehdr
#undef Elf_Shdr
#undef Elf_Rel
#undef Elf_Rela
#undef Elf_Sym
#undef ELF_R_SYM
#undef Elf_r_sym
#undef ELF_R_INFO
#undef Elf_r_info
#undef ELF_ST_BIND
#undef ELF_ST_TYPE
#undef fn_ELF_R_SYM
#undef fn_ELF_R_INFO
#undef uint_t
#undef _w
#undef _align
#undef _size

#ifdef RECORD_MCOUNT_64
# define append_func		append64
# define sift_rel_mcount	sift64_rel_mcount
# define nop_mcount		nop_mcount_64
# define missing_sym		missing_sym_64
# define find_section_sym_index	find64_section_sym_index
# define has_rel_mcount		has64_rel_mcount
# define tot_relsize		tot64_relsize
# define get_relp		get_relp_64
# define do_func		do64
# define get_mcountsym		get_mcountsym_64
# define is_fake_mcount		is_fake_mcount64
# define fn_is_fake_mcount	fn_is_fake_mcount64
# define MIPS_is_fake_mcount	MIPS64_is_fake_mcount
# define mcount_adjust		mcount_adjust_64
# define Elf_Addr		Elf64_Addr
# define Elf_Ehdr		Elf64_Ehdr
# define Elf_Shdr		Elf64_Shdr
# define Elf_Rel		Elf64_Rel
# define Elf_Rela		Elf64_Rela
# define Elf_Sym		Elf64_Sym
# define ELF_R_SYM		ELF64_R_SYM
# define Elf_r_sym		Elf64_r_sym
# define ELF_R_INFO		ELF64_R_INFO
# define Elf_r_info		Elf64_r_info
# define ELF_ST_BIND		ELF64_ST_BIND
# define ELF_ST_TYPE		ELF64_ST_TYPE
# define fn_ELF_R_SYM		fn_ELF64_R_SYM
# define fn_ELF_R_INFO		fn_ELF64_R_INFO
# define uint_t			uint64_t
# define _w			w8
# define _align			7u
# define _size			8
#else
# define append_func		append32
# define sift_rel_mcount	sift32_rel_mcount
# define nop_mcount		nop_mcount_32
# define missing_sym		missing_sym_32
# define find_section_sym_index	find32_section_sym_index
# define has_rel_mcount		has32_rel_mcount
# define tot_relsize		tot32_relsize
# define get_relp		get_relp_32
# define do_func		do32
# define get_mcountsym		get_mcountsym_32
# define is_fake_mcount		is_fake_mcount32
# define fn_is_fake_mcount	fn_is_fake_mcount32
# define MIPS_is_fake_mcount	MIPS32_is_fake_mcount
# define mcount_adjust		mcount_adjust_32
# define Elf_Addr		Elf32_Addr
# define Elf_Ehdr		Elf32_Ehdr
# define Elf_Shdr		Elf32_Shdr
# define Elf_Rel		Elf32_Rel
# define Elf_Rela		Elf32_Rela
# define Elf_Sym		Elf32_Sym
# define ELF_R_SYM		ELF32_R_SYM
# define Elf_r_sym		Elf32_r_sym
# define ELF_R_INFO		ELF32_R_INFO
# define Elf_r_info		Elf32_r_info
# define ELF_ST_BIND		ELF32_ST_BIND
# define ELF_ST_TYPE		ELF32_ST_TYPE
# define fn_ELF_R_SYM		fn_ELF32_R_SYM
# define fn_ELF_R_INFO		fn_ELF32_R_INFO
# define uint_t			uint32_t
# define _w			w
# define _align			3u
# define _size			4
#endif

/* Functions and pointers that do_file() may override for specific e_machine. */
static int fn_is_fake_mcount(Elf_Rel const *rp)
{
	return 0;
}
static int (*is_fake_mcount)(Elf_Rel const *rp) = fn_is_fake_mcount;

static uint_t fn_ELF_R_SYM(Elf_Rel const *rp)
{
	return ELF_R_SYM(_w(rp->r_info));
}
static uint_t (*Elf_r_sym)(Elf_Rel const *rp) = fn_ELF_R_SYM;

static void fn_ELF_R_INFO(Elf_Rel *const rp, unsigned sym, unsigned type)
{
	rp->r_info = _w(ELF_R_INFO(sym, type));
}
static void (*Elf_r_info)(Elf_Rel *const rp, unsigned sym, unsigned type) = fn_ELF_R_INFO;

static int mcount_adjust = 0;

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

static int MIPS_is_fake_mcount(Elf_Rel const *rp)
{
	static Elf_Addr old_r_offset = ~(Elf_Addr)0;
	Elf_Addr current_r_offset = _w(rp->r_offset);
	int is_fake;

	is_fake = (old_r_offset != ~(Elf_Addr)0) &&
		(current_r_offset - old_r_offset == MIPS_FAKEMCOUNT_OFFSET);
	old_r_offset = current_r_offset;

	return is_fake;
}

/* Append the new shstrtab, Elf_Shdr[], __mcount_loc and its relocations. */
static int append_func(Elf_Ehdr *const ehdr,
			Elf_Shdr *const shstr,
			uint_t const *const mloc0,
			uint_t const *const mlocp,
			Elf_Rel const *const mrel0,
			Elf_Rel const *const mrelp,
			unsigned int const rel_entsize,
			unsigned int const symsec_sh_link)
{
	/* Begin constructing output file */
	Elf_Shdr mcsec;
	char const *mc_name = (sizeof(Elf_Rela) == rel_entsize)
		? ".rela__mcount_loc"
		:  ".rel__mcount_loc";
	unsigned const old_shnum = w2(ehdr->e_shnum);
	uint_t const old_shoff = _w(ehdr->e_shoff);
	uint_t const old_shstr_sh_size   = _w(shstr->sh_size);
	uint_t const old_shstr_sh_offset = _w(shstr->sh_offset);
	uint_t t = 1 + strlen(mc_name) + _w(shstr->sh_size);
	uint_t new_e_shoff;

	shstr->sh_size = _w(t);
	shstr->sh_offset = _w(sb.st_size);

	t += sb.st_size;
	t += (_align & -t);  /* word-byte align */
	new_e_shoff = t;

	/* body for new shstrtab */
	if (ulseek(sb.st_size, SEEK_SET) < 0)
		return -1;
	if (uwrite(old_shstr_sh_offset + (void *)ehdr, old_shstr_sh_size) < 0)
		return -1;
	if (uwrite(mc_name, 1 + strlen(mc_name)) < 0)
		return -1;

	/* old(modified) Elf_Shdr table, word-byte aligned */
	if (ulseek(t, SEEK_SET) < 0)
		return -1;
	t += sizeof(Elf_Shdr) * old_shnum;
	if (uwrite(old_shoff + (void *)ehdr,
	       sizeof(Elf_Shdr) * old_shnum) < 0)
		return -1;

	/* new sections __mcount_loc and .rel__mcount_loc */
	t += 2*sizeof(mcsec);
	mcsec.sh_name = w((sizeof(Elf_Rela) == rel_entsize) + strlen(".rel")
		+ old_shstr_sh_size);
	mcsec.sh_type = w(SHT_PROGBITS);
	mcsec.sh_flags = _w(SHF_ALLOC);
	mcsec.sh_addr = 0;
	mcsec.sh_offset = _w(t);
	mcsec.sh_size = _w((void *)mlocp - (void *)mloc0);
	mcsec.sh_link = 0;
	mcsec.sh_info = 0;
	mcsec.sh_addralign = _w(_size);
	mcsec.sh_entsize = _w(_size);
	if (uwrite(&mcsec, sizeof(mcsec)) < 0)
		return -1;

	mcsec.sh_name = w(old_shstr_sh_size);
	mcsec.sh_type = (sizeof(Elf_Rela) == rel_entsize)
		? w(SHT_RELA)
		: w(SHT_REL);
	mcsec.sh_flags = 0;
	mcsec.sh_addr = 0;
	mcsec.sh_offset = _w((void *)mlocp - (void *)mloc0 + t);
	mcsec.sh_size   = _w((void *)mrelp - (void *)mrel0);
	mcsec.sh_link = w(symsec_sh_link);
	mcsec.sh_info = w(old_shnum);
	mcsec.sh_addralign = _w(_size);
	mcsec.sh_entsize = _w(rel_entsize);

	if (uwrite(&mcsec, sizeof(mcsec)) < 0)
		return -1;

	if (uwrite(mloc0, (void *)mlocp - (void *)mloc0) < 0)
		return -1;
	if (uwrite(mrel0, (void *)mrelp - (void *)mrel0) < 0)
		return -1;

	ehdr->e_shoff = _w(new_e_shoff);
	ehdr->e_shnum = w2(2 + w2(ehdr->e_shnum));  /* {.rel,}__mcount_loc */
	if (ulseek(0, SEEK_SET) < 0)
		return -1;
	if (uwrite(ehdr, sizeof(*ehdr)) < 0)
		return -1;
	return elf_write(lf);
}

static unsigned get_mcountsym(Elf_Rel const *relp)
{
	struct symbol *sym = find_symbol_by_index(lf, Elf_r_sym(relp));
	char const *symname = sym->name;
	char const *mcount = gpfx == '_' ? "_mcount" : "mcount";
	char const *fentry = "__fentry__";

	if (symname[0] == '.')
		++symname;  /* ppc64 hack */
	if (strcmp(mcount, symname) == 0 ||
	    (altmcount && strcmp(altmcount, symname) == 0) ||
	    (strcmp(fentry, symname) == 0))
		return Elf_r_sym(relp);
	return 0;
}

static void get_relp(const struct section * const rels,
			Elf_Ehdr const *const ehdr,
			Elf_Rel const **relp)
{
	Elf_Rel const *const rel0 = (Elf_Rel const *)(rels->sh.sh_offset
		+ (void *)ehdr);
	*relp = rel0;
}

/*
 * Look at the relocations in order to find the calls to mcount.
 * Accumulate the section offsets that are found, and their relocation info,
 * onto the end of the existing arrays.
 */
static uint_t *sift_rel_mcount(uint_t *mlocp,
			       unsigned const offbase,
			       Elf_Rel **const mrelpp,
			       const struct section * const rels,
			       Elf_Ehdr const *const ehdr,
			       unsigned const recsym_index,
			       uint_t const recval,
			       unsigned const reltype)
{
	uint_t *const mloc0 = mlocp;
	Elf_Rel *mrelp = *mrelpp;
	Elf_Rel const *relp;
	unsigned int rel_entsize = rels->sh.sh_entsize;
	unsigned const nrel = rels->sh.sh_size / rel_entsize;
	unsigned mcountsym = 0;
	unsigned t;

	get_relp(rels, ehdr, &relp);

	for (t = nrel; t; --t) {
		if (!mcountsym)
			mcountsym = get_mcountsym(relp);

		if (mcountsym && mcountsym == Elf_r_sym(relp) &&
				!is_fake_mcount(relp)) {
			uint_t const addend =
				_w(_w(relp->r_offset) - recval + mcount_adjust);
			mrelp->r_offset = _w(offbase
				+ ((void *)mlocp - (void *)mloc0));
			Elf_r_info(mrelp, recsym_index, reltype);
			if (rel_entsize == sizeof(Elf_Rela)) {
				((Elf_Rela *)mrelp)->r_addend = addend;
				*mlocp++ = 0;
			} else
				*mlocp++ = addend;

			mrelp = (Elf_Rel *)(rel_entsize + (void *)mrelp);
		}
		relp = (Elf_Rel const *)(rel_entsize + (void *)relp);
	}
	*mrelpp = mrelp;
	return mlocp;
}

/*
 * Read the relocation table again, but this time its called on sections
 * that are not going to be traced. The mcount calls here will be converted
 * into nops.
 */
static int nop_mcount(const struct section * const rels,
		      Elf_Ehdr const *const ehdr,
		      const char *const txtname)
{
	Elf_Shdr *const shdr0 = (Elf_Shdr *)(_w(ehdr->e_shoff)
		+ (void *)ehdr);
	Elf_Rel const *relp;
	Elf_Shdr const *const shdr = &shdr0[rels->sh.sh_info];
	unsigned rel_entsize = rels->sh.sh_entsize;
	unsigned const nrel = rels->sh.sh_size / rel_entsize;
	unsigned mcountsym = 0;
	unsigned t;
	int once = 0;

	get_relp(rels, ehdr, &relp);

	for (t = nrel; t; --t) {
		int ret = -1;

		if (!mcountsym)
			mcountsym = get_mcountsym(relp);

		if (mcountsym == Elf_r_sym(relp) && !is_fake_mcount(relp)) {
			if (make_nop) {
				ret = make_nop((void *)ehdr, _w(shdr->sh_offset) + _w(relp->r_offset));
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
			Elf_Rel rel;
			rel = *(Elf_Rel *)relp;
			Elf_r_info(&rel, Elf_r_sym(relp), rel_type_nop);
			if (ulseek((void *)relp - (void *)ehdr, SEEK_SET) < 0)
				return -1;
			if (uwrite(&rel, sizeof(rel)) < 0)
				return -1;
		}
		relp = (Elf_Rel const *)(rel_entsize + (void *)relp);
	}
	return 0;
}

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
				uint_t *const recvalp,
				Elf_Ehdr const *const ehdr)
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
			if (w2(ehdr->e_machine) == EM_ARM
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

static char const *has_rel_mcount(const struct section * const rels)
{
	const struct section *txts;
	if (rels->sh.sh_type != SHT_REL && rels->sh.sh_type != SHT_RELA)
		return NULL;
	txts = find_section_by_index(lf, rels->sh.sh_info);
	if ((txts->sh.sh_type != SHT_PROGBITS) ||
	    !(txts->sh.sh_flags & SHF_EXECINSTR))
		return NULL;
	return txts->name;
}


static unsigned tot_relsize()
{
	const struct section *sec;
	unsigned totrelsz = 0;
	char const *txtname;

	list_for_each_entry(sec, &lf->sections, list) {
		txtname = has_rel_mcount(sec);
		if (txtname && is_mcounted_section_name(txtname))
			totrelsz += sec->sh.sh_size;
	}
	return totrelsz;
}


/* Overall supervision for Elf32 ET_REL file. */
static int do_func(Elf_Ehdr *const ehdr
		   unsigned const reltype)
{
	Elf_Shdr *const shdr0 = (Elf_Shdr *)(_w(ehdr->e_shoff)
		+ (void *)ehdr);

	/* Upper bound on space: assume all relevant relocs are for mcount. */
	unsigned       totrelsz;

	Elf_Rel *      mrel0;
	Elf_Rel *      mrelp;

	uint_t *      mloc0;
	uint_t *      mlocp;

	unsigned rel_entsize = 0;
	unsigned symsec_sh_link = 0;

	const struct section *sec;

	int result = 0;

	if (find_section_by_name(lf, "__mcount_loc") != NULL)
		return 0;

	totrelsz = tot_relsize();
	if (totrelsz == 0)
		return 0;
	mrel0 = umalloc(totrelsz);
	mrelp = mrel0;
	if (!mrel0)
		return -1;

	/* 2*sizeof(address) <= sizeof(Elf_Rel) */
	mloc0 = umalloc(totrelsz>>1);
	mlocp = mloc0;
	if (!mloc0) {
		free(mrel0);
		return -1;
	}

	list_for_each_entry(sec, &lf->sections, list) {
		char const *txtname;

		txtname = has_rel_mcount(sec);
		if (txtname && is_mcounted_section_name(txtname)) {
			uint_t recval = 0;
			unsigned int recsym_index;

			symsec_sh_link = sec->sh.sh_link;
			recsym_index = find_section_sym_index(
				sec->sh.sh_info, txtname, &recval,
				ehdr);
			if (recsym_index == missing_sym) {
				result = -1;
				goto out;
			}

			rel_entsize = sec->sh.sh_entsize;
			mlocp = sift_rel_mcount(mlocp,
				(void *)mlocp - (void *)mloc0, &mrelp,
				sec, ehdr, recsym_index, recval, reltype);
		} else if (txtname && (warn_on_notrace_sect || make_nop)) {
			/*
			 * This section is ignored by ftrace, but still
			 * has mcount calls. Convert them to nops now.
			 */
			if (nop_mcount(sec, ehdr, txtname) < 0) {
				result = -1;
				goto out;
			}
		}
	}
	if (!result && mloc0 != mlocp)
		result = append_func(ehdr, &shdr0[w2(ehdr->e_shstrndx)],
				     mloc0, mlocp, mrel0, mrelp,
				     rel_entsize, symsec_sh_link);
out:
	free(mrel0);
	free(mloc0);
	return result;
}

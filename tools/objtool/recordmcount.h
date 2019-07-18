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
#undef sift_rel_mcount
#undef do_func
#undef Elf_Shdr
#undef Elf_Rel
#undef Elf_Rela
#undef ELF_R_INFO
#undef Elf_r_info
#undef fn_ELF_R_INFO
#undef uint_t
#undef _w
#undef _size

#ifdef RECORD_MCOUNT_64
# define sift_rel_mcount	sift64_rel_mcount
# define do_func		do64
# define Elf_Rel		Elf64_Rel
# define Elf_Rela		Elf64_Rela
# define ELF_R_INFO		ELF64_R_INFO
# define Elf_r_info		Elf64_r_info
# define fn_ELF_R_INFO		fn_ELF64_R_INFO
# define uint_t			uint64_t
# define _w			w8
# define _size			8
#else
# define sift_rel_mcount	sift32_rel_mcount
# define do_func		do32
# define Elf_Rel		Elf32_Rel
# define Elf_Rela		Elf32_Rela
# define ELF_R_INFO		ELF32_R_INFO
# define Elf_r_info		Elf32_r_info
# define fn_ELF_R_INFO		fn_ELF32_R_INFO
# define uint_t			uint32_t
# define _w			w
# define _size			4
#endif

static void fn_ELF_R_INFO(Elf_Rel *const rp, unsigned sym, unsigned type)
{
	rp->r_info = _w(ELF_R_INFO(sym, type));
}
static void (*Elf_r_info)(Elf_Rel *const rp, unsigned sym, unsigned type) = fn_ELF_R_INFO;

/*
 * Look at the relocations in order to find the calls to mcount.
 * Accumulate the section offsets that are found, and their relocation info,
 * onto the end of the existing arrays.
 */
static uint_t *sift_rel_mcount(uint_t *mlocp,
			       unsigned const offbase,
			       Elf_Rel **const mrelpp,
			       const struct section * const rels,
			       unsigned const recsym_index,
			       unsigned long const recval,
			       unsigned const reltype)
{
	uint_t *const mloc0 = mlocp;
	Elf_Rel *mrelp = *mrelpp;
	unsigned int rel_entsize = rels->sh.sh_entsize;
	unsigned mcountsym = 0;
	struct rela *rela;

	list_for_each_entry(rela, &rels->rela_list, list) {
		if (!mcountsym)
			mcountsym = get_mcountsym(rela);

		if (mcountsym == GELF_R_INFO(rela->sym->idx, rela->type) && !is_fake_mcount(rela)) {
			uint_t const addend =
				_w(rela->offset - recval + mcount_adjust);
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
	}
	*mrelpp = mrelp;
	return mlocp;
}


/* Overall supervision for Elf32 ET_REL file. */
static int do_func(unsigned const reltype)
{
	/* Upper bound on space: assume all relevant relocs are for mcount. */
	unsigned       totrelsz;

	Elf_Rel *      mrel0;
	Elf_Rel *      mrelp;

	uint_t *      mloc0;
	uint_t *      mlocp;

	unsigned int rel_entsize = 0;

	struct section *sec, *mlocs, *mrels;
	unsigned int const old_shnum = lf->ehdr.e_shnum;

	char const *mc_name;
	bool is_rela;

	if (find_section_by_name(lf, "__mcount_loc") != NULL)
		return 0;

	totrelsz = tot_relsize(&rel_entsize);
	if (totrelsz == 0)
		return 0;

	mrel0 = malloc(totrelsz);
	mrelp = mrel0;
	if (!mrel0)
		return -1;

	/* 2*sizeof(address) <= sizeof(Elf_Rel) */
	mloc0 = malloc(totrelsz>>1);
	mlocp = mloc0;
	if (!mloc0) {
		free(mrel0);
		return -1;
	}

	is_rela = (sizeof(Elf_Rela) == rel_entsize);
	mc_name = is_rela
			? ".rela__mcount_loc"
			:  ".rel__mcount_loc";

	/* add section: __mcount_loc */
	mlocs = elf_create_section(lf, mc_name + (is_rela ? 1 : 0) + strlen(".rel"), _size, 0);
	if (!mlocs)
		goto out;

	mlocs->sh.sh_link = 0;
	mlocs->sh.sh_info = 0;
	mlocs->sh.sh_addralign = _size;

	/* add section .rel[a]__mcount_loc */
	mrels = elf_create_section(lf, mc_name, rel_entsize, 0);
	if (!mrels)
		goto out;
	mrels->sh.sh_type = is_rela
				? SHT_RELA
				: SHT_REL;
	mrels->sh.sh_flags = 0;
	mrels->sh.sh_link = find_section_by_name(lf, ".symtab")->idx;
	mrels->sh.sh_info = old_shnum;
	mrels->sh.sh_addralign = _size;

	list_for_each_entry(sec, &lf->sections, list) {
		char const *txtname;

		txtname = has_rel_mcount(sec);
		if (txtname && is_mcounted_section_name(txtname)) {
			unsigned long recval = 0;
			unsigned int recsym_index;

			recsym_index = find_section_sym_index(
				sec->sh.sh_info, txtname, &recval);
			if (recsym_index == missing_sym)
				goto out;

			mlocp = sift_rel_mcount(mlocp,
				(void *)mlocp - (void *)mloc0, &mrelp,
				sec, recsym_index, (uint_t)recval, reltype);
		} else if (txtname && (warn_on_notrace_sect || make_nop)) {
			/*
			 * This section is ignored by ftrace, but still
			 * has mcount calls. Convert them to nops now.
			 */
			if (nop_mcount(sec, txtname) < 0)
				goto out;
		}
	}

	if (mloc0 != mlocp) {
		/* Update the section sizes */
		mlocs->sh.sh_size = (void *)mlocp - (void *)mloc0;
		mlocs->len = mlocs->sh.sh_size;
		mlocs->data->d_size = mlocs->len;
		mlocs->data->d_buf = mloc0;

		mrels->sh.sh_size = (void *)mrelp - (void *)mrel0;
		mrels->len = mrels->sh.sh_size;
		mrels->data->d_size = mrels->len;
		mrels->data->d_buf = mrel0;

		/* overwrite the ELF file */
		return elf_write(lf);
	}
	return 0;
out:
	free(mrel0);
	free(mloc0);
	return -1;
}

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
#undef Elf_Rela

#ifdef RECORD_MCOUNT_64
# define sift_rel_mcount	sift64_rel_mcount
# define do_func		do64
# define Elf_Rela		Elf64_Rela
#else
# define sift_rel_mcount	sift32_rel_mcount
# define do_func		do32
# define Elf_Rela		Elf32_Rela
#endif

/*
 * Look at the relocations in order to find the calls to mcount.
 * Accumulate the section offsets that are found, and their relocation info,
 * onto the end of the existing arrays.
 */
static void sift_rel_mcount(GElf_Addr **mlocpp,
			       GElf_Sxword *r_offsetp,
			       void **const mrelpp,
			       const struct section * const rels,
			       unsigned const recsym_index,
			       unsigned long const recval,
			       unsigned const reltype,
			       bool is_rela)
{
	GElf_Rel *mrelp = *mrelpp;
	GElf_Rela *mrelap = *mrelpp;
	unsigned int mcount_sym_info = 0;
	struct rela *rela;

	list_for_each_entry(rela, &rels->rela_list, list) {
		unsigned long addend;

		if (!mcount_sym_info)
			mcount_sym_info = get_mcount_sym_info(rela);

		if (mcount_sym_info != GELF_R_INFO(rela->sym->idx, rela->type) || is_fake_mcount(rela))
			continue;

		addend = rela->offset - recval + mcount_adjust;
		if (is_rela) {
			mrelap->r_offset = *r_offsetp;
			mrelap->r_info = GELF_R_INFO(recsym_index, reltype);
			mrelap->r_addend = addend;
			mrelap++;
			**mlocpp = 0;
		} else {
			mrelp->r_offset = *r_offsetp;
			mrelp->r_info = GELF_R_INFO(recsym_index, reltype);
			mrelp++;
			**mlocpp = addend;
		}
		(*mlocpp)++;
		r_offsetp += loc_size;
	}
	*mrelpp = is_rela ? (void *)mrelap : (void *)mrelp;
}


/* Overall supervision for Elf32 ET_REL file. */
static int do_func(unsigned const reltype)
{
	/* Upper bound on space: assume all relevant relocs are for mcount. */
	unsigned       totrelsz;

	void *mrel0;
	void *mrelp;

	GElf_Addr *mloc0;
	GElf_Addr *mlocp;
	GElf_Sxword r_offset = 0;

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
	mlocs = elf_create_section(lf, mc_name + (is_rela ? 1 : 0) + strlen(".rel"), sizeof(*mloc0), 0);
	if (!mlocs)
		goto out;

	mlocs->sh.sh_link = 0;
	mlocs->sh.sh_info = 0;
	mlocs->sh.sh_addralign = 8;
	mlocs->data->d_buf = mloc0;
	mlocs->data->d_type = ELF_T_ADDR; /* elf_xlatetof() conversion */

	/* add section .rel[a]__mcount_loc */
	mrels = elf_create_section(lf, mc_name, rel_entsize, 0);
	if (!mrels)
		goto out;
	/* Like elf_create_rela_section() without the name bits */
	mrels->sh.sh_type = is_rela ? SHT_RELA : SHT_REL;
	mrels->sh.sh_flags = 0;
	mrels->sh.sh_link = find_section_by_name(lf, ".symtab")->idx;
	mrels->sh.sh_info = old_shnum;
	mrels->sh.sh_addralign = 8;
	mrels->data->d_buf = mrel0;
	mrels->data->d_type = is_rela ? ELF_T_RELA : ELF_T_REL; /* elf_xlatetof() conversion */

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

			sift_rel_mcount(&mlocp, &r_offset, &mrelp, sec,
				recsym_index, recval, reltype, is_rela);
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
		/* Update the section size and Elf_Data size */
		mlocs->sh.sh_size = (void *)mlocp - (void *)mloc0;
		mlocs->len = mlocs->sh.sh_size;
		mlocs->data->d_size = mlocs->len;

		mrels->sh.sh_size = mrelp - mrel0;
		mrels->len = mrels->sh.sh_size;
		mrels->data->d_size = mrels->len;

		/* overwrite the ELF file */
		return elf_write(lf);
	}
	return 0;
out:
	free(mrel0);
	free(mloc0);
	return -1;
}

/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2015 Josh Poimboeuf <jpoimboe@redhat.com>
 */
#ifndef _BUILTIN_H
#define _BUILTIN_H

#include <subcmd/parse-options.h>

/* An objtool command with optional subcommands */
struct cmd_struct {
	const char *const name;
	const char *const *subcmds;
	const char *const short_description;
	const char *const usage;
	const struct option *options;
	bool may_write;

	/* Save an values/configuration from parsed options */
	void *(*save_opts)(void);

	/* Run the command with the saved options on the ELF data */
	int (*fn)(void *, struct elf *);
};

/* Command has no subcommands */
extern const char *const *CMD_SUBCMDS_NONE;

/* Add an object file for processing in all passes. */
int append_obj(const char *path);

extern struct cmd_struct cmd_check;
extern struct cmd_struct cmd_orc;

#ifdef CMD_MCOUNT
extern struct cmd_struct cmd_mcount;
#else
#define cmd_mcount cmd_nop
#endif

#endif /* _BUILTIN_H */

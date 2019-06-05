// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2015 Josh Poimboeuf <jpoimboe@redhat.com>
 */

/*
 * objtool:
 *
 * The 'check' subcmd analyzes every .o file and ensures the validity of its
 * stack trace metadata.  It enforces a set of rules on asm code and C inline
 * assembly code so that stack traces can be reliable.
 *
 * For more information, see tools/objtool/Documentation/stack-validation.txt.
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <subcmd/exec-cmd.h>
#include <subcmd/pager.h>
#include <linux/kernel.h>
#include <linux/list.h>

#include "builtin.h"

static const char objtool_usage_string[] =
	"objtool COMMAND [ARGS]";

const char *const CMD_SUBCMDS_NONE[] = { NULL };

static struct cmd_struct *objtool_cmds[] = {
	&cmd_check, &cmd_orc, &cmd_mcount,
};

static struct cmd_struct *find_cmd(const char *cmd)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(objtool_cmds); i++) {
		struct cmd_struct *p = objtool_cmds[i];

		if (strcmp(p->name, cmd))
			continue;
		return p;
	}
	return NULL;
}

bool help;

static void cmd_usage(void)
{
	unsigned int i, longest = 0;

	printf("\n usage: %s\n\n", objtool_usage_string);

	for (i = 0; i < ARRAY_SIZE(objtool_cmds); i++) {
		if (longest < strlen(objtool_cmds[i]->name))
			longest = strlen(objtool_cmds[i]->name);
	}

	puts(" Commands:");
	for (i = 0; i < ARRAY_SIZE(objtool_cmds); i++) {
		printf("   %-*s   ", longest, objtool_cmds[i]->name);
		puts(objtool_cmds[i]->short_description);
	}

	printf("\n");

	exit(129);
}

struct pass {
	struct list_head list;
	struct cmd_struct *cmd;
	const char *const *argv;
	int argc;
	void *saved_opts;
};

static LIST_HEAD(pass_list);

static struct pass *append_pass(const char *const *argv, int argc)
{
	struct pass *p;

	p = malloc(sizeof(*p));
	if (!p)
		return NULL;
	INIT_LIST_HEAD(&p->list);
	p->cmd = NULL;
	p->saved_opts = NULL;
	p->argv = argv;
	p->argc = argc;
	list_add_tail(&p->list, &pass_list);

	return p;
}

/* The list of object files to process */
struct obj_work {
	struct list_head list;
	struct elf *elf;
	const char *path; /* For warnings, logging, debugging... ONLY */
};

static LIST_HEAD(obj_list);

int append_obj(const char *path)
{
	struct obj_work *o;

	o = malloc(sizeof(*o));
	if (!o)
		return 1;
	INIT_LIST_HEAD(&o->list);
	o->path = path;
	o->elf = NULL;
	list_add_tail(&o->list, &obj_list);
	return 0;
}

static bool passes_may_write = false;
static int elf_open_flags = O_RDONLY;

static int parse_one_pass(struct pass *p)
{
	struct cmd_struct *c;
	int i, ret = EXIT_SUCCESS;

	if (p->argc < 1)
		return ret;

	prev_pass->cmd = c = find_cmd(p->argv[0]);
	if (c && !passes_may_write)
		passes_may_write = c->may_write;
	if (!c)
		goto remainder;

	i = parse_options_subcommand(p->argc, p->argv,
					c->options, c->subcmds,
					c->usage, 0);
	if (c->save_opts)
		p->saved_opts = c->save_opts();
	ret = EXIT_FAILURE;
	switch (i) {
	case PARSE_OPT_DONE:
		ret = EXIT_SUCCESS;
		break;
	case PARSE_OPT_LIST_SUBCMDS:
		fprintf(stderr, "%s subcommands:\n", c->name);
		for (i = 0; c->subcmds[i]; i++) {
			fprintf(stderr, "%s\n", c->subcmds[i]);
		}
	case PARSE_OPT_HELP:
	case PARSE_OPT_UNKNOWN:
	case PARSE_OPT_LIST_OPTS:
	default:
		usage_with_options(c->usage, c->options);
	}
remainder:
	for (i = 0; i < p->argc; i++) {
		if (append_obj(p->argv[i]))
			ret = EXIT_FAILURE;
	}

	return ret;
}

/*
 * Parse the command line arguments. Split each command line into
 * segments using -- as a separator. A pass is a segment with one
 * command that operates on input files. A segment may omit a
 * command and only specify objtool options, object files, or be
 * completely empty.
 *
 * objtool exits with an error unless:
 * At least one command was specified
 * At least one object file to work on was specified
 * All specified commands, executed in the order specified, succeeded on
 * 	all object files specified.
 *
 * Examples:
 * objtool objD.o -- check objA.o -- orc gen objB.o -- mcount objC.o -- objD.o objE.o
 *
 * This checks, generates ORC metadata, and records mcount calls on
 * **all** of the object files mentioned. Weirdly, it does so **twice** for
 * objD.o.
 *
 * Passes are somewhat analogous to shell pipes with some
 * important exceptions:
 *   The files operated on are not really passed via pipes. They are
 *   	opened by objtool then each pass operates on the opened file
 *   	without reopening it.
 *
 *   Objtool will only overwrite a file if all passes succeed on the
 *   	object file in question *and* any pass reports making changes.
 *
 *   The files will be appear to be editted in-place -- any temporary
 *   	files used will be hidden by the objtool commands.
 *
 * Otherwise they're like pipes:
 *   The contents of the file and which files are being processed are
 *   implicit in the order of the passes and the order of the object
 *   files.
 *
 * NOTE: The order must be presumed to be significant.
 *
 * 	 It's generally safer to run "check" commands first.
 *
 * 	 While it's currently true that the current set of commands can
 * 	 	be run in any order and produce the same results, this
 * 	 	will not always be true.
 */
static int parse_passes(int *argc, const char ***argv)
{
	static const char *const pass_sep = "--";
	struct pass *prev_pass = NULL;
	int ret = EXIT_FAILURE;
	int num_cmds_found = 0;
	const char *arg = NULL;

	prev_pass = append_pass(*argv, *argc);
	while (prev_pass && *argc > 0) {
		arg = (*argv)[0];

		if (!strcmp(arg, pass_sep)) {
			/* Adjust previous pass's arg count */
			prev_pass->argc -= *argc;
			(*argv)[0] = NULL;

			(*argv)++;
			(*argc)--;

			if (prev_pass->argc < 1) {
empty_pass:
				/*
				 * Previous pass was empty
				 * (e.g. successive -- args)
				 */
				prev_pass->argv = *argv;
				prev_pass->argc = *argc;
			} else {
				/* Parse the previous pass's args */
				if (parse_one_pass(prev_pass))
					goto out;
				if (!prev_pass->cmd)
					goto empty_pass;
				num_cmds_found++;

				/* Start a new pass */
				prev_pass = append_pass(*argv, *argc);
				if (!prev_pass)
					goto out;
			}
		} else {
			(*argv)++;
			(*argc)--;
		}
	}

	if (prev_pass && (!arg || strcmp(arg, pass_sep))) {
		/* We haven't parsed the last pass yet */
		ret = parse_one_pass(prev_pass);
		if (prev_pass->cmd)
			num_cmds_found++;
	}

	/* Remove trailing do-nothing passes */
	while (prev_pass && !prev_pass->cmd) {
		list_del(&prev_pass->list);
		free(prev_pass);

		if (!list_empty(&pass_list))
			prev_pass = list_prev(&pass_list);
		else {
			ret = EXIT_FAILURE;
			help = true;
			prev_pass = NULL;
			break;
		}
	}
out:
	elf_open_flags = passes_may_write ? O_RDWR : O_RDONLY;

	if (num_cmds_found < 1)
		help = true;

	return ret;
}

static int free_obj_list(void)
{
	struct obj_work *obj;
	int ret = EXIT_SUCCESS;

	list_for_each_entry_safe(obj, &obj_list, list) {
		list_del(&obj->list);
		if (elf_changed(obj->elf) && elf_write(obj->elf)) {
			/* TODO error in elf_write() */
			fprintf(stderr, "Error processing \"%s\"\n", obj->path);
			ret = EXIT_FAILURE;
		}

		/* NOTE: obj->path is presumed to be from main's argv */
		if (obj->elf)
			elf_close(obj->elf);
		free(obj);
	}

	return ret;
}

static void free_passes(void)
{
	struct pass *p;

	list_for_each_entry_safe(p, &pass_list, list) {
		list_del(&p->list);
		free(p);
	}
}

static int handle_internal_command(struct pass *pass, struct obj_work *obj)
{
	if (!pass || pass->argc < 1 || !pass->cmd ||
	    !obj || !obj->elf || !obj->path)
		return EXIT_FAILURE;
	return pass->cmd->fn(pass->saved_opts, obj->path, obj->elf);
}

int main(int argc, const char **argv)
{
	struct pass *pass;
	struct obj_work *obj;
	static const char *const UNUSED = "OBJTOOL_NOT_IMPLEMENTED";
	int exit_code = EXIT_SUCCESS;

	/* libsubcmd init */
	exec_cmd_init("objtool", UNUSED, UNUSED, UNUSED);
	pager_init(UNUSED);

	argv++;
	argc--;

	parse_passes(&argc, &argv);
	if (help)
		cmd_usage();

	if (list_empty(&obj_list)) {
		obj = malloc(sizeof(*obj));
		INIT_LIST_HEAD(&obj->list);
		obj->path = "/dev/stdin";
		obj->elf = NULL;
		list_add_tail(&obj->list, &obj_list);
	}

	list_for_each_entry(obj, &obj_list, list) {
		obj->elf = elf_open(obj->path, elf_open_flags);
		if (!obj->elf) {
			fprintf(stderr, "Failed to open \"%s\"\n", obj->path);
			exit_code = EXIT_FAILURE;
			continue;
		}

		/* NOTE: If there's more than one object we could fork here */

		list_for_each_entry(pass, &pass_list, list) {
			int ret = handle_internal_command(pass, obj);

			if (ret != EXIT_SUCCESS)
				exit_code = ret;
		}
	}

	if (free_obj_list() != EXIT_SUCCESS)
		exit_code = EXIT_FAILURE;
	free_passes();

	return exit_code;
}

#!/bin/bash

ARCH_ALL=x86
ARCH_NONE=powerpc

function assert_check_and_orc_available()
{
	local OBTOOL_STDOUT="$1"
	cmp - "${OBJTOOL_STDOUT}" <<-EOF_ALL_EOF
	 usage: objtool COMMAND [ARGS]

	 Commands:
	   check   Perform stack metadata validation on an object file
	   orc     Generate in-place ORC unwind tables for an object file

	EOF_ALL_EOF
}

function assert_none_available()
{
	local OBTOOL_STDOUT="$1"
	cmp - "${OBJTOOL_STDOUT}" <<-EOF_NONE_EOF
	 usage: objtool COMMAND [ARGS]

	 Commands:

	 Unavailable commands on this architecture:
	   check   Perform stack metadata validation on an object file
	   orc     Generate in-place ORC unwind tables for an object file

	EOF_NONE_EOF
}

for A in "${ARCH_ALL}" "${ARCH_NONE}" ; do
	case "${A}" in
	"")
		BA=""
		OA=""
		;;
	*)
		BA="-${A}"
		OA="ARCH=${A}"
		;;
	esac

	make O=build${BA} ${OA} defconfig tools/objtool
	./build${BA}/tools/objtool/objtool --help > \
		./build${BA}/tools/objtool/objtool.help.txt

	case "${A}" in
	${ARCH_ALL})
		assert_check_and_orc_available "./build${BA}/tools/objtool/objtool.help.txt" && continue
		;;
	${ARCH_NONE})
		assert_none_available "./build${BA}/tools/objtool/objtool.help.txt" && continue
		;;
	*)
		echo "Unexpected architecture used to test objtool"
		break 2
		;;
	esac

	echo "Unexpected output from objtool"
	break
done

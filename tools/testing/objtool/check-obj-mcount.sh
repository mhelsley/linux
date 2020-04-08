#!/bin/bash
set -ueE

PROG="$0"

function debug()
{
	#echo "$@"
	:
}

function result()
{
	echo "$@"
}

function check_obj_mcount()
{
	local TOOLCHAIN="$1"
	local TOOLCHAIN_="${TOOLCHAIN:+${TOOLCHAIN}-}"
	local OBJ="$2"

	[ -r "${OBJ}" ]

	debug "Checking the objdump output to make sure we added an __mcount_loc section"
	debug "${TOOLCHAIN_}objdump -x -j __mcount_loc -s ${OBJ}"
	"${TOOLCHAIN_}objdump" -x -j __mcount_loc -s "${OBJ}" | tail -n +2 | \
		awk -f "$(dirname "${PROG}")/diff-obj-mcount.awk" 
	local RC=$?
	return ${RC}
}

function expect_pass() { if "$@" ; then result PASS ; return 0; else result FAIL ; return 1; fi ; }
function expect_fail() { if "$@" ; then result FAIL ; return 1; else result PASS ; return 0; fi ; }

function test_this()
{
	trap 'rm ./foo.o ; popd > /dev/null ' EXIT

	debug "Compiling foo with mcount locations recorded"
	gcc -Wall -pg -O0 -g -mrecord-mcount -c foo.c -o foo.o
	expect_pass check_obj_mcount "" ./foo.o

	debug "Compiling foo without mcount locations recorded"
	gcc -Wall -pg -O0 -g -c foo.c -o foo.o
	expect_fail check_obj_mcount "" ./foo.o
}

if (( $# > 0 )); then
	echo "Running $0"
	for F in "$@" ; do
		echo "Checking \"${F}\""
		check_obj_mcount "" "${F}"
	done
else
	echo "Testing $0"
	pushd "$(dirname "$0")" > /dev/null
	trap 'popd > /dev/null' EXIT
	test_this
fi

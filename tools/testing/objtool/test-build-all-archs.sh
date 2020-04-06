#!/bin/bash
function setrc()
{
	return $1
}
set -e

if which git > /dev/null 2> /dev/null ; then
	. "$(git --exec-path)/git-sh-setup"
	if SRC_TOP=$(git rev-parse --show-toplevel) ; then
		/bin/true
	else
		SRC_TOP="${GIT_DIR:-$(pwd)}"
	fi
	SRC_TOP="$(readlink -e "${SRC_TOP}")"
	cd "${SRC_TOP}"
else
	SRC_TOP=$(pwd)
fi
export SRC_TOP
echo "SRC_TOP: \"${SRC_TOP}\""

# HACK: Tell git to not interact with the user
export GIT_PAGER=cat
export GIT_EDITOR=""

trap 'RC=$? ; git log -n 1 --pretty=oneline HEAD ; trap '' ERR ; setrc ${RC}' ERR

function __source_path()
{
	realpath -Pe "$1"
}
declare -gfr __source_path

function __source_show_path()
{
	realpath -Pe --relative-base="${SRC_TOP}" "$(__source_path "$1")"
}
declare -gfr __source_show_path

function __source_stat()
{
	stat -L -c '%t:%T:%D:%i:%s:%W:%Y' "$1"
}
declare -gfr __source_stat

##
# Quiet -- completely silences info, warning, debug, and error messages
# Trace -- does not override quiet; shows stack trace after messages
##

# Which output to print
# shellcheck disable=SC2034
declare -gA QUIET=( [DEBUG]=1 ) #[INFO]=1 )

# When to do a script stack dump
# shellcheck disable=SC2034
declare -gA TRACE=( [ERROR]=1 [WARN]=1 )

function dump_stack()
{
	local -i I=1 # don't show dump_stack itself
	local SRC=""
	local -i LNO=""
	local FN=""
	local PFX="	"
	local SFX=""

	if [ $# -gt 0 ]; then
		(( I=I + $1 ))
		shift
	fi

	if [ $# -gt 0 ]; then
		PFX="$1"
		shift
	fi

	if [ $# -gt 0 ]; then
		SFX="$1"
		shift
	fi

	while (( I < ${#FUNCNAME[@]} )); do
		SRC="$(__source_show_path "${BASH_SOURCE[$I]}")"
		LNO=${BASH_LINENO[ $((I - 1)) ]}
		FN="${FUNCNAME[$I]}()"
		echo "${PFX}${SRC}:${LNO}: ${FN}${SFX}" || break
		(( I++ ))
	done
}
declare -gfr dump_stack

function __error()
{
	local SKIP=$(( 0 + $1))
	shift

        if [[ -v 'QUIET[ERROR]' ]]; then return 0; fi
	echo "ERROR:" "$@" >&2
	if [[ -v "TRACE[ERROR]" ]]; then
		dump_stack $(( 1 + SKIP )) "ERROR:"
	fi
}
declare -gfr __error

function error()
{
	__error 1 "$@"
}
declare -gfr error
function errorf()
{
	__error 1 "$(printf "$@")"
}
declare -gfrt errorf

function die()
{
	if [[ -v EMSG ]]; then
		__error 1 "${EMSG}" "$@"
		unset EMSG
	else
		__error 1 "$@"
	fi
        exit 2
}
declare -gfr die
function dief()
{
	die "$(printf "$@")"
}
declare -gfrt dief


function traceme()
{
	if [[ -v 'TRACE['$1']' ]]; then
		dump_stack 2
	fi
}
declare -gfr traceme

function warn()
{
        if [[ -v 'QUIET[WARN]' ]]; then return 0; fi
	echo "WARN: " "$@" >&2
	traceme WARN
}
declare -gfrt warn
function warnf()
{
	warn "$(printf "$@")"
}
declare -gfrt warnf

function info()
{
        if [[ -v 'QUIET[INFO]' ]]; then return 0; fi
	echo "INFO: " "$@" >&2
	traceme INFO
}
declare -gfrt info
function infof()
{
	info "$(printf "$@")"
}
declare -gfrt infof

function debug()
{
        if [[ -v 'QUIET[DEBUG]' ]]; then return 0; fi
	echo "DEBUG: " "$@" >&2
	traceme DEBUG
}
declare -gfrt debug
function debugf()
{
	debug "$(printf "$@")"
}
declare -gfrt debugf

function report_error()
{
	local RC=$1

	if [ -d "${GIT_DIR}" ]; then
		git log -n 1 --pretty=oneline HEAD
	fi
	__error 1 "caught exit code ${RC}"
}

trap 'RC=$? ; report_error ${RC} ; trap '' ERR; setrc ${RC}' ERR

# The set of kernel architectures
#
# TODO endianness and bitsize are likely screwed up below and lack
#	any indication of the correct multiplicity
#
declare -Ag KARCH=(
	[alpha]="big 64"
	[arc]="little 32"
	[arm]="little 32"
	[arm64]="little 64"
	[c6x]="little i"
	[csky]="little i"
	[h8300]="h8300"
	[hexagon]="hexagon"
	[ia64]="little 64"
	[m68k]="big 32"
	[microblaze]="microblaze"
	[mips]="little 64"
	[nds32]="little 32"
	[nios2]="nios2"
	[openrisc]="openrisc"
# TODO takes forever
#	[parisc]="big 32"
	[powerpc]="little 64"
	[riscv]="little 64"
	[s390]="big 64"
	[sh]="little 32"
	[sparc]="big 64"
	# Omit user mode linux (aka um)
	[unicore32]="unicore32"
	[x86]="little 64"
	[xtensa]="xtensa"
)

function map_kconfig_symbol()
{
	local SYM="$1"
	local MAP_NAME="KARCH_${SYM}"

	debug "Defining ${MAP_NAME}"
	declare -Ag "${MAP_NAME}"

	local -n MAP="${MAP_NAME}"

	for A in $(grep -R -E "${SYM}" "arch" | \
			cut -d / -f 2 | sort | uniq) ; do
		MAP["${A}"]="${A}"
	done
	readonly "${MAP_NAME}"
	debug "KARCH_${SYM}: ${!MAP[*]}"
}

##
# Define sets of archs which have certain pertinent features
#
# NOTE: We're assuing these don't change over the course of running this
#	script.
##
# KARCH_HAVE_FUNCTION_TRACER
map_kconfig_symbol HAVE_FUNCTION_TRACER
# KARCH_HAVE_DYNAMIC_FTRACE
map_kconfig_symbol HAVE_DYNAMIC_FTRACE
# KARCH_HAVE_C_RECORDMCOUNT
map_kconfig_symbol HAVE_C_RECORDMCOUNT

##
# Note: A given kernel arch can correspond to multiple archs in
# other "namespaces" so we use a string with space-separated archs
# as our list and this requires dropping quotes when expanding the
# results in order to turn the list into an array.
##

# Note: -linux-* toolchains only; obtained mostly via ls /usr/*-linux-*
declare -Ag KARCH_TO_DEB_TC=(
	[alpha]="alpha-linux-gnu"
	[arm]="arm-linux-gnueabi arm-linux-gnueabihf"
	[arm64]="aarch64-linux-gnu"
	[ia64]="ia64-linux-gnu"
	[m68k]="m68k-linux-gnu"
	[mips]="mips64el-linux-gnuabi64" # mipsel-linux-gnu" # Missing gcc for mips-linux-gnu"
# TODO takes forever
#	[parisc]="hppa-linux-gnu" # hppa64-linux-gnu" # QEMU does not support 64-bit
	[powerpc]="powerpc64le-linux-gnu powerpc64-linux-gnu powerpc-linux-gnu"
	[riscv]="riscv64-linux-gnu"
	[s390]="s390x-linux-gnu"
	[sh]="sh4-linux-gnu"
	[sparc]="sparc64-linux-gnu" # missing sparc-linux-gnu ?
	[x86]="x86_64-linux-gnu i686-linux-gnu" # NOTE: skip (gnu)x32 ABI crap
)

#
# Kernel Arch to QEMU Arch that have a corresponding DEB_TC
#
declare -Ag KARCH_TO_QEMU_ARCH=(
	[alpha]="alpha"
	[arm]="arm arm"
	[arm64]="aarch64"
	[m68k]="m68k"
	[microblaze]="microblazeel microblaze"
	[mips]="mips64el" # mipsel" # missing compiler for mips" # Also  mips64
	[nios2]="nios2"
	[openrisc]="or1k"
# TODO takes forever
#	[parisc]="hppa"
	[powerpc]="ppc64le ppc64 ppc"
	[riscv]="riscv64" # Also riscv32
	[s390]="s390x"
	[sh]="sh4" # Also sh4eb
	[sparc]="sparc64" # sparc" # Also sparc32plus
	[unicore32]="unicore32"
	[x86]="x86_64 i386"
	[xtensa]="xtensa xtensaeb"
)

##
# Store the maximum width the elements in the array name passed via $2
# into the variable with the name passed via $1
##
function elem_width()
{
        local -n W="$1"
        local -n A="$2"

	local RESTORE="$(set +o)"
	trap 'trap "" RETURN ; eval "${RESTORE}"' RETURN
	set +e

        (( W = 0 ))
        for I in "${A[@]}" ; do
                (( W = W < ${#I} ? ${#I} : W ))
        done
}

function key_width()
{
        local -n A="$2"
        local -a K=( "${!A[@]}" )
        elem_width "$1" K
}

function cat_after()
{
	local REGEX="$1"
	shift
	awk 'BEGIN { f = 0; } (f == 1) { print $0 ; next; } (f == 0) && /'"${REGEX}"'/ { f = 1; }' "$@"
}

function cat_before()
{
	local REGEX="$1"
	shift
	awk 'BEGIN { f = 1; } (f == 1) && /'"${REGEX}"'/ { f = 0; } (f == 1) { print $0 ; next; }' "$@"
}

function objtool_has_cmd()
{
	local OT="$1"
	local CMD="$2"

	local RESTORE="$(set +o)"
	trap 'trap "" RETURN ; eval "${RESTORE}"' RETURN
	set -o pipefail
	set +e

	"${OT}" --help | \
		cat_after '^ Commands:$' | \
		cat_before '^ Unavailable commands.*$' | \
		grep -E '^\s*'"${CMD}"'\b.*$' > /dev/null 2> /dev/null
}

function get_karch_from_gen_headers()
{
	local BO="$1"

	head -n 4 "${BO}/include/generated/autoconf.h" | \
	    tail -n 1 | sed -e 's/^ \* Linux\/\(.[^ ]*\) .*$/\1/'
}

##
# Make parameters
##
J=12
TARGETS=( )
if [ -r "${SRC_TOP}/tools/objtool/builtin-mcount.c" ]; then
	TARGETS+=( "tools/objtool" )
else
	TARGETS+=( "scripts" )
fi
LOG_FILE=make.log

function test_obj_cmd_combos()
{
	local CMD="$1"
	local BO="$2"
	shift 2

	for OPT in "" "-w" ; do
		for S in "${BO}/tools/testing/objtool/"*.o ; do
			[ -r "${S}" ]
			"${CMD}" $@ ${OPT} "${S}"
		done
		# TODO test multiple objs on the command line
		#"${CMD}" $@ ${OPT} "${BO}/tools/testing/objtool/"*.o
	done
}

function test_objtool_mcount()
{
	local BO="$1"
	local OT="${BO}/tools/objtool/objtool"

	info "Checking for \"${OT}\""
	[ -x "${OT}" ]

	debug "Trying \"${OT}\" --help"
	"${OT}" --help > /dev/null

	if [ -f "${BO}/../tools/objtool/builtin-mcount.c" ]; then
		objtool_has_cmd "${OT}" mcount
		info "\"${OT}\" has mcount"
	else
		error "\"${OT}\" lacks mcount"
	fi

	test_obj_cmd_combos "${OT}" "${BO}"
}

function test_recordmcount()
{
	local BO="$1"
	local OT="${BO}/scripts/recordmcount"

	[ -x "${OT}" ]
	test_obj_cmd_combos "${OT}" "${BO}"
}

function test_recordmcount_perl()
{
	local BO="$1"
	local OT="${SRC_TOP}/scripts/recordmcount.pl"

	[ -x "${OT}" ]
	local A="$(get_karch_from_gen_headers "${BO}")"
	local ENDIAN="little"
	local BITS=64
	local TOOLCHAIN=""

	TOOLCHAIN="$(basename "${BO}")"
	TOOLCHAIN="${TOOLCHAIN#build-}"
	case "${A}" in
	sparc*|s390*|powerpc|ppc64|ppc|m68k|parisc|alpha)
		ENDIAN="big" ;;
	*) ;;
	esac
	case "${TOOLCHAIN}" in
	[^-]*el-*|[^-]*le-*)
		ENDIAN="little" ;;
	*) ;;
	esac
	case "${TOOLCHAIN}" in
	*64*)	BITS=64 ;;
	*32*|i[3456]86|s390|m68k|mips|mipsel|sparc|armel|armhf|nios2|arc|sh)
		BITS=32 ;;
	esac

	#usage: recordmcount.pl arch endian bits objdump objcopy cc ld nm rm mv is_module inputfile
	test_obj_cmd_combos "${OT}" "${BO}" \
		"${A}" \
		"${ENDIAN}" \
		"${BITS}" \
		"${TOOLCHAIN}-objdump" \
		"${TOOLCHAIN}-objcopy" \
		"${TOOLCHAIN}-gcc" \
		"${TOOLCHAIN}-ld" \
		"${TOOLCHAIN}-nm" \
		rm \
		mv \
		0
}

function test_obj_samples()
{
	local BO="$1"
	local C=0

	if [ -x "${BO}/scripts/recordmcount" ]; then
		test_recordmcount   "${BO}"
		(( C++ ))
	fi
	if [ -x "${BO}/tools/objtool/objtool" ]; then
		test_objtool_mcount "${BO}"
		(( C++ ))
	fi
	if (( C < 1 )); then
		if [ -x "${SRC_TOP}/scripts/recordmcount.pl" ]; then
			test_recordmcount_perl "${BO}"
			(( C++ ))
		fi
	fi
	if (( C < 1 )); then
		return 1
	fi
	return 0
}

# Width of the arch name
key_width WKA KARCH

# Verify that binfmt_misc is set up
grep -F enabled /proc/sys/fs/binfmt_misc/status > /dev/null 2> /dev/null

function binfmt_enabled()
{
	local QA="$1"
	local BFMT="/proc/sys/fs/binfmt_misc/qemu-${QA}"

	local RESTORE="$(set +o)"
	trap 'trap "" RETURN ; eval "${RESTORE}"' RETURN
	set +e

	[ -r "${BFMT}" ] || return 1
	debug "binfmt support for ${QA}"

	return 0

	# TODO check the rest?

	# Enabled and non-empty interpretter
	grep -E '^enabled\ninterpretter [^\s]+$' "${BFMT}" > /dev/null 2> /dev/null || return 1
	debug "binfmt enabled for ${QA}"

	# Interpretter is executable
	local INTERP="$(head -n 2 "${BFMT}" | tail -n 1 | sed -e 's/^interpretter\s*\(.*\)$/\1/')"
	[ -x "${INTERP}" ] || return 1
	debug "binaries for ${QA} are executable"
}

DO_ASK_INSTALL=""

function toolchain_installed()
{
	local TOOLCHAIN="$1"

	if [ '!' -x "$(which "${TOOLCHAIN}-objdump")" ]; then
		PKG_EXISTS=$(apt-cache search "binutils-${TOOLCHAIN}" | wc -l)
		if (( PKG_EXISTS > 0 )) && [ -n "${DO_ASK_INSTALL}" ]; then
			info "Installing binutils for ${TOOLCHAIN}"
			sudo apt-get install "binutils-${TOOLCHAIN}"
		else
			return 1
		fi
	fi
	if [ '!' -x "$(which "${TOOLCHAIN}-gcc")" ]; then
		PKG_EXISTS=$(apt-cache search "gcc-${TOOLCHAIN}" | wc -l )
		if (( PKG_EXISTS > 0 )) && [ -n "${DO_ASK_INSTALL}" ]; then
			info "Installing compiler for ${TOOLCHAIN}"
			sudo apt-get install "gcc-${TOOLCHAIN}"
		else
			return 1
		fi
	fi

	if [ '!' -x "$(which "${TOOLCHAIN}-objdump")"  -o \
	     '!' -x "$(which "${TOOLCHAIN}-gcc")" ]; then
		return 1
	fi

	return 0
}

##
# Install binutils and compiler packages for cross-compilation.
# We reuse the automatic install helping-bits from toolchain_installed
#
# TODO add porcelain to make use of this function
##
function easy_install()
{
	for A in "" "${!KARCH[@]}"; do
		if [ -n "${A}" ]; then
				 # Note lack of quotes
			TOOLCS=( ${KARCH_TO_DEB_TC["${A}"]} ) || continue
		else
			TOOLCS=( "" )
		fi

		for TOOLCHAIN in "${TOOLCS[@]}" ; do
			if toolchain_installed "${TOOLCHAIN}" ; then
				continue
			fi
		done
	done
}

DO_EASY_INSTALL=""
if [ -n "${DO_ASK_INSTALL}" -a -n "${DO_EASY_INSTALL}" ]; then
	easy_install
fi

#
# Filter out those qemu arches we don't have and the kernel archs
# we don't have any qemu -static support registered for.
#
info "Determining host cross compilation support"
for A in "${!KARCH[@]}"; do
	QARCHS=( ${KARCH_TO_QEMU_ARCH[${A}]} ) # note lack of quotes
	TOOLCS=( ${KARCH_TO_DEB_TC[${A}]} ) # note lack of quotes
	for (( I = 0; I < ${#QARCHS[@]}; I++ )) ; do
		QA="${QARCHS[$I]}"
		TOOLCHAIN="${TOOLCS[$I]}"
		if binfmt_enabled "${QA}" ; then
			if [ -n "${TOOLCHAIN}" ]; then
				if toolchain_installed "${TOOLCHAIN}" ; then
					continue
				fi
			fi
		fi
		debug "Cannot test cross-compilation on virtual machine ${QA} with toolchain ${TOOLCHAIN}"
		unset QARCHS[$I]
		unset TOOLCS[$I]
	done


	if (( (${#QARCHS[@]} < 1) || (${#TOOLCS[@]} < 1) )); then
		debug "Cannot test cross-compilation for ARCH=${A}"
		unset KARCH[${A}]
		unset KARCH_TO_QEMU_ARCH[${A}]
		unset KARCH_TO_DEB_TC[${A}]
	else
		if (( ${#QARCHS[@]} != ${#TOOLCS[@]} )); then
			error "SCRIPT BUG: Mapping toolchains ${TOOLCS[*]} to emulators ${QARCHS[*]} failed"
		fi
		KARCH_TO_QEMU_ARCH[${A}]="${QARCHS[*]}"
		KARCH_TO_DEB_TC[${A}]="${TOOLCS[*]}"
		debug "build: ARCH=${A} VMs: ${QARCHS[*]} Toolchains: ${TOOLCS[*]}"
	fi
done

#
# NOTE: The host architecture and default toolchain are specified as empty
#	strings for A, and TOOLCHAIN
#
for A in "" "${!KARCH[@]}"; do
	if [ -n "${A}" ]; then
			 # Note lack of quotes
		TOOLCS=( ${KARCH_TO_DEB_TC["${A}"]} ) || continue
	else
		TOOLCS=( "" )
	fi

	# TODO test all toolchains
	#for TOOLCHAIN in "${TOOLCS[@]}" ; do
	# Currently we skip most and just use the "highest priority" aka first
	for TOOLCHAIN in "${TOOLCS[0]}" ; do
		if [ -n "${A}" ]; then
			OA="ARCH=${A}"
			if [ -z "${TOOLCHAIN}" ]; then
				continue
			fi
			BO="${SRC_TOP}/build-${TOOLCHAIN}"
			OXC="CROSS_COMPILE=${TOOLCHAIN}-"
		else
			OA=""
			if [ -n "${TOOLCHAIN}" ]; then
				continue
			fi
			# Build on host for host
			BO="${SRC_TOP}/build"
			OXC=""
		fi
		OBO="O=${BO}"

		mkdir -p "${BO}"
		if [ -n "${LOG_FILE}" ]; then
			BLOG="${BO}/${LOG_FILE}"
		fi
		LOG="${BLOG:-/dev/null}"

		MAKE=( "make" ${OBO} ${OA} ${OXC} )
		infof 'Arch: %-*s  Toolchain: "%s"\n' "${WKA}" "${A:-HOST}" "${TOOLCHAIN}"

		# Ensure the kernel has a base .config
		if "${MAKE[@]}" "defconfig" > "${LOG}" 2>&1 ; then
			/bin/true
		else
			RC=$?
			if [ -f "${LOG}" -a -r "${LOG}" ]; then
				cat "${LOG}"
			fi
			setrc ${RC}
			error "Failed to configure ${OA} ${OXC} with defaults"
		fi
		A="$(get_karch_from_gen_headers "${BO}")"
		debug "Extracted ARCH=${A} from kernel config"

		# Edit the .config for our testing purposes
		CFG_EDITS=()
		if [ -n "${KARCH_HAVE_FUNCTION_TRACER[${A}]}" ]; then
			CFG_EDITS+=( \
				-e "FTRACE" \
				-e "FUNCTION_TRACER" \
			)
		fi
		if [ -n "${KARCH_HAVE_DYNAMIC_FTRACE[${A}]}" ]; then
			CFG_EDITS+=( \
				-e "DYNAMIC_FTRACE" \
			)
		fi
		if [ -n "${KARCH_HAVE_C_RECORDMCOUNT[${A}]}" ]; then
			CFG_EDITS+=( \
				-e "FTRACE_MCOUNT_RECORD" \
				-d "HAVE_NOP_MCOUNT" \
				-d "HAVE_FENTRY" \
			)
		fi

		if (( ${#CFG_EDITS[@]} > 0 )); then
		if "${SRC_TOP}/scripts/config" --file "${BO}/.config" \
			"${CFG_EDITS[@]}" ; then
			/bin/true
		else
			error "Failed to configure ARCH=${A} ${OXC}"
		fi

		# Fix up any config blunders
		if "${MAKE[@]}" olddefconfig > "${LOG}" 2>&1 ; then
			/bin/true
		else
			RC=$?
			if [ -f "${LOG}" -a -r "${LOG}" ]; then
				cat "${LOG}"
			fi
			setrc ${RC}
			error "Failed to build ARCH=${A} ${OXC}"
		fi
		fi # One or more CFG_EDITS

		# Build our artifacts to test
		if "${MAKE[@]}" "-j${J}" "${TARGETS[@]}" > "${LOG}" 2>&1 ; then
			/bin/true
		else
			RC=$?
			if [ -f "${LOG}" -a -r "${LOG}" ]; then
				cat "${LOG}"
			fi
			setrc ${RC}
			error "Failed to build ARCH=${A} ${OXC}"
		fi

		# Build our sample input
		info "Building foo.o"
		mkdir -p "${BO}/tools/testing/objtool"
		"${TOOLCHAIN:+${TOOLCHAIN}-}gcc" -Wall -g -c "tools/testing/objtool/foo.c" -o "${BO}/tools/testing/objtool/foo.o" >> "${LOG}" 2>&1

		# Use the test artifacts to process the sample input
		test_obj_samples "${BO}"
	done
done

exit $?

#!/bin/bash
set -e

SRC_TOP="$(readlink -f "$(git rev-parse --show-cdup)")"
OBJ_TOP="${SRC_TOP}"
CFG_PATH="${SRC_TOP}/.config"

function extract_vmlinux()
{
	"${SRC_TOP}/scripts/extract-vmlinux" "$@"
}

function extract_mcount()
{
	# TODO might want to normalize the comparison a bit
	# TODO this is a bit of a hack -- we compare all .tracedata
	#	which we assume is mostly the same as "__mcount_loc" data.
#	local ARCH="${1-=x86_64}"
	local OBJ="${OBJ_TOP}/vmlinux.o"
#	extract_vmlinux "${OBJ_TOP}/arch/${ARCH}/boot/bzImage" > .vmlinux.mcount
#	readelf -x .tracedata .vmlinux.mcount
	readelf -x __mcount_loc "${OBJ}"
	readelf -x .rela__mcount_loc "${OBJ}"

#	rm -f .vmlinux.mcount
#	objdump -j text.__mcount_loc -s "${OBJ}"
# readelf -a ${OBJ_TOP}/vmlinux
# Relocation section '.rela.orc_unwind_ip' at offset 0x16b9d2e0 contains 476478 entries:
#  Offset          Info           Type           Sym. Value    Sym. Name + Addend
#ffffffff82ef767f  19cbd0000000b R_X86_64_32S      ffffffff8307c790 __stop_mcount_loc + 0
#ffffffff82ef7689  1cabe0000000b R_X86_64_32S      ffffffff8301cd98 __start_mcount_loc + 0
#ffffffff82ef76c2  1cabe0000000b R_X86_64_32S      ffffffff8301cd98 __start_mcount_loc + 0

}

function diff_mcount()
{

	if [ '!' -f ".mcount.orig" ]; then
		extract_mcount > .mcount.orig
	fi
	extract_mcount | diff -spu .mcount.orig -
}

function change_config()
{
	local CHANGE="$1"

	CFG_NAME=$(echo -n "$CHANGE" | sed -e 's/^\([^=]\+\)=.*$/\1/g')
	CFG_VALUE=$(echo -n "$CHANGE" | sed -e 's/^[^=]\+=\(.*\)$/\1/g')

	if [ -z "${CFG_VALUE}" ] || [ "${CFG_VALUE}" == "n" ]; then
		CHANGE='# '"${CFG_NAME}"' is not set'
	fi
	grep -E '\b'"${CFG_NAME}"'[\s=]' "${CFG_PATH}" > /dev/null && { \
		sed -e 's/^\s*#\s*\('"${CFG_NAME}"'\)\sis not set.*$/'"${CHANGE}"'/' "${CFG_PATH}" | \
		sed -e 's/^\s*'"${CFG_NAME}"'=.*$/'"${CHANGE}"'/' > "${CFG_PATH}.new"
		set -x
		diff -q "${CFG_PATH}" "${CFG_PATH}.new" || \
		mv "${CFG_PATH}.new" "${CFG_PATH}"
		set +x
	} || {
		echo -e '\n'"${CHANGE}"'\n' >> "${CFG_PATH}"
	}

	pushd "${SRC_TOP}" && {
		make O=${OBJ_TOP} oldconfig || {
			RC=$?
			popd
			return $RC
		}
		popd
	}
}

# Backup config
cp "${CFG_PATH}" "${CFG_PATH}.test-mcount.bak"
trap 'mv "${CFG_PATH}.test-mcount.bak" "${CFG_PATH}"' EXIT

function iterate()
{
	while read CHANGE ; do
		change_config "${CHANGE}"

		pushd "${SRC_TOP}"
		make O=${OBJ_TOP} -j6 bzImage || {
			RC=$?
			popd
			exit $RC
		}
		popd

		diff_mcount
	done
	rm -f .mcount*
}

##
# Generate changes for the config vars below and pipe them into our loop
#
# NOTE: The CONFIG_HAVE_ variables are only safe to include below when
#       we're not doing a crosscompile and they are y on the host.
##
${OBJ_TOP}/tools/testing/objtool/config-sample - <<-EOF | iterate
CONFIG_HAVE_C_RECORDMCOUNT
EOF

#CONFIG_DYNAMIC_FTRACE
#CONFIG_FUNCTION_TRACER
#CONFIG_FTRACE_MCOUNT_RECORD
#CONFIG_HAVE_FTRACE_MCOUNT_RECORD
#CONFIG_HAVE_C_RECORDMCOUNT
#CONFIG_HAVE_FENTRY

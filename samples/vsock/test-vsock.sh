#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

VSPOKE=./vspoke
if [ '!' -x "${VSPOKE}" ]; then
	VSPOKE=$(command -v vspoke)
fi

# TODO figure out which kind of node we're running on 
HOST="baremetal"
#HOST="guest"
#HOST="intermediate"
VSPOKEARGS=( )

case "${HOST}" in
baremetal)
	VSPOKEARGS+=( --client --stream )
	coproc SCRIPT { cat - <<-EOFOEOF
		echo hello
		set flow datagram
		reset
		echo world
		exit
		# TODO
		set flow stream
		set endpoint client
		set dest
		reset
		EOFOEOF
	}
	# TODO 
	expect hello
	expect world
	# TODO
	;;
intermediate)
	VSPOKEARGS+=( --server --stream )
	coproc SCRIPT { cat - <<-EOFOEOF
		EOFOEOF
	}
	;;
guest)
	VSPOKEARGS+=( --server --stream )
	coproc SCRIPT { cat - <<-EOFOEOF
		EOFOEOF
	}
	;;
esac


cat - <&${SCRIPT[0]}- | "${VSPOKE}" "${VSPOKEARGS[@]}"

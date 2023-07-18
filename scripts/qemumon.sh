#!/usr/bin/env bash

set -euo pipefail

function run_cmd {
  echo "$1" | \
    sudo socat - unix-connect:qemu-monitor-socket | \
    { grep -Ev '^(\(qemu\)|QEMU)' || test $? = 1; }
}


while (("$#")); do
	case "$1" in
	-i | --interactive)
		# Start an interactive session with the QEMU VM monitor
		sudo socat \
		  -,echo=0,icanon=0 unix-connect:qemu-monitor-socket
		exit 0
		;;
	--status)
		# Get VM status
		run_cmd "info status"
		exit 0
		;;
	--dump)
		DUMPDIR="/mnt/LinuxMemoryForensics/dumps"
	  	# Dump guest memory to file
		if [[ ! -d ${DUMPDIR} ]] || [[ $# < 2 ]]
		then
		  echo "Dump folder mounted? Name specified?"
		  exit 1
		fi
		run_cmd "stop"
		run_cmd "dump-guest-memory ./dumps/$2"
		echo -n "Wait for QEMU "
		for i in `seq 1 5`;
		do
		  sleep 1
		  echo -n "."
		done
		echo "done?"
		run_cmd "cont"
		sudo chmod 666 "./dumps/$2"
		mv "./dumps/$2" "${DUMPDIR}/$2"
		exit 0
		;;
	-d | --debug)
		# Enable debug output
		set -euxo pipefail
		shift 1
		;;
	-*)
		echo "Error: Unknown option: $1" >&2
		exit 1
		;;
	*) # No more options
		break
		;;
	esac
done

exit 0

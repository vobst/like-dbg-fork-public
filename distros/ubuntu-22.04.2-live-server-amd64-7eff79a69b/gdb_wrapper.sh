#!/usr/bin/env bash

# Wrapper around scripts/gdb.sh for a particular distro VM:
# ubuntu-22.04.2-live-server-amd64-7eff79a69b

set -euo pipefail

if [[ $# -eq 1 ]]
then
  GDB_SCRIPT="$1"
else
  GDB_SCRIPT=../../io/scripts/gdb_script_dummy.py
fi

$LIKE_ROOT/scripts/gdb.sh 					\
  -a x86_64 							\
  -l debug_root/usr/lib/debug/boot/vmlinux-5.15.0-76-generic 	\
  -k kernel_root 						\
  -d debug_root 						\
  -g $GDB_SCRIPT			 			\
  -i $LIKE_ROOT/configs/gdbinit 				\
  -kd debug_root/usr/share/gdb/auto-load/boot/vmlinux-5.15.0-76-generic/vmlinuz-5.15.0-76-generic-gdb.py \
  -sp /build/linux-xHju8f/linux-5.15.0

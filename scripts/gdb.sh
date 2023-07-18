#!/usr/bin/env bash

set -xeuo pipefail

function usage {
  echo "Usage:"
  echo "-a | --arch"
  echo "-l | --vmlinux"
  echo "-k | --kernel-root"
  echo "-sp | --substitute-path"
  echo "-d | --debug-root"
  echo "-g | --gdb_script"
  echo "-kd | --kernel_gdb_script"
  echo "-i | --gdb_init"
  echo "-* | -h"
}

while (("$#")); do
    case "$1" in
        -a | --arch)
            # Sets the architecture as expected in GDB
            ARCH=$2
            shift 2
            ;;
        -l | --vmlinux)
            # vmlinux with debug symbols
            VMLINUX=$2
            shift 2
            ;;
        -k | --kernel-root)
            # kernel root directory
            KERNEL_ROOT=$2
            shift 2
            ;;
        -sp | --substitute-path)
            # change hard-coded references to source files in debug info
            SUB_PATH=$2
            shift 2
            ;;
        -d | --debug-root)
            # debug info root directory
            DEBUG_ROOT=$2
            shift 2
            ;;
        -g | --gdb_script)
            # Sets the location of the user defined GDB script
            GDB_SCRIPT=$2
            shift 2
            ;;
        -kd | --kernel_gdb_script)
            # Sets the location of the user defined GDB script
            KERNEL_GDB_SCRIPT=$2
            shift 2
            ;;
        -i | --gdb_init)
            # Sets the location of the user defined GDB script
            GDB_INIT=$2
            shift 2
            ;;
        -* | -h)
	    usage
            exit 1
            ;;
        *) # No more options
            break
            ;;
    esac
done

if [ -z "$KERNEL_ROOT" ] || \
  [ -z "$DEBUG_ROOT" ] || \
  [ -z "$VMLINUX" ] || \
  [ -z "$ARCH" ] || \
  [ -z "$GDB_INIT" ] || \
  [ -z "$GDB_SCRIPT" ]; then
    echo "[!] Not all required arguments were set"
    usage
    exit 255
fi

# create vmlinux to make kernel gdb scripts happy
ln -fsv $VMLINUX vmlinux

# handle GDB naming sceme
case "$ARCH" in
    arm64)
        ARCH=aarch64
        ;;
    arm)
        ARCH=armv7
        ;;
    x86_64)
        ARCH=i386:x86-64:intel
        ;;
    *) ;;
esac

sudo -E gdb-multiarch \
    -q "$VMLINUX" \
    -x "$GDB_INIT" \
    -iex "set architecture $ARCH" \
    -ex "gef-remote --qemu-user --qemu-binary $VMLINUX 127.0.0.1 1234" \
    -ex "directory $KERNEL_ROOT" \
    -ex "set substitute-path $SUB_PATH /" \
    -ex "add-auto-load-safe-path $DEBUG_ROOT/usr/share/gdb/auto-load/" \
    -ex "add-auto-load-safe-path $KERNEL_ROOT" \
    -ex "set debug-file-directory $DEBUG_ROOT/usr/lib/debug/" \
    -ex "add-symbol-file $VMLINUX" \
    -ex "source $KERNEL_GDB_SCRIPT" \
    -ex "source $LIKE_ROOT/io/scripts/pt-dump/pt.py" \
    -ex "lx-symbols" \
    -ex "macro define offsetof(_type, _memb) ((long)(&((_type *)0)->_memb))" \
    -ex "macro define containerof(_ptr, _type, _memb) ((_type *)((void *)(_ptr) - offsetof(_type, _memb)))" \
    -x "$GDB_SCRIPT"

#!/usr/bin/env bash

set -xue

if [[ $# -ne 1 ]]
then
  echo "Add a new vm from an ISO"
  echo "Usage: $0 /path/to/iso"
fi

ISO="$1"
HASH="$(cat $ISO | head -c 1000 | md5sum | rg '^(.*?) ' -o -r '$1' | head -c 10)"
NAME=$(basename $ISO)
NAME="${NAME%.*}-$HASH"

VMHOME="$LIKE_ROOT/distros/$NAME"
mkdir -p $VMHOME

sudo virt-install 							\
  --connect qemu:///system 					\
  --disk path=$VMHOME/$NAME.qcow2,size=20,sparse=yes,format=qcow2 \
  --memory 8192 						\
  --osinfo detect=on,require=off 				\
  --name $NAME 							\
  --cdrom $ISO

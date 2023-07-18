#!/usr/bin/env bash

set -exuo pipefail

KERNDIR="/mnt/LinuxMemoryForensics/kernels"

if [[ $# != 1 ]]
then
  echo "Adds a self-compiled kernel to my archive."
  echo "Usage: $0 <path/to/vmlinux>"
  echo "Example: $0 kernel_root/linux-6.2.6_x86_64_playground/vmlinux"
  exit 1
fi

# label image by hash of build container
filepath="${1}"
chash=`strings "${filepath}" | rg 'user@(.*?)\) ' -o -r '$1' | head -n 1`
filename="vmlinux-${chash}"

for section in ".BTF" "__ksymtab_strings" "__ksymtab" "__ksymtab_gpl"
do
  if [[ -z $(readelf --sections "${filepath}" | rg "${section}") ]]
  then
    # old kernels might not have BTF
    continue
  fi
  llvm-objcopy --dump-section=${section}=- "${filepath}" > \
    "${KERNDIR}/${filename}.${section}"
  h=`md5sum "${KERNDIR}/${filename}.${section}" | rg '^([0-9a-f]+) .*?$' -o -r '$1'`
  mv "${KERNDIR}/${filename}.${section}" \
    "${KERNDIR}/${filename}.${section}.$h"
done

cp "${filepath}" "${KERNDIR}/${filename}"

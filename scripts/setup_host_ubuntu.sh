#!/usr/bin/env bash

# prepares a distro directory for an Ubuntu guest
# run from VM home

# get kernel source code
mkdir -p kernel_root
ssh libvirt 							\
  'find /root -maxdepth 1 -type d -name "linux*" | xargs tar cz -O' \
  | tar zxf - --strip-components=2 -C kernel_root

# get debug symbols
mkdir -p debug_root
scp libvirt:'/root/linux-image-unsigned-*' . 			\
  && dpkg-deb -x linux-image-unsigned-*.ddeb debug_root

# clean up
rm linux-image-unsigned-*.ddeb
ssh libvirt 'rm -rf /root/linux*'

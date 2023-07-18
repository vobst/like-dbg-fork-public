#!/usr/bin/env bash

# run as root inside the guest
# - prepares VM for kernel debugging
# - downloads kernel source code and debug symbols

set -x

# delete root password
passwd -d root
echo "PermitEmptyPasswords yes" >> /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/g' \
  /etc/ssh/sshd_config

# start sshd
systemctl enable sshd
systemctl start sshd
systemctl restart sshd

# without keys update of index does not work with debug repository
apt update
apt install 			\
  ubuntu-dbgsym-keyring 	\
  dpkg-dev			\
  apt-rdepends

# uncomment source repositories
sed -E -i 's/^# deb/deb/g' /etc/apt/sources.list

# add debug repositories
echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-proposed main restricted universe multiverse" \
  | sudo tee -a /etc/apt/sources.list.d/ddebs.list

# refresh package index
apt update

# kernel debugging is better without ASLR
echo 'GRUB_CMDLINE_LINUX="nokaslr"' >> /etc/default/grub
update-grub

# get kernel sources (creates e.g. ./linux-5.15.0/"
apt source linux

# get kernel debug symbols (creates e.g.
# ./linux-image-unsigned-5.15.0-76-generic-dbgsym_5.15.0-76.83_amd64.ddeb)
TMP="$(apt-rdepends linux-image-`uname -r`-dbgsym 2>/dev/null | tail -n 1)"
apt download $TMP

exit 0

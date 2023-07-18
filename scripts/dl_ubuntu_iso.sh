#!/usr/bin/env bash

set -xueo pipefail

if [[ $# -ne 1 ]]
then
  echo "Download an Ubuntu server ISO"
  echo "Usage: $0 MMNP ARCH"
fi

BASE_URL=https://mirror.level66.network/ubuntu-releases
MMNP="$1"
ARCH="$2"

curl "$BASE_URL/$MMNP/ubuntu-${MMNP}-live-server-${ARCH}.iso"	\
  -o /tmp/"ubuntu-${MMNP}-live-server-${ARCH}.iso"

Public release of a pile of scripts I use for Linux debugging.
Intended to allow readers to reproduce my blog post on the Corjail
CTF challenge [[]()].

## Getting Started
Follow those steps to set up the debugging environment used in the blog
post.
1. install Docker
2. install Python dependencies
  - if the first command fails you might have to install Python virtual
  environments first
```
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```
3. download the archive containing the kernel root and the challenge
filesystem
[[](https://drive.proton.me/urls/8B8N7FJJZG#FOrmMUp2x0RW)],
move the zip file to the project's root and unzip it
4. create an ssh key
```
mkdir .ssh
ssh-keygen -f "./ssh/lkd.id_rsa" -t rsa -N ""
```
5. enter a tmux session and start the VM with the debugger attached
  - first startup will be slow as some containers must be build
```
tmux
./start_kgdb.py --verbose
```

## Usage

You can download the exploit's source code from its public
repository [[](https://github.com/vobst/ctf-corjail-public)].
Some things you might find useful when experimenting
with the exploit yourself:
- Select the gdb script with the `gdb_script` setting in
`./configs/user.ini`. You might want to switch between the one for
debugging the exploit and the one for experimenting with different
privilege escalation methods. There is also an empty gdb script for
interactive debugging. The scripts themselves are located under `io/scripts`.
- Change the variant of the exploit to debug by toggling the
`RW_VARIANT` attribute of the `Session` class. In general, always adapt
those attributes when making changes to the exploit's `config.h`.
- In case you wonder how to get the exploit into the VM, start a local
http server in the host and use curl in the guest.
- Run `/usr/local/bin/jail` to launch an unprivileged shell to escape
from.

## Undocumented Stuff

Some other things this project can do for you if you don't mind piecing
it together yourself be digging through this pile of scripts:
- semi-automated setup of VMs with distro releases for kernel debugging
(source code, symbols, scripts, ... all the good stuff), running on
QMEMU/KVM+libvirt
  - Ubuntu server
- creating memory dumps of guest
- convenient interaction with QEMU monitor
- capturing network traffic of guest
- building and debugging kernel modules for guest
- configuring, building, running and debugging mainline kernels at
arbitrary commits or tags
  - applying patches directly from the mailing list
  - applying general patches
- automate debugging with gdb using scripts
  - small library of gdb scripts with some useful exploit dev features
  - integration of third party gdb scripts
- configure, patch, and build your own QEMU
- ... and probably some stuff I am forgetting right now

## Shoutouts
We all stand on the shoulders of giants, this pile of scripts would
not exist without:
- [like-dbg](https://github.com/0xricksanchez/like-dbg)

### Other Great Projects
- [pt-dump](https://github.com/martinradev/gdb-pt-dump)
- [libslub](https://github.com/nccgroup/libslub)
- [linux-kernel-debugging](https://github.com/martinclauss/linux-kernel-debugging)
- [salt](https://github.com/PaoloMonti42/salt)

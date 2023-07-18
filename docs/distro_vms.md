## Setup distro VM
- download the ISO, e.g.,
```
$LIKE_ROOT/scripts/dl_ubuntu_iso.sh 22.04.2 amd64
```
- install the VM
```
$LIKE_ROOT/scripts/virt_install.sh /tmp/ubuntu-22.04.2-live-server-amd64.iso
```
- eject the install medium
```
change-media <domain> /path/to/iso --eject
```
- enable the qemu gdb stub, edit the domain and add the following
xml object
```
<commandline xmlns="http://libvirt.org/schemas/domain/qemu/1.0">
    <arg value='-s'/>
</commandline>
```
- run the guest setup script (in the guest) as root, e.g.,
```
$LIKE_ROOT/scripts/setup_guest_ubuntu.sh
```
- run the host setup script (on the host) from the VM home
```
cd $LIKE_ROOT/distros/ubuntu-22.04.2-live-server-amd64-7eff79a69b
$LIKE_ROOT/scripts/setup_host_ubuntu.sh
```
- create a wrapper for
```
$LIKE_ROOT/scripts/gdb.sh
```
that sets some distro specific switches
- enjoy kernel debugging for a distro VM ;)

### Misc stuff
- remove a domain
```
undefine <domain> \
--remove-all-storage \
--snapshots-metadata \
--checkpoints-metadata \
--nvram
```

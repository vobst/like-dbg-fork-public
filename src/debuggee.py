#!/usr/bin/env python3

import subprocess as sp
from pathlib import Path

from loguru import logger

from .docker_runner import DockerRunner
from .misc import adjust_qemu_arch, cfg_setter, tmux, tmux_shell


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | DEBUGGEE                                                                                            |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class Debuggee(DockerRunner):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        user_cfg = kwargs.get("user_cfg", "")
        cfg_setter(
            self,
            [
                "general",
                "debuggee",
                "debuggee_docker",
                "rootfs_general",
            ],
            user_cfg,
            exclude_keys=["kernel_root"],
        )
        if self.ctf:
            self.ctf_mount = kwargs.get("ctf_mount")
            self.kernel = Path(self.docker_mnt) / kwargs.get(
                "ctf_kernel", ""
            )
            self.rootfs = Path(self.docker_mnt) / kwargs.get(
                "ctf_fs", ""
            )
        else:
            if self.alt_kern:
                self.kernel = Path(self.docker_mnt) / self.alt_kern
                logger.info(f"Using alt kernel: {self.kernel}")
            else:
                self.kernel = (
                    Path(self.docker_mnt)
                    / self.kernel_root
                    / "arch"
                    / self.arch
                    / "boot"
                    / "Image"
                )
                logger.info(f"Using kernel: {self.kernel}")
            if self.alt_rootfs:
                self.rootfs = Path(self.docker_mnt) / self.alt_rootfs
                logger.info(f"Using alt rootfs: {self.rootfs}")
            else:
                self.rootfs = (
                    Path(self.docker_mnt)
                    / self.rootfs_dir
                    / (self.rootfs_base + self.arch + self.rootfs_ftype)
                )
                logger.info(f"Using rootfs: {self.rootfs}")
        self.qemu_arch = adjust_qemu_arch(self.arch)
        self.cmd = None

    def run(self):
        super().run(check_existing=True)

    def infer_qemu_fs_mount(self) -> str:
        r = self.rootfs if self.ctf else Path(*self.rootfs.parts[2:])
        magic = sp.run(f"file {r}", shell=True, capture_output=True)
        rootfs = self.rootfs.name if self.ctf else self.rootfs
        if b"cpio archive" in magic.stdout:
            return f" -initrd {rootfs}"
        elif b"filesystem data" in magic.stdout:
            return f" -drive file={rootfs},format=raw"
        elif b"QCOW" in magic.stdout:
            return f" -drive file={rootfs},format=qcow2"
        else:
            logger.error(f"Unsupported rootfs type: {magic.stdout}")
            exit(-1)

    def infer_panic_behavior(self) -> int:
        if self.panic == "reboot":
            return -1
        elif self.panic == "halt":
            return 0
        elif "wait" in self.panic:
            try:
                ret = int(self.panic.split(" ")[1])
                return ret
            except (IndexError, ValueError):
                return 15
        else:
            logger.error("Unknown requested panic behavior...")
            exit(-1)

    def _add_smep_smap(self) -> None:
        if self.smep:
            self.cmd += ",+smep"
        if self.smap:
            self.cmd += ",+smap"

    def run_container(self):
        container_name: str = "lkd_debuggee"
        image_name: str = f"{self.tag}"
        mount_point = self.ctf_mount if self.ctf else Path.cwd()
        kernel = (
            Path(self.docker_mnt) / self.kernel.name
            if self.ctf
            else self.kernel
        )
        dcmd = (
            f"docker run --privileged -it --rm "
            f"--name {container_name} "
            f"-v {mount_point}:/io "
            f"-p 127.0.0.1:10021:10021 -p 127.0.0.1:1234:1234 "
            f"-p 127.0.0.1:4444:4444 "
            f"{image_name} "
        )
        qemu = (
            self.qemu_bin
            if self.qemu_bin
            else f"qemu-system-{self.qemu_arch}"
        )
        self.cmd = (
            f"{qemu} -m {self.memory} -smp {self.smp} -kernel {kernel}"
        )
        if self.monitorsocket:
            logger.info(
                f"Creating QEMU monitor socket {self.monitorsocket=}"
            )
            self.cmd += (
                " -monitor unix:/io/qemu-monitor-socket,server,nowait"
            )
        else:
            logger.info(
                f"Not creating QEMU monitor socket {self.monitorsocket=}"
            )
        if self.vmcoreinfo:
            logger.info(
                "Adding device vmcoreinfo for better core dumps"
            )
            self.cmd += " -device vmcoreinfo"
        else:
            logger.info(
                "Not adding device vmcoreinfo for better core dumps"
            )
        if self.qemu_arch == "aarch64":
            self.cmd += " -cpu cortex-a72"
            self.cmd += ' -machine type=virt -append "console=ttyAMA0 root=/dev/vda'
        elif self.qemu_arch == "x86_64":
            self.cmd += " -cpu qemu64,+rdrand"
            self._add_smep_smap()
            self.cmd += ' -append "console=ttyS0 root=/dev/sda rw'
        else:
            logger.error(f"Unsupported architecture: {self.qemu_arch}")
            exit(-1)
        self.cmd += " earlyprintk=serial net.ifnames=0"
        if not self.kaslr:
            self.cmd += " nokaslr"
        else:
            self.cmd += " kaslr"
        if not self.smep:
            self.cmd += " nosmep"
        if not self.smap:
            self.cmd += " nosmap"
        if not self.kpti:
            self.cmd += " nopti"
        else:
            self.cmd += " pti=on"
        if self.lsm:
            self.cmd += f" lsm={self.lsm}"
        self.cmd += f' oops=panic panic={self.infer_panic_behavior()}"'
        self.cmd += self.infer_qemu_fs_mount()
        self.cmd += " -net user,id=u1,host=10.0.2.10,hostfwd=tcp::10021-:22,hostfwd=tcp::4444-:4444 -net nic,model=e1000 -nographic -pidfile vm.pid"
        if self.pcap:
            logger.info(f"Capturing guest traffic to pcap/vm.pcap")
            self.cmd += " -object filter-dump,id=f1,netdev=u1,file=/io/pcap/vm.dat"
        if self.kvm and self.qemu_arch == "x86_64":
            self.cmd += " -enable-kvm"
        if self.gdb:
            self.cmd += " -S -s"
        tmux("selectp -t 1")
        runner = f"{dcmd} {self.cmd}"
        tmux_shell(runner)

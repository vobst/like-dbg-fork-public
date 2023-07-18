#!/usr/bin/env python3

import subprocess as sp
from glob import glob
from pathlib import Path

from loguru import logger

from .docker_runner import DockerRunner
from .misc import (
    cfg_setter,
    get_sha256_from_file,
    new_context,
    tmux,
    tmux_shell,
)

GDB_SCRIPT_HIST = Path(".gdb_hist")


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | DEBUGGER                                                                                            |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class Debugger(DockerRunner):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        user_cfg = kwargs.get("user_cfg", "")
        cfg_setter(
            self,
            ["general", "debugger"],
            user_cfg,
            exclude_keys=["kernel_root"],
        )
        if kwargs.get("ctf_ctx", False):
            self.ctf = True
            self._set_ctf_ctx(kwargs)
        else:
            self.ctf = False
            self.project_dir = Path.cwd() / self.kernel_root
        self.custom_gdb_script = Path(
            f"/root/scripts/{self.gdb_script}"
        )
        self.script_logging = (
            "set -e"
            if kwargs.get("log_level", "INFO") == "INFO"
            else "set -eux"
        )
        self.skip_prompts = kwargs.get("skip_prompts", False)

    def _set_ctf_ctx(self, kwargs) -> None:
        self.ctf_kernel = Path(kwargs.get("ctf_kernel", ""))
        self.project_dir = Path(self.ctf_dir).resolve().absolute()
        vmlinux = Path(self.project_dir) / "vmlinux"
        if (
            not vmlinux.exists()
            or b"ELF"
            not in sp.run(
                f"file {vmlinux}", shell=True, capture_output=True
            ).stdout
        ):
            if self._extract_vmlinux():
                exit(-1)

    def _extract_vmlinux(self) -> int:
        vml_ext = (
            Path(glob("**/extract-vmlinux.sh", recursive=True)[0])
            .resolve()
            .absolute()
        )
        pkernel = self.ctf_kernel.resolve().absolute()
        with new_context(self.ctf_dir):
            cmd = f"{vml_ext} {pkernel} > vmlinux"
            ret = sp.run(f"{cmd}", shell=True, capture_output=True)
            if ret.returncode == 0:
                logger.info(
                    "Successfully extracted 'vmlinux' from compressed kernel"
                )
                return 0
            else:
                logger.error("Failed to extract 'vmlinux'")
                return 1

    def run_container(self) -> None:
        container_name: str = "lkd_debugger"
        debuggee_container_name: str = "lkd_debuggee"
        image_name: str = f"{self.tag}"

        entrypoint = (
            f'/bin/bash -c "{self.script_logging}; '
            f'. /root/scripts/debugger.sh '
            f'-a {self.arch} -p {self.docker_mnt} -c {int(self.ctf)} '
            f'-g {self.custom_gdb_script}"'
        )

        runner = (
            f"docker run -it --rm "
            f"--name {container_name} "
            f"--security-opt seccomp=unconfined --cap-add=SYS_PTRACE "
            f"-v {self.project_dir}/../../io/scripts/:/root/scripts "
            f"-v {self.project_dir}:/io "
            f"--pid=container:{debuggee_container_name} "
            f"--net=container:{debuggee_container_name} "
            f"{image_name} {entrypoint}"
        )

        tmux("selectp -t 2")
        tmux_shell(runner)

    @staticmethod
    def _is_gdb_script_hist() -> bool:
        return GDB_SCRIPT_HIST.exists()

    def run(self) -> None:
        super().run(check_existing=True)

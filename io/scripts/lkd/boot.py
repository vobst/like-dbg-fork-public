import gdb

# randomization dome with PUD granularity
PUD_SHIFT: int = 30
PUD_SIZE: int = 1 << PUD_SHIFT
PUD_MASK: int = ~(PUD_SIZE - 1) & 0xFFFFFFFFFFFFFFFF

unrandomized_vmemmap_base: int = 0
unrandomized_page_offset_base: int = 0
unrandomized_vmalloc_base: int = 0
unrandomized_startup_64: int = 0

randomized_vmemmap_base: int = 0
randomized_page_offset_base: int = 0
randomized_vmalloc_base: int = 0
randomized_startup_64: int = 0


class KernelRandomizeMemoryBP(gdb.Breakpoint):
    def stop(self) -> bool:
        global unrandomized_vmalloc_base
        global unrandomized_page_offset_base
        global unrandomized_startup_64
        global unrandomized_vmemmap_base

        # pretend that kaslr is on, even though we booted with nokaslr
        # this randomizes vmmemap_base, page_offset_base, vmalloc_base
        # but not kernel_base, i.e., we can test that our exploit
        # does not depend on disabled randomization and still debug properly :)
        gdb.execute("set boot_params.hdr.loadflags |= 2")

        unrandomized_vmemmap_base = int(
            gdb.parse_and_eval("vmemmap_base")
        )
        unrandomized_page_offset_base = int(
            gdb.parse_and_eval("page_offset_base")
        )
        unrandomized_vmalloc_base = int(
            gdb.parse_and_eval("vmalloc_base")
        )
        unrandomized_startup_64 = int(gdb.parse_and_eval("&startup_64"))

        return True


class StartKernelBP(gdb.Breakpoint):
    def stop(self) -> bool:
        gdb.execute("lx-symbols")

        return True


def boot_into_paritalASLR() -> None:
    """
    Boot into a state where ther kernel image is not randomized,
    but other regiond like vmemmap, vmalloc, and the direct map
    are.
    """
    global randomized_vmalloc_base
    global randomized_page_offset_base
    global randomized_startup_64
    global randomized_vmemmap_base

    StartKernelBP("start_kernel", temporary=True)
    KernelRandomizeMemoryBP("kernel_randomize_memory", temporary=True)

    # start_kernel("start_kernel", temporary=True)
    gdb.execute("continue")

    # kernel_randomize_memory("kernel_randomize_memory", temporary=True)
    gdb.execute("finish")
    gdb.execute("finish")

    randomized_vmemmap_base = int(
        gdb.parse_and_eval("vmemmap_base")
    )
    randomized_page_offset_base = int(
        gdb.parse_and_eval("page_offset_base")
    )
    randomized_vmalloc_base = int(
        gdb.parse_and_eval("vmalloc_base")
    )
    randomized_startup_64 = int(gdb.parse_and_eval("&startup_64"))

    slide_vmemmap = (
        randomized_vmemmap_base - unrandomized_vmemmap_base
    ) >> PUD_SHIFT
    print(f"vmemmap_base,{hex(randomized_vmemmap_base)},{slide_vmemmap}")
    slide_page_offset = (
        randomized_page_offset_base - unrandomized_page_offset_base
    ) >> PUD_SHIFT
    print(f"page_offset_base,{hex(randomized_page_offset_base)},{slide_page_offset}")
    slide_vmalloc = (
        randomized_vmalloc_base - unrandomized_vmalloc_base
    ) >> PUD_SHIFT
    print(f"vmalloc_base,{hex(randomized_vmalloc_base)},{slide_vmalloc}")

    gdb.execute("continue")

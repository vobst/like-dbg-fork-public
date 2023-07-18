# pyright: reportGeneralTypeIssues=false, reportMissingModuleSource=false
from __future__ import annotations
import gdb

from typing import Any, Tuple, Dict, List, Iterable

from lkd.utils import (
    offset_of,
    cpu_num,
    deref_per_cpu,
    current_cpu,
    swap64,
)


class GenericStruct:
    """
    Info: Container for a struct. Do not instantiate directly.
    @attr   gdb.Value   address     pointer to struct
    @cvar   gdb.Value   stype       structure type
    @cvar   gdb.Value   ptype       structure pointer type
    @cvar   Dictionary  flags       flags that can be set
    """

    stype: gdb.Type | None = None
    ptype: gdb.Type | None = None
    flags: Dict[str | None, int] = {}

    def __init__(self, address):
        """
        Info: Constructor must deal with multiple input types.
        @param  undef       address     pointer to struct
        """
        assert self.stype and self.ptype

        try:
            address.type
        except:
            address = gdb.Value(address)

        if str(address.type) != str(self.ptype):
            address = address.cast(self.ptype)

        assert isinstance(address, gdb.Value)
        self.address: gdb.Value = address

    def get_member(self, member: str) -> gdb.Value:
        """
        @param  String      member      struct member to get
        """
        return self.address.dereference()[member]

    def flag_set(self, flag: str | None) -> bool:
        """
        Info: Returns 1 if flag is set on instance. Only works if
              struct has a member called 'flags'. Else must overwrite when
              subclassing.
        @param  String      flag        Symbolic representation of flag we
                                        want to check.
        """
        return (
            self.flags.get(flag, 0) & int(self.get_member("flags")) != 0
        )

    @property
    def sym_flags(self):
        tmp = []
        for flag in self.flags:
            if self.flag_set(flag):
                tmp.append(flag)
        if len(tmp) == 0:
            return "none"
        return " | ".join(tmp)

    @staticmethod
    def print_key_value(key: Any, value: Any, indent: int = 0) -> None:
        """
        Info: Defines output format.
        """
        print(indent * " " + "> '{0}': {1}".format(key, value))

    def print_member(self, member):
        """
        @param  String      member      struct member to print
        """
        value = self.get_member(member)
        if value.type.code == gdb.TYPE_CODE_PTR and int(value) == 0:
            value = "NULL"
        elif member == "flags":
            value = self.sym_flags
        self.print_key_value(member, value)

    def print_header(self):
        """
        Info: prints type and address of the struct.
        """
        print("{0} at {1}".format(self.stype, self.address))

    def print_info(self):
        """
        Info: Prints summary including 'interesting' members of the
              struct.
        """
        self.print_header()
        self._print_info()
        print("")

    def _print_info(self):
        """
        Implement yourself when subclassing.
        """
        pass


class Task(GenericStruct):
    stype = gdb.lookup_type("struct task_struct")
    ptype = stype.pointer()

    def _print_info(self):
        self.print_member("pid")
        self.print_member("comm")


class Pipe(GenericStruct):
    stype = gdb.lookup_type("struct pipe_inode_info")
    ptype = stype.pointer()

    def _print_info(self):
        self.print_member("head")
        self.print_member("tail")
        self.print_member("ring_size")
        self.print_member("bufs")


class PipeBuffer(GenericStruct):
    stype = gdb.lookup_type("struct pipe_buffer")
    ptype = stype.pointer()
    flags = {
        "PIPE_BUF_FLAG_LRU": 0x01,
        "PIPE_BUF_FLAG_ATOMIC": 0x02,
        "PIPE_BUF_FLAG_GIFT": 0x04,
        "PIPE_BUF_FLAG_PACKET": 0x08,
        "PIPE_BUF_FLAG_CAN_MERGE": 0x10,
        "PIPE_BUF_FLAG_WHOLE": 0x20,
    }

    def _print_info(self):
        self.print_member("page")
        self.print_member("offset")
        self.print_member("len")
        self.print_member("ops")
        self.print_member("flags")


class File(GenericStruct):
    stype = gdb.lookup_type("struct file")
    ptype = stype.pointer()

    def get_filename(self):
        # TODO Maybe make it like page_address so it can be used as
        #   a convenience function without creating class instance
        return self.get_member("f_path")["dentry"]["d_name"][
            "name"
        ].string()

    def _print_info(self):
        self.print_member("f_mapping")
        self.print_key_value("filename", self.get_filename())


class AddrSpace(GenericStruct):
    stype = gdb.lookup_type("struct address_space")
    ptype = stype.pointer()

    def _print_info(self):
        self.print_member("a_ops")
        self.print_key_value(
            "i_pages.xa_head", self.get_member("i_pages")["xa_head"]
        )


class XArray(GenericStruct):
    stype = gdb.lookup_type("struct xarray")
    ptype = stype.pointer()
    # TODO implement proper xarray functionality
    def _print_info(self):
        pass


class Slab(GenericStruct):
    try:
        stype: gdb.Type = gdb.lookup_type("struct slab")
    except:
        # Problem: Pre 5.17 kernels have no 'struct slab' and handle it
        #   as a 'struct page' union member instead.
        #   https://lwn.net/Articles/881039/
        stype: gdb.Type = gdb.lookup_type("struct page")
    ptype: gdb.Type = stype.pointer()

    def __init__(self, *args, **kwargs):
        super().__init__(*args)

        cache: KmemCache = KmemCache(self.get_member("slab_cache"))
        self.offset: int = int(cache.get_member("offset"))
        self.random: int = int(cache.get_member("random"))

    @classmethod
    def from_folio(cls, folio: Folio):
        """
        Info: Converts a Folio to Slab.
        @param  Folio       folio       Folio we want to convert to Slab.
        """
        return cls(folio.address)

    @classmethod
    def from_page(cls, page: Page):
        """
        Info: Constructs a Slab from any Page within it.
        @param  Page        page        Page we want to know Slab of.
        """
        folio: Folio = Folio.from_page(page)
        return cls.from_folio(folio)

    @classmethod
    def from_virtual(cls, virtual: Any):
        """
        Info: Constructs a Slab from any virtual address within it.
        @param              virtual     Any virtual address within slab
                                        e.g., whats returned by kmalloc.
        """
        page: Page = Page.from_virtual(virtual)
        return cls.from_page(page)

    @classmethod
    def split_address(cls, address: int) -> Tuple[int, int]:
        """
        Info: Splits a virtual address in a slab into a part that
              identifies the slab and a part that identifies the object.
        @param  int         address     The virtual address to split
        """
        return ((address >> 16) & 0xFFFF, address & 0xFFFF)

    @classmethod
    def format_address(cls, address: int) -> str:
        """
        Info: Pretty format an address in a slab.
        """
        return ":".join(
            map(
                lambda x: format(x, "04x"),
                cls.split_address(address),
            )
        )

    @classmethod
    def freelist(
        cls,
        cache: KmemCache | None,
        address: int,
        offset: int | None = None,
        random: int | None = None,
    ) -> Iterable[int]:
        """
        Info: generates the freelist of a slab
        @param  cache       KmemCache       The top level slab cache.
        @param  address     int             Address of the first free
                                            slot.
        """
        if cache == None:
            assert offset != None and random != None
        else:
            offset: int = int(cache.get_member("offset"))
            random: int = int(cache.get_member("random"))

        while address != 0:
            yield address

            try:
                obfuscated_ptr: int = int(
                    gdb.Value(address + offset)
                    .cast(gdb.lookup_type("unsigned long").pointer())
                    .dereference()
                )
            except Exception as E:
                print(
                    "Ups, either your exploit messes with the "
                    "slabs freelist or your gdb scripts suck"
                )
                print("Aborting freelist generation")
                print(E)
                break

            # freelist_ptr function
            address = random ^ swap64(address + offset) ^ obfuscated_ptr

    def counters(self) -> Tuple[int, int, int]:
        """
        Info: Returns the total capacity of the slab, the number of
              slots that are currently in use, and the frozen state.
        @return Tuple[int, int, int]    (inuse, objects, frozen)
        """
        counters: int = int(self.get_member("counters"))
        return (
            counters & 0xFFFF,
            (counters >> 16) & 0x7FFF,
            (counters >> 31) & 1,
        )

    def counters_str(self) -> Tuple[str, str, str]:
        return (
                str(self.counters()[0]) + "u",
                str(self.counters()[1]) + "c",
                str(self.counters()[2]) + "f",
        )

    @property
    def order(self) -> int:
        folio: Folio = Folio.from_slab(self)
        return int(folio.order)

    def oneline_summary(self) -> str:
        """
        Info: <slab identifier>:<useless slot identifier>::
                <length of freelist>:<inuse slots>:<total slots>:
                <frozen>
        """
        cache: KmemCache = KmemCache(self.get_member("slab_cache"))

        if int(cache.address) == 0:
            print(
                "WARN: oneline_summary requested for slab with "
                "slab_cache == NULL"
            )
            print(f"Using fallback {self.offset=} {self.random=}")
            freelist: Iterable[int] = self.freelist(
                None,
                int(self.get_member("freelist")),
                self.offset,
                self.random,
            )
        else:
            freelist: Iterable[int] = self.freelist(
                cache, int(self.get_member("freelist"))
            )

        return (
            f"{self.format_address(Page.page_to_virt(self.address))}"
            "::"
            f"{len(list(freelist))}f"
            ":"
            f"{':'.join(self.counters_str())}"
        )

    def _print_info(self) -> None:
        self.print_key_value("oneline_summary:", self.oneline_summary())


class Page(GenericStruct):
    stype = gdb.lookup_type("struct page")
    ptype = stype.pointer()
    pagesize: int = 4096
    page_shift: int = 12
    # start of the array of all struct page
    try:
        vmemmap_base: int = int(gdb.parse_and_eval("vmemmap_base"))
    except:
        # no aslr, x64
        vmemmap_base: int = 0xFFFFEA0000000000
    # base of the physical memory map
    try:
        page_offset_base: int = int(
            gdb.parse_and_eval("page_offset_base")
        )
    except:
        # no aslr, x64
        page_offset_base: int = 0xFFFF888000000000
    flags = {
        flag.name: 1 << int(flag.enumval)
        for flag in gdb.lookup_type("enum pageflags").fields()
    }

    def __init__(self, address):
        """
        @attr   gdb.Value   virtual     virtual address of data
        """
        super().__init__(address)
        self.virtual = self.page_address(self.address)

    @classmethod
    def from_virtual(cls, virtual: Any):
        """
        Info: Constructs the Page for a physmap virtual address.
        """
        pfn: int = (
            int(virtual) - cls.page_offset_base
        ) >> cls.page_shift
        assert cls.stype
        return cls(cls.vmemmap_base + int(cls.stype.sizeof) * pfn)

    @classmethod
    def page_to_phys(cls, page: Any):
        """
        Info: Calculates the physical address of a page.
        @param  undefined   page        Must become a 'struct page *' by
                                        a call to int().
        @return Int                     Physical address of page.
        """
        page = int(page)
        assert cls.stype
        return (
            int((page - cls.vmemmap_base) / cls.stype.sizeof)
            << cls.page_shift
        )

    @classmethod
    def phys_to_virt(cls, address: int) -> int:
        """
        Info: Calculates the virtual address to a physical address.
        """
        return address + cls.page_offset_base

    @classmethod
    def page_to_virt(cls, address: Any) -> int:
        return cls.phys_to_virt(cls.page_to_phys(int(address)))

    @classmethod
    def page_address(cls, page: Any) -> int:
        """
        Info: Calculates the virtual address of a page.
        @param  undefined   page        'struct page *'
        @return int                     physmap addr of page's memory
        """
        page = int(page)
        return cls.phys_to_virt(cls.page_to_phys(page))

    def read(self, offset, length) -> bytes:
        return (
            gdb.selected_inferior()
            .read_memory(self.virtual + offset, length)
            .tobytes()
        )

    def _print_info(self):
        self.print_member("flags")
        self.print_key_value("virtual", hex(self.virtual))
        self.print_key_value(
            "data",
            str(self.read(0, 20))
            + str(self.read(self.pagesize - 20, 20)),
        )


class Folio(GenericStruct):
    # TODO list with pages of folio
    try:
        stype: gdb.Type = gdb.lookup_type("struct folio")
    except:
        # Problem: Pre 5.14 kernels have no folios. They use compound
        #   pages instead. https://lwn.net/Articles/849538/
        stype: gdb.Type = gdb.lookup_type("struct page")
    ptype: gdb.Type = stype.pointer()
    flags = Page.flags

    @classmethod
    def from_slab(cls, slab: Slab):
        """
        Info: Converts Slab to Folio.
        @param  Slab        slab        Slab we want to convert to folio
        """
        return cls(slab.address)

    @classmethod
    def from_page(cls, page: Page):
        """
        Info: Constuct Folio from any Page within it.
        @param  Page        page        Page instance we want to get the
                                        folio of.
        """
        head: int = int(page.get_member("compound_head"))
        if head & 1:
            return cls(head - 1)
        else:
            return cls(page.address)

    @classmethod
    def from_virtual(cls, virtual: Any):
        """
        Info: Constructs a folio from any virtual address within it.
        """
        page: Page = Page.from_virtual(virtual)
        return cls.from_page(page)

    @property
    def order(self) -> int:
        """
        Info: A folio contains 2^order pages. This info is stored on the
              first tail page.
        """
        if int(self.get_member("flags")) & self.flags.get("PG_head", 0):
            assert Page.stype
            return int(
                self.address[1].cast(Page.stype)["compound_order"]
            )
        else:
            return 0

    def _print_info(self) -> None:
        self.print_member("flags")
        self.print_key_value("order", hex(self.order))


class KmemCache(GenericStruct):
    stype: gdb.Type = gdb.lookup_type("struct kmem_cache")
    ptype: gdb.Type = stype.pointer()
    list_offset: int = offset_of(stype, "list")

    @classmethod
    def from_list(cls, lst):
        """
        Info: Constructor from &cache->list
        """
        return cls(int(lst) - cls.list_offset)

    @classmethod
    def from_slab(cls, address: Any):
        """
        Info: Constructor from any slab within this chache
        @param  address                 Virtual address of 'struct slab'
                                        (or 'struct page').
        """
        slab: Slab = Slab(address)
        return cls(slab.get_member("slab_cache"))

    @classmethod
    def from_virtual(cls, address: Any):
        """
        Info: Constructor from any virtual address within any slab in
              this chache.
        """
        slab: Slab = Slab.from_virtual(address)
        return cls.from_slab(slab.address)

    def nxt(self):
        pass

    def prev(self):
        pass

    def _print_info_per_cpu(self, cpu: int | None = None) -> None:
        """Displays some per-cpu state for this slab cache
        @param  cpu     int             Show only a single cpu. Default
                                        is all cpus.
        """
        cpus: List[int] = [cpu] if cpu != None else list(range(cpu_num))

        for cpu in cpus:
            print(f"+ CPU {cpu}")
            kmem_cache_cpu: gdb.Value = deref_per_cpu(
                self.get_member("cpu_slab"), cpu
            )
            # active per-cpu slab
            slab: Slab = Slab.from_page(Page(kmem_cache_cpu["page"]))
            self.print_key_value(
                "page",
                f"{Slab.format_address(Page.page_to_virt(slab.address))}"
                "::"
                f"{len(list(Slab.freelist(self, int(kmem_cache_cpu['freelist']))))}"
                ":"
                f"{':'.join(map(lambda x: str(x), slab.counters()))}",
                indent = 1,
            )

            # per-cpu partial slabs
            msg = ""
            partial: int = int(kmem_cache_cpu["partial"])
            while partial != 0:
                slab: Slab = Slab.from_page(Page(partial))
                msg += "-->" + slab.oneline_summary()
                partial: int = int(slab.get_member("next"))
            self.print_key_value(
                "partials",
                msg,
                indent = 1,
            )

    def _print_info(self):
        self.print_member("name")
        self._print_info_per_cpu(current_cpu())

from binaryninja import BinaryView
from weable.src.constants import METACLASS_ALLOC_OFF, EXT_METHOD_OFF, NEW_UC_OFF
from weable.src.vtable import find_class_vtable_from_alloc


class IClass:
    def __init__(self, this_addr: int, p_addr: int, name: str, sz: int, bv: BinaryView = None): # type: ignore
        # address to instance of metaclass
        self.this_addr = this_addr
        
        self.p_addr = p_addr
        self.name = name
        self.sz = sz

        self.parent: "IClass | None" = None
        self.vtable_addr: int = 0
        self.this_vtable_addr: int = 0
        self.src: int = 0
        self.origin_kext: str = ""

        if bv:
            self._try_set_origin_kext(bv, self.this_addr)



    # ── setters ───────────────────────────────────────────────────────

    def set_vtable(self, vtable_addr: int):
        self.vtable_addr = vtable_addr

    def set_parent(self, parent: "IClass"):
        self.parent = parent

    def set_src(self, src: int, bv: BinaryView = None): # type: ignore
        self.src = src
        if bv and self.src > 0:
            self._try_set_origin_kext(bv, self.src)

    def set_this_vtable(self, bv: BinaryView):
        if self.vtable_addr == 0:
            return

        alloc_ptr = bv.read_pointer(self.vtable_addr + METACLASS_ALLOC_OFF)
        result = find_class_vtable_from_alloc(bv, alloc_ptr)
        if result:
            self.this_vtable_addr = result
            self._try_set_origin_kext(bv, self.vtable_addr)
            if self.this_vtable_addr > 0:
                self._try_set_origin_kext(bv, self.this_vtable_addr)

    # ── queries ───────────────────────────────────────────────────────

    def get_externalMethod_addr(self, bv: BinaryView) -> int | None:
        if self.this_vtable_addr > 0:
            return bv.read_pointer(self.this_vtable_addr + EXT_METHOD_OFF)
        return None

    def get_new_uc_addr(self, bv: BinaryView) -> int | None:
        if self.this_vtable_addr > 0:
            return bv.read_pointer(self.this_vtable_addr + NEW_UC_OFF)
        return None

    def get_vtable_entries_count(self, bv: BinaryView, addr: int) -> int:
        if addr > 0:
            curr = addr
            while bv.read_pointer(curr) != 0:
                curr += bv.address_size
            return (curr - addr) // bv.address_size
        
        raise Exception(f'bad vtable addr: @{hex(addr)}')


    def get_this_vtable_struct(self, bv: BinaryView) -> str:
        entries = self.get_vtable_entries_count(bv, self.this_vtable_addr)
        print(f"Counted {entries} entries")

        functions = [f"void (*func_{hex(i)})();" for i in range(entries)]
        inner = "\n\t\t".join(functions)
        return f"struct VT_{self.name} {{{inner}}};"

    # ── internal ──────────────────────────────────────────────────────

    def _try_set_origin_kext(self, bv: BinaryView, addr: int, last: bool = False):
        sections = bv.get_sections_at(addr)

        if len(sections) > 1:
            raise Exception(f"Address should belong to one section, got: {sections}")

        if len(sections) == 0:
            if last and not self.origin_kext:
                raise Exception(f"Last attempt to get origin kext failed: class={self.name}")
            return

        kext_name = sections[0].name.split("::")[0]

        if self.origin_kext and self.origin_kext != kext_name:
            raise Exception(
                f"Addresses of one class diverge: new={kext_name} old={self.origin_kext}"
            )

        self.origin_kext = kext_name

    def __repr__(self) -> str:
        return (
            f"IClass(name={self.name!r}, this={hex(self.this_addr)}, "
            f"vtable={hex(self.this_vtable_addr)}, kext={self.origin_kext!r})"
        )


BASE_ICLASS = IClass(0x0, 0x0, "OSNullClass", 0x0)
BASE_ICLASS.set_src(0x0)
BASE_ICLASS.set_parent(BASE_ICLASS)
from binaryninja import BinaryView, LowLevelILOperation, lowlevelil

from weable.src.utils import unsigned, get_u_reg_value_at, resolve_reg_value, reg_value
from weable.src.iclass import IClass, BASE_ICLASS
from weable.src.registry import ClassRegistry

def set_classes(bv: BinaryView, reg: ClassRegistry):
    def must_set_var(addr: int, name: str, entries: int):
        dvar = bv.get_data_var_at(addr)
        if dvar is not None:
            dvar.name = name

            # if vtable
            if entries > 0:
                dvar.type = f'void * [{entries}]'  # type: ignore
        else:
            raise Exception(f'Failed to get var at addr @{hex(addr)}')

    instances = reg.all_gInstances()
    cll = reg.all()

    # Set metaclass instances
    for addr in instances:
        if addr > 0:
            name = f'instance_{instances[addr]}'
            must_set_var(addr, name, 0x0)
    
    # Set vtables of metaclasses & classes
    for cl in cll:
        if cl.vtable_addr > 0:
            metaName = reg.get_class(cl.this_addr)
            must_set_var(cl.vtable_addr, f'vtable_for_{metaName}', cl.get_vtable_entries_count(bv, cl.vtable_addr))

            if cl.this_vtable_addr > 0:
                must_set_var(cl.this_vtable_addr, f'vtable_for_{cl.name}', cl.get_vtable_entries_count(bv, cl.this_vtable_addr))
    

def analyse_all(bv: BinaryView) -> ClassRegistry:
    registry = ClassRegistry()

    _analyse_sections(bv, "__mod_init_func", registry)
    _analyse_sections(bv, "__kmod_init", registry)

    registry.add(BASE_ICLASS)
    registry.set_parents()
    registry.set_real_vtables(bv)
    registry.print_tree()

    return registry


# ── internal ──────────────────────────────────────────────────────────


def _analyse_sections(bv: BinaryView, sel_section: str, registry: ClassRegistry):
    for section_name in bv.sections:
        if sel_section not in section_name:
            continue

        section = bv.get_section_by_name(section_name)
        if not section:
            print("Section not found — is this a kernelcache?")
            return

        print(f"Found {section_name} at @{hex(section.start)}")

        for addr in range(section.start, section.end, bv.address_size):
            ptr = bv.read_pointer(addr)
            if ptr == 0:
                continue
            if not bv.get_function_at(ptr):
                print(f"Creating user function at @{hex(ptr)}")
                bv.create_user_function(ptr)
            _analyse_static_initializer(bv, ptr, registry)


def _analyse_static_initializer(bv: BinaryView, ptr: int, registry: ClassRegistry):
    func = bv.get_function_at(ptr)
    if not func:
        return

    llil = func.llil
    if not llil:
        print("(!?) LLIL not ready — skipping")
        return

    print(f"Analysing initializer {func.name} (@{hex(ptr)})")
    memo: dict[int, IClass] = {}

    for block in llil:
        for instr in block:
            if instr.operation == LowLevelILOperation.LLIL_CALL:
                _handle_call(bv, func, instr, ptr, memo, registry)

            elif instr.operation == LowLevelILOperation.LLIL_STORE:
                _handle_store(instr, memo)


def _handle_call(bv, func, instr, src_ptr, memo, registry):
    addr = instr.address

    x0 = get_u_reg_value_at(func, addr, "x0")
    x1 = get_u_reg_value_at(func, addr, "x1")

    x2 = get_u_reg_value_at(func, addr, "x2")
    if not x2:
        resolved = resolve_reg_value(bv, func, addr, "x2")
        if resolved is not None:
            x2 = resolved

    x3 = get_u_reg_value_at(func, addr, "x3")

    class_name = bv.get_string_at(x1)
    if not class_name:
        return  # вероятно zone_create_ext и т.п.

    new_cls = IClass(x0, x2, class_name.value, x3, bv)
    new_cls.set_src(src_ptr, bv)
    memo[x0] = new_cls
    registry.add(new_cls)
    
    # x0 - ptr of class::metaClass, *x0 - class::metaClass->vtable


def _handle_store(instr, memo):
    ops = instr.operands
    if len(ops) < 2:
        return

    dst, src = ops[0], ops[1]

    if not isinstance(dst, lowlevelil.LowLevelILReg):
        return

    dst_v = reg_value(dst)
    if dst_v not in memo:
        return

    src_v = src.possible_values.value  # type: ignore
    if src_v:
        memo[dst_v].set_vtable(unsigned(src_v))
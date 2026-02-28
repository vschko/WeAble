import os
import json
from pathlib import Path
from binaryninja import BinaryView, LowLevelILOperation, lowlevelil, log

from weable.src.utils import unsigned, get_u_reg_value_at, resolve_reg_value, reg_value, find_next_call_from
from weable.src.iclass import IClass, BASE_ICLASS
from weable.src.registry import ClassRegistry
from weable.src.constants import *
from collections import deque


def perform_analysis(bv: BinaryView):
    reg = get_registry(bv)
    log.log_info(f":: WeAble :: Found {len(reg.all())} types")

    setup_classes(bv, reg)
    restore_useful_functions(bv)
    log.log_info(f":: WeAble :: Done!")


def load_known_vtables(vtables_dir: str = './assets/vtables') -> dict[str, list[str]]:
    vtables_dir= str(Path(os.path.dirname((os.path.realpath(__file__))))/vtables_dir)

    known = {}
    vtables_path = Path(vtables_dir)
    if not vtables_path.exists():
        return known
    for f in vtables_path.glob('*.json'):
        try:
            with open(f, 'r') as fp:
                data = json.load(fp)
                known[data['name']] = data['vtable_entries']
        except (json.JSONDecodeError, KeyError):
            continue
    return known


def setup_classes(bv: BinaryView, reg: ClassRegistry):
    def must_set_var(addr: int, name: str, entries: int):
        dvar = bv.get_data_var_at(addr)
        if dvar is not None:
            dvar.name = name
            if entries > 0:
                dvar.type = f'void * [{entries}]' # type: ignore
        else:
            raise Exception(f'Failed to get var at addr @{hex(addr)}')

    instances = reg.all_gInstances()
    cll = reg.all()

    print(f'[*] Setting {len(instances)} metaclass instances...')
    for addr in instances:
        if addr > 0:
            must_set_var(addr, f'instance_{instances[addr]}', 0x0)

    print(f'[*] Setting vtables for {len(cll)} classes...')
    for cl in cll:
        if cl.vtable_addr > 0:
            metaName = reg.get_class(cl.this_addr)
            must_set_var(cl.vtable_addr, f'vtable_for_{metaName}',
                         cl.get_vtable_entries_count(bv, cl.vtable_addr))
            if cl.this_vtable_addr > 0:
                must_set_var(cl.this_vtable_addr, f'vtable_for_{cl.name}',
                             cl.get_vtable_entries_count(bv, cl.this_vtable_addr))

    known_vtables = load_known_vtables()
    ptr_size = bv.address_size
    print(f'[*] Pointer size: {ptr_size}')

    def read_ptr(addr: int) -> int:
        data = bv.read(addr, ptr_size)
        if not data or len(data) < ptr_size:
            return 0
        return int.from_bytes(data, byteorder='little')

    vtable_ptrs: dict[str, list[int]] = {}
    for cl in cll:
        if cl.this_vtable_addr > 0:
            count = cl.get_vtable_entries_count(bv, cl.this_vtable_addr)
            if count > 0:
                vtable_ptrs[cl.name] = [
                    read_ptr(cl.this_vtable_addr + i * ptr_size)
                    for i in range(count)
                ]
    print(f'[*] Cached vtable pointers for {len(vtable_ptrs)} classes')

    resolved: dict[str, list[str]] = {}
    for name, entries in known_vtables.items():
        resolved[name] = list(entries)
    print(f'[*] Pre-resolved {len(resolved)} classes from JSON')

    def rename_func(addr: int, name: str) -> bool:
        if addr == 0:
            return False
        func = bv.get_function_at(addr)
        if func is None:
            return False
        if func.name.startswith('sub_') or func.name.startswith('j_sub_'):
            func.name = name
            return True
        return False

    visited: set[str] = set()
    initial = reg.get_descendants('OSObject', depth=1)
    queue: deque[IClass] = deque(initial)

    stats = {
        'from_json': 0,
        'from_binary': 0,
        'inherited': 0,
        'no_parent': 0,
        'renamed': 0,
        'skipped_no_func': 0,
        'overrides': 0,
        'new_methods': 0,
    }
    processed = 0

    while queue:
        cl = queue.popleft()
        child_name = cl.name

        if child_name in visited:
            continue
        visited.add(child_name)

        processed += 1
        if processed % 100 == 0:
            print(f'[*] Processed {processed} classes, queue: {len(queue)}...')

        parent = cl.parent
        if parent is None:
            print(f'[?] {child_name}: no parent, skipping resolve')
            stats['no_parent'] += 1
            queue.extend(reg.get_descendants(child_name, depth=1))
            continue

        parent_resolved = resolved.get(parent.name, [])

        if child_name in known_vtables:
            resolved[child_name] = list(known_vtables[child_name])
            stats['from_json'] += 1
            print(f'[+] {child_name}: resolved from JSON ({len(resolved[child_name])} entries)')

        elif child_name in vtable_ptrs and parent_resolved:
            child_ptrs = vtable_ptrs[child_name]
            child_count = len(child_ptrs)
            parent_ptrs = vtable_ptrs.get(parent.name, [])

            if not parent_ptrs:
                print(f'[?] {child_name}: parent {parent.name} has no binary vtable, '
                      f'using resolved names only')

            entries: list[str] = []
            local_overrides = 0
            local_new = 0

            for i in range(child_count):
                if i < len(parent_resolved):
                    inherited = (
                        parent_ptrs
                        and i < len(parent_ptrs)
                        and child_ptrs[i] == parent_ptrs[i]
                    )
                    if inherited:
                        entries.append(parent_resolved[i])
                    else:
                        orig = parent_resolved[i]
                        method = orig.split('::', 1)[-1] if '::' in orig else orig
                        entries.append(f'{child_name}::{method}')
                        local_overrides += 1
                else:
                    entries.append(f'{child_name}::method_{i}')
                    local_new += 1

            resolved[child_name] = entries
            stats['from_binary'] += 1
            stats['overrides'] += local_overrides
            stats['new_methods'] += local_new
            print(f'[+] {child_name}: resolved from binary '
                  f'(parent={parent.name}, {len(entries)} entries, '
                  f'{local_overrides} overrides, {local_new} new)')

        else:
            resolved[child_name] = list(parent_resolved)
            stats['inherited'] += 1
            reason = 'no binary vtable' if child_name not in vtable_ptrs else 'no parent resolved'
            print(f'[-] {child_name}: inherited from {parent.name} ({reason})')

        if child_name in vtable_ptrs and child_name in resolved:
            local_renamed = 0
            local_skipped = 0
            for i, method_name in enumerate(resolved[child_name]):
                if i >= len(vtable_ptrs[child_name]):
                    break
                func_ptr = vtable_ptrs[child_name][i]
                if rename_func(func_ptr, method_name):
                    local_renamed += 1
                elif func_ptr != 0 and bv.get_function_at(func_ptr) is None:
                    local_skipped += 1

            stats['renamed'] += local_renamed
            stats['skipped_no_func'] += local_skipped

            if local_renamed > 0 or local_skipped > 0:
                print(f'    → renamed {local_renamed} funcs, '
                      f'{local_skipped} skipped (no func at addr)')

        queue.extend(reg.get_descendants(child_name, depth=1))

def restore_useful_functions(bv: BinaryView):
    checkpoints = {
        'IOTaskHasEntitlement': set_IOTaskHasEntitlement,
    }

    for step, fn in checkpoints.items():
        addr = fn(bv)
        if addr:
            log.log_info(f':: WeAble :: Restored {step} at @{hex(addr)}')
        else:
            print(f':: WeAble :: Failed to restore {step}')


def get_registry(bv: BinaryView) -> ClassRegistry:
    registry = ClassRegistry()

    _analyse_sections(bv, "__mod_init_func", registry)
    _analyse_sections(bv, "__kmod_init", registry)

    registry.add(BASE_ICLASS)
    registry.set_parents()
    registry.set_real_vtables(bv)

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


def set_IOTaskHasEntitlement(bv: BinaryView):
    canary_ptr = bv.find_next_data(bv.start, CANARY_IOTaskHasEntitlement.encode()) 
    if canary_ptr and canary_ptr > 0:
        for ref in bv.get_code_refs(canary_ptr):
            caller_addr = bv.get_previous_function_start_before(ref.address)
            caller = bv.get_function_at(caller_addr)
            if caller and CANARY_CALLER_IOTaskHasEntitlement in caller.name:
                target_fn_addr = find_next_call_from(bv, caller, ref.address)
                
                if target_fn_addr and target_fn_addr > 0:
                    target_fn = bv.get_function_at(target_fn_addr)
                    if target_fn:
                        target_fn.name = '_IOTaskHasEntitlement'
                        return target_fn_addr
    return 0x0
    
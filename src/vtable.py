from binaryninja import BinaryView, MediumLevelILOperation


def find_class_vtable_from_alloc(bv: BinaryView, alloc_addr: int):
    alloc_func = bv.get_function_at(alloc_addr)
    if not alloc_func:
        return None

    mlil = alloc_func.mlil
    if not mlil:
        return None

    vtable = _find_vtable_store_in_func(bv, mlil)
    if vtable:
        return vtable

    for block in mlil:
        for instr in block:
            if instr.operation != MediumLevelILOperation.MLIL_CALL:
                continue
            callee = instr.dest
            if callee.operation != MediumLevelILOperation.MLIL_CONST_PTR:
                continue
            ctor_func = bv.get_function_at(callee.constant)
            if ctor_func and ctor_func.mlil:
                vtable = _find_vtable_store_in_func(bv, ctor_func.mlil)
                if vtable:
                    return vtable

    return None


def _find_vtable_store_in_func(bv: BinaryView, mlil):
    last_vtable = None

    for block in mlil:
        for instr in block:
            if instr.operation != MediumLevelILOperation.MLIL_STORE:
                continue

            dst = instr.dest
            src = instr.src

            if src.operation not in (
                MediumLevelILOperation.MLIL_CONST,
                MediumLevelILOperation.MLIL_CONST_PTR,
            ):
                continue

            vtable_candidate = src.constant & 0xFFFFFFFFFFFFFFFF
            is_base_store = False

            if dst.operation in (
                MediumLevelILOperation.MLIL_VAR,
                MediumLevelILOperation.MLIL_VAR_SSA,
            ):
                is_base_store = True
            elif dst.operation == MediumLevelILOperation.MLIL_ADD:
                ops = dst.operands
                if (
                    len(ops) == 2
                    and ops[1].operation == MediumLevelILOperation.MLIL_CONST
                    and ops[1].constant == 0
                ):
                    is_base_store = True

            if is_base_store:
                seg = bv.get_segment_at(vtable_candidate)
                if seg and not seg.executable:
                    last_vtable = vtable_candidate

    return last_vtable
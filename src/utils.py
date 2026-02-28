import struct
from binaryninja import (
    BinaryView,
    RegisterValueType,
    LowLevelILOperation,
    lowlevelil,
    variable,
)


def unsigned(val: int, bits: int = 64) -> int:
    return val & ((1 << bits) - 1)


def get_u_reg_value_at(func, addr: int, reg_name: str) -> int:
    val = func.get_reg_value_at(addr, reg_name)
    if val.type in (
        RegisterValueType.ConstantValue,
        RegisterValueType.ConstantPointerValue,
    ):
        return unsigned(val.value)
    return 0x0


def resolve_reg_value(bv: BinaryView, func, call_addr: int, reg_name: str):
    llil = func.llil
    if not llil:
        return None

    instrs_before_call = []
    for block in llil:
        for instr in block:
            if instr.address >= call_addr:
                break
            instrs_before_call.append(instr)

    return _trace_reg(bv, func, call_addr, reg_name, instrs_before_call, depth=0)


def reg_value(reg: lowlevelil.LowLevelILReg) -> int:
    reg_v = reg.value

    if reg_v.type in (
        RegisterValueType.ConstantValue,
        RegisterValueType.ConstantPointerValue,
    ):
        return unsigned(reg_v.value)

    if isinstance(reg_v, (variable.StackFrameOffsetRegisterValue, variable.Undetermined)):
        return 0x0

    raise Exception(f"Unknown register value type: {type(reg_v)}")


# ── internal ──────────────────────────────────────────────────────────

def _trace_reg(bv, func, call_addr, reg_name, instrs, depth):
    if depth > 8:
        return None

    for instr in reversed(instrs):
        if instr.operation != LowLevelILOperation.LLIL_SET_REG:
            continue
        if str(instr.dest) != reg_name:
            continue

        src = instr.src

        if src.operation == LowLevelILOperation.LLIL_LOAD:
            load_addr = src.src.value
            if load_addr.type in (
                RegisterValueType.ConstantValue,
                RegisterValueType.ConstantPointerValue,
            ):
                mem_addr = unsigned(load_addr.value)
                data = bv.read(mem_addr, 8)
                if data and len(data) == 8:
                    return struct.unpack('<Q', data)[0]
            return None

        if src.operation == LowLevelILOperation.LLIL_REG:
            other_reg = str(src.src)
            idx = instrs.index(instr)
            return _trace_reg(bv, func, call_addr, other_reg, instrs[:idx], depth + 1)

        val = src.value
        if val.type in (
            RegisterValueType.ConstantValue,
            RegisterValueType.ConstantPointerValue,
        ):
            return unsigned(val.value)

        return None

    return None
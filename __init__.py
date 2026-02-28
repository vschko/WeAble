"""
	Call analyse_all 
"""

import json
import struct
from binaryninja import *

METACLASS_ALLOC_OFF = 0x68
EXT_METHOD_OFF = 0x540 # x1 -> sel?
NEW_UC_OFF = 0x460     # x3 -> type

def unsigned(val, bits=64):
    return val & ((1 << bits) - 1)


class IClass:
	this_addr: int
	p_addr: int
	vtable_addr: int
	this_vtable_addr: int
	name: str
	sz: int 
	src: int
	origin_kext: str

	def __init__(self, this_addr: int, p_addr: int, name: str, sz: int, bv = None):
		self.p_addr = p_addr
		self.name = name
		self.sz = sz
		self.parent = None
		self.vtable_addr = 0x0
		self.this_vtable_addr = 0
		self.src = 0
		self.origin_kext = ''

		self.this_addr = this_addr
		if bv:
			self._try_set_origin_kext(bv, self.this_addr)

	def set_vtable(self, vtable_addr: int):
		self.vtable_addr = vtable_addr

	def set_parent(self, p):
		self.parent = p

	def set_src(self, src: int, bv=None):
		self.src = src

		if bv and self.src > 0:
			self._try_set_origin_kext(bv, self.src)

	def set_this_vtable(self, bv: BinaryView):
		if self.vtable_addr == 0:
			return

		alloc_vt = self.vtable_addr+METACLASS_ALLOC_OFF
		alloc_ptr = bv.read_pointer(alloc_vt)		
		if res := find_class_vtable_from_alloc(bv, alloc_ptr):
			self.this_vtable_addr = res
			
			self._try_set_origin_kext(bv, self.vtable_addr)			
			if self.this_vtable_addr > 0:
				self._try_set_origin_kext(bv, self.this_vtable_addr)
	
	def get_this_vtable_struct(self, bv: BinaryView):
		if self.this_vtable_addr == 0x0:
			raise Exception('can\'t build struct for vtable=0x0')
		
		curr = self.this_vtable_addr
		while bv.read_pointer(curr) != 0:
			curr += bv.address_size
		entries = (curr - self.this_vtable_addr)//bv.address_size
		print(f'Counted {entries} entries')

		functions = [f'void (*func_{hex(i)})();' for i in range(entries)]
		self.__apply_known_schemas(bv, functions)

		inner = '\n\t\t'.join(functions)
		c_struct = f"struct VT_{self.name} {{{inner}}};"
		return c_struct
	
	def __apply_known_schemas(self, bv: BinaryView, funcs: list[str]):
		pass

	def _try_set_origin_kext(self, bv: BinaryView, addr: int, last=False):
		sections = bv.get_sections_at(addr)
		if len(sections) > 1: 
			raise Exception(f'In normal world addr should be related to one kext: got {sections}')
		
		if len(sections) == 0:
			if last and len(self.origin_kext) == 0:
				raise Exception(f'Last attempt to get origin kext failed: class={self.name}')
			return
		
		section_name = sections[0].name
		#in modern world sections look like "com.apple.driver.ASIOKit::__DATA_CONST.__const"
		kext_name = section_name.split('::')[0]

		# Just one more canary
		if len(self.origin_kext) > 0 and self.origin_kext != kext_name:
			raise Exception(f'Addresses of one Kext divergent: new={kext_name} old={self.origin_kext}')
		
		self.origin_kext = kext_name

	def get_externalMethod_addr(self, bv: BinaryView):
		if self.this_vtable_addr > 0:
			v = bv.read_pointer(self.this_vtable_addr + EXT_METHOD_OFF)
			return v

	def get_new_uc_addr(self, bv: BinaryView):
		if self.this_vtable_addr > 0:
			v = bv.read_pointer(self.this_vtable_addr + NEW_UC_OFF)
			return v


def get_u_reg_value_at(func, addr, reg_name):
    val = func.get_reg_value_at(addr, reg_name)
    if val.type in (
        RegisterValueType.ConstantValue,
        RegisterValueType.ConstantPointerValue,
    ):
        return unsigned(val.value)
    return 0x0


def resolve_reg_value(bv: BinaryView, func, call_addr, reg_name):
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
            if instr.operation == MediumLevelILOperation.MLIL_CALL:
                callee = instr.dest
                if callee.operation == MediumLevelILOperation.MLIL_CONST_PTR:
                    ctor_addr = callee.constant
                    ctor_func = bv.get_function_at(ctor_addr)
                    if ctor_func and ctor_func.mlil:
                        vtable = _find_vtable_store_in_func(bv, ctor_func.mlil)
                        if vtable:
                            return vtable

    return None


def _find_vtable_store_in_func(bv, mlil):
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

            if dst.operation == MediumLevelILOperation.MLIL_VAR:
                is_base_store = True

            elif dst.operation == MediumLevelILOperation.MLIL_ADD:
                ops = dst.operands
                if len(ops) == 2:
                    if (ops[1].operation == MediumLevelILOperation.MLIL_CONST
                            and ops[1].constant == 0):
                        is_base_store = True

            if dst.operation in (
                MediumLevelILOperation.MLIL_VAR,
                MediumLevelILOperation.MLIL_VAR_SSA,
            ):
                is_base_store = True

            if is_base_store:
                seg = bv.get_segment_at(vtable_candidate)
                if seg and not seg.executable:
                    last_vtable = vtable_candidate

    return last_vtable

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
            return _trace_reg(bv, func, call_addr, other_reg,
                              instrs[:idx], depth + 1)

        val = src.value
        if val.type in (
            RegisterValueType.ConstantValue,
            RegisterValueType.ConstantPointerValue,
        ):
            return unsigned(val.value)

        return None

    return None

def reg_value(reg: lowlevelil.LowLevelILReg):
	reg_v = reg.value

	if reg_v.type == RegisterValueType.ConstantValue:
		real_v = reg_v.value
	elif reg_v.type == RegisterValueType.ConstantPointerValue:
		real_v = reg_v.value
	elif type(reg_v) == variable.StackFrameOffsetRegisterValue or type(reg_v) == variable.Undetermined:
		real_v = 0x0
	else:
		raise Exception("Unknown type of value!")

	return unsigned(real_v)
			

BASE_ICLASS = IClass(0x0, 0x0, "OSNullClass", 0x0)
BASE_ICLASS.set_src(0x0)
BASE_ICLASS.set_parent(BASE_ICLASS)

class ClassRegistry:
	registry: dict[int, IClass]
	secondaryRegistry: dict[str, IClass]

	def __init__(self):
		self.registry = dict()
		self.secondaryRegistry = dict()
	
	def add(self, cls: IClass):
		if cls.this_addr in self.registry:
			return
			#raise Exception('adding class again?')
		self.registry[cls.this_addr] = cls
		self.secondaryRegistry[cls.name] = cls

	def all(self) -> list[IClass]:
		return [*self.registry.values()]
	
	def set_parents(self):
		bad_classes = []
		for c in self.registry.values():
			if not c.p_addr in self.registry:
				bad_classes.append(c.this_addr)
				continue  
			
			parent = self.registry[c.p_addr]
			c.set_parent(parent)
		
		print('Bad classes count: ', len(bad_classes))
		for b in bad_classes:
			del(self.registry[b])
	
	def set_real_vtables(self, bv: BinaryView):
		for c in self.registry.values():
			c.set_this_vtable(bv)

	def print_tree(self):
		children: dict[int, list[IClass]] = dict()
		for cls in self.registry.values():
			if cls.parent is None or cls.parent is BASE_ICLASS:
				continue
			p_addr = cls.parent.this_addr
			if p_addr not in children:
				children[p_addr] = []
			children[p_addr].append(cls)

		roots = [c for c in self.registry.values() if c.parent is BASE_ICLASS]
		roots.sort(key=lambda c: c.name)

		def _print(cls: IClass, depth: int):
			#print(f"{'\t' * depth}{cls.name} (sz={hex(cls.sz)}, MVT={hex(cls.vtable_addr)}, VT={hex(cls.this_vtable_addr)})")
			kids = children.get(cls.this_addr, [])
			kids.sort(key=lambda c: c.name)
			for child in kids:
				_print(child, depth + 1)

		for root in roots:
			_print(root, 0)
		print(f'Total: {len(self.registry)} entries')

	def get_descendants(self, classname: str) -> list[IClass]:
		cls = self.secondaryRegistry.get(classname)
		if cls is None:
			return []

		children_map: dict[int, list[IClass]] = {}
		for c in self.registry.values():
			if c.parent is None or c.parent is BASE_ICLASS:
				continue
			p_addr = c.parent.this_addr
			if p_addr not in children_map:
				children_map[p_addr] = []
			children_map[p_addr].append(c)

		result: list[IClass] = []

		def _collect(node: IClass):
			for child in children_map.get(node.this_addr, []):
				result.append(child)
				_collect(child)

		_collect(cls)
		return result
	
	def dump(self, path='/tmp/registry.json'):
		osc = []

		# name, all parents (right to left ->), origin_kext, real_vtable_addr
		for osclass in self.secondaryRegistry.values():
			print(osclass)
			parents = []
			
			if osclass.parent:
				curr = osclass.parent
				while curr.name != 'OSNullClass':
					parents.append(curr.name)
					curr = curr.parent
			
			dump_osclass = {
				'class_name': osclass.name,
				'origin': osclass.origin_kext,
				'parents': parents,
				'vtable_addr': osclass.this_vtable_addr
			}
			osc.append(dump_osclass)
			
		with open(path, 'w') as fd:
			fd.write(json.dumps(osc))
		print('done')

reg = ClassRegistry()


def analyse_static_initializer(bv: BinaryView, ptr: int):
	ini_func = bv.get_function_at(ptr)
	if not ini_func:
		return
	
	llil = ini_func.llil
	if not llil:
		print('(!?) llil not ready? skipping')
		return

	print(f'Analysing the initializer {ini_func.name} (@{hex(ptr)})')
	memo = {}

	for block in llil:
		for instr in block:
			if instr.operation == LowLevelILOperation.LLIL_CALL:
				x0 = get_u_reg_value_at(ini_func, instr.address, 'x0')

				x1 = get_u_reg_value_at(ini_func, instr.address, 'x1')

				x2 = get_u_reg_value_at(ini_func, instr.address, 'x2')
				if x2 is None or x2 == 0:
					x2_resolved = resolve_reg_value(bv, ini_func, instr.address, 'x2')
					if x2_resolved is not None:
						x2 = x2_resolved

				x3 = get_u_reg_value_at(ini_func, instr.address, 'x3')

				className = bv.get_string_at(x1)
				if not className:
					# There are some zone_create_ext calls also inside
					continue
				
				n_cls = IClass(x0, x2, className.value, x3, bv)
				memo[x0] = n_cls
				n_cls.set_src(ptr, bv)
				reg.add(n_cls)
			
			elif instr.operation == LowLevelILOperation.LLIL_STORE:
				ops = instr.operands
				if len(ops) < 2:
					continue
				
				dst, src = ops[0], ops[1]
				
				if type(dst) is lowlevelil.LowLevelILReg:
					dst_v = reg_value(dst)	
					if dst_v in memo:
						# So it's a 'this' ptr we've seen!
						src_v = src.possible_values.value # type: ignore
						if src_v:
							src_v = unsigned(src_v)
							memo[dst_v].set_vtable(src_v)


def analyse_sections(bv: BinaryView, sel_section):
	for s_name in bv.sections:
		if sel_section in s_name:
			init_section = bv.get_section_by_name(s_name)
			if not init_section:
				print('Section not found.. Is this a kernelcache')
				return
			
			print(f'Found {s_name} at @{hex(init_section.start)}')
			for curr_addr in range(init_section.start, init_section.end, bv.address_size):
				ptr = bv.read_pointer(curr_addr)
				if ptr != 0x0:
					if not bv.get_function_at(ptr):
						print(f'Creating user function at @{hex(ptr)}')
						bv.create_user_function(ptr)
					analyse_static_initializer(bv, ptr)
	
def analyse_all(bv: BinaryView):
	analyse_sections(bv, '__mod_init_func')
	analyse_sections(bv, '__kmod_init')

	reg.add(BASE_ICLASS)
	reg.set_parents()
	reg.set_real_vtables(bv)
	reg.print_tree()
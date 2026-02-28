import json
from binaryninja import BinaryView
from weable.src.iclass import IClass, BASE_ICLASS


class ClassRegistry:
    def __init__(self):
        self._by_addr: dict[int, IClass] = {}
        self._by_name: dict[str, IClass] = {}
        
        # addrOf gClass -> name
        self._instance_to_class: dict[int, str] = {}

    # ── mut ───────────────────────────────────────────────────────

    def add(self, cls: IClass):
        if cls.this_addr in self._by_addr:
            return
        
        self._by_name[cls.name] = cls
        self._by_addr[cls.this_addr] = cls
        
        # TODO: rework a bit
        self._by_name[f'{cls.name}::MetaClass'] = cls
        self._instance_to_class[cls.this_addr] = f'{cls.name}::MetaClass'

    def add_instance(self, addr: int, name: str):
        assert addr not in self._instance_to_class

        self._instance_to_class[addr] = name

    def get_class(self, gAddr) -> str:
        return self._instance_to_class[gAddr]

    def all(self) -> list[IClass]:
        return list(self._by_addr.values())
    
    def all_gInstances(self) -> dict[int, str]:
        return self._instance_to_class

    def set_parents(self):
        bad_addrs = []
        for cls in self._by_addr.values():
            if cls.p_addr in self._by_addr:
                cls.set_parent(self._by_addr[cls.p_addr])
            else:
                bad_addrs.append(cls.this_addr)

        print(f"Bad classes count: {len(bad_addrs)}")
        for addr in bad_addrs:
            name = self._by_addr[addr].name
            del self._by_addr[addr]
            self._by_name.pop(name, None)

    def set_real_vtables(self, bv: BinaryView):
        for cls in self._by_addr.values():
            cls.set_this_vtable(bv)

    # ── req ───────────────────────────────────────────────────────

    def get_by_name(self, name: str) -> IClass | None:
        return self._by_name.get(name)

    def get_descendants(self, classname: str) -> list[IClass]:
        root = self._by_name.get(classname)
        if root is None:
            return []

        children_map = self._build_children_map()
        result: list[IClass] = []

        def _collect(node: IClass):
            for child in children_map.get(node.this_addr, []):
                result.append(child)
                _collect(child)

        _collect(root)
        return result

    def dump(self, path: str = "/tmp/registry.json"):
        entries = []
        for cls in self._by_name.values():
            parents = []
            if cls.parent:
                curr = cls.parent
                while curr.name != "OSNullClass":
                    parents.append(curr.name)
                    curr = curr.parent

            entries.append({
                "class_name": cls.name,
                "origin": cls.origin_kext,
                "parents": parents,
                "vtable_addr": cls.this_vtable_addr,
            })

        with open(path, "w") as fd:
            json.dump(entries, fd, indent=2)
        print(f"Dumped {len(entries)} classes to {path}")

    # ── private ───────────────────────────────────────────────────────

    def _build_children_map(self) -> dict[int, list[IClass]]:
        children: dict[int, list[IClass]] = {}
        for cls in self._by_addr.values():
            if cls.parent is None or cls.parent is BASE_ICLASS:
                continue
            children.setdefault(cls.parent.this_addr, []).append(cls)
        return children
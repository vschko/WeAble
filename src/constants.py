METACLASS_ALLOC_OFF = 0x68
EXT_METHOD_OFF = 0x540   # x1 -> sel
NEW_UC_OFF = 0x460       # x3 -> type

# func canaries
CANARY_IOTaskHasEntitlement = "com.apple.private.spawn-subsystem-root"
CANARY_CALLER_IOTaskHasEntitlement = "posix_spawn"
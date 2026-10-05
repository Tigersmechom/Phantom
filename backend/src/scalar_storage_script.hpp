#pragma once

#include <string_view>

namespace phantom::detail {
// Compiled trusted code. The caller appends only a validated numeric frame
// level and ASCII identifier. No parse_and_eval, gdb.Value arithmetic, cast,
// assignment, dynamic_type, indexing, pretty-printer or inferior call.
inline constexpr std::string_view scalarStorageScript = R"PY(
import gdb, json
def _phantom_scalar_storage(level, name, locator):
    result = dict(available=False, source='gdb-python-dwarf', locator=locator,
                  lifetime='unknown', reason=None, typeName=None,
                  scalar=None, addressHex=None)
    def reject(reason):
        result['reason'] = reason
    try:
        frame = gdb.newest_frame()
        for unused in range(level):
            if frame is None:
                break
            frame = frame.older()
        if frame is None:
            reject('frame-unavailable')
        elif frame.architecture().name() != 'i386:x86-64':
            reject('architecture-unsupported')
        # x86-64 has eight-bit bytes and native little-endian scalars. The
        # parameter check also rejects an explicit conflicting GDB setting,
        # without parsing localized human-readable `show endian` output.
        elif gdb.parameter('endian') not in ('auto', 'little'):
            reject('byte-order-unsupported')
        else:
            value = frame.read_var(name)
            original = value.type
            typ = original.strip_typedefs()
            # Type names are metadata, never a formatted inferior Value.
            label = original.name if original.name is not None else str(original)
            result['typeName'] = label.encode('utf-8')[:256].decode('utf-8', 'ignore')
            size = typ.sizeof
            code = typ.code
            if code not in (gdb.TYPE_CODE_INT, gdb.TYPE_CODE_CHAR, gdb.TYPE_CODE_BOOL, gdb.TYPE_CODE_FLT):
                reject('scalar-type-unsupported')
            elif size not in (1, 2, 4, 8) or (code == gdb.TYPE_CODE_BOOL and size != 1) or (code == gdb.TYPE_CODE_FLT and size not in (4, 8)):
                reject('scalar-size-unsupported')
            elif typ.dynamic:
                reject('dynamic-type-unsupported')
            elif typ != typ.unqualified():
                reject('qualified-type-unsupported')
            else:
                # unqualified() removes const/volatile but notably DOES NOT
                # remove _Atomic on GDB 15. An atomic int has INT code and
                # name "int". Require equality with a built-in keyword type,
                # not a spelling/size guess or a user-supplied type name.
                # This also excludes extended integers/floats, long double
                # (even with an eight-byte compiler ABI), and representations
                # outside this x86-64 profile. Matching FLT code and size alone
                # does not establish a supported binary32/binary64 type.
                builtins = ('float', 'double') if code == gdb.TYPE_CODE_FLT else (
                            'bool', 'char', 'signed char', 'unsigned char',
                            'short', 'unsigned short', 'int', 'unsigned int',
                            'long', 'unsigned long', 'long long',
                            'unsigned long long', 'wchar_t', 'char8_t',
                            'char16_t', 'char32_t')
                builtin = False
                for keyword in builtins:
                    try:
                        if typ == gdb.lookup_type(keyword) and (code != gdb.TYPE_CODE_FLT or
                                size == {'float': 4, 'double': 8}[keyword]):
                            builtin = True
                            break
                    except gdb.error:
                        pass
                if not builtin:
                    reject('scalar-representation-unsupported')
                elif code != gdb.TYPE_CODE_FLT and not hasattr(typ, 'is_signed'):
                    reject('signedness-unavailable')
                else:
                    if code == gdb.TYPE_CODE_FLT:
                        kind, signed = 'float', None
                        representation = 'ieee754-binary32' if size == 4 else 'ieee754-binary64'
                    elif code == gdb.TYPE_CODE_BOOL:
                        kind, signed, representation = 'boolean', None, 'boolean-01'
                    else:
                        kind, signed = 'integer', bool(typ.is_signed)
                        representation = 'twos-complement' if signed else 'unsigned-binary'
                    result['scalar'] = dict(kind=kind, byteSize=int(size), bits=int(size) * 8,
                                            signed=signed, byteOrder='little', representation=representation)
                    # Availability predicates can fetch lazy values. Only a
                    # supported scalar of at most eight bytes reaches them.
                    if value.is_optimized_out:
                        reject('optimized-out')
                    elif getattr(value, 'is_unavailable', False):
                        reject('value-unavailable')
                    else:
                        pointer = value.address
                        if pointer is None:
                            reject('not-addressable')
                        else:
                            candidate = int(pointer)
                            if candidate < 0 or candidate > (1 << 64) - 1 - size:
                                reject('address-range-unavailable')
                            else:
                                result['addressHex'] = hex(candidate)
                                result['available'] = True
    except Exception:
        # Debug names and GDB exception strings can be arbitrarily large.
        # Never return exception text or format the inferior's Value.
        result['available'] = False
        result['addressHex'] = None
        reject('debug-metadata-unavailable')
    gdb.write('PHANTOM_SCALAR_STORAGE_V1:' + json.dumps(result, ensure_ascii=True, separators=(',', ':')) + '\n')
)PY";
}  // namespace phantom::detail

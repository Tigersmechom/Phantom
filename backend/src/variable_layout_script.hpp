#pragma once

#include <string_view>

namespace phantom::detail {
// Compiled into the backend: never source a target-controlled Python file.
// The caller appends only a validated numeric frame level and ASCII identifier.
// This deliberately does not use parse_and_eval, dynamic_type, Value.__str__,
// Value arithmetic, indexing, casts, pretty-printers, or inferior calls.
inline constexpr std::string_view variableLayoutScript = R"PY(
import gdb, json
def _phantom_variable_layout(level, name, locator):
    limits = dict(maxDepth=8, maxNodes=128, maxFields=128, maxNameLength=256, maxResponseBytes=262144)
    result = dict(available=False, source='gdb-python-dwarf', locator=locator,
                  coverage='none', lifetime='unknown', bitOffsetConvention='gdb-target-bitpos',
                  storage=dict(available=False, addressHex=None, reason='location-unavailable'),
                  root=None, limits=limits, truncationReasons=[])
    state = dict(nodes=0, fields=0, partial=False)
    def truncated(reason):
        if reason not in result['truncationReasons']:
            result['truncationReasons'].append(reason)
    def label(value):
        if value is None:
            return None
        # Only Type names / Field names are passed here, never a gdb.Value.
        value = str(value)
        if len(value) > limits['maxNameLength']:
            truncated('name-limit')
            return value[:limits['maxNameLength']]
        return value
    def size_of(typ):
        try:
            size = typ.sizeof
            if size is None or size < 0 or size > 18446744073709551615:
                return None
            return int(size)
        except Exception:
            return None
    def type_name(typ):
        return label(typ.name if typ.name is not None else typ)
    def node(typ, address, address_reason, depth):
        if depth > limits['maxDepth']:
            truncated('depth-limit')
            return None
        if state['nodes'] >= limits['maxNodes']:
            truncated('node-limit')
            return None
        number = state['nodes']
        state['nodes'] += 1
        stripped = typ.strip_typedefs()
        code = stripped.code
        kind = {
            gdb.TYPE_CODE_STRUCT: 'struct', gdb.TYPE_CODE_UNION: 'union',
            gdb.TYPE_CODE_ARRAY: 'array', gdb.TYPE_CODE_PTR: 'pointer',
            gdb.TYPE_CODE_REF: 'reference', gdb.TYPE_CODE_RVALUE_REF: 'reference',
            gdb.TYPE_CODE_INT: 'integer', gdb.TYPE_CODE_CHAR: 'integer',
            gdb.TYPE_CODE_FLT: 'float', gdb.TYPE_CODE_ENUM: 'enum',
            gdb.TYPE_CODE_BOOL: 'boolean', gdb.TYPE_CODE_VOID: 'void',
            gdb.TYPE_CODE_FUNC: 'function', gdb.TYPE_CODE_METHOD: 'function'
        }.get(code, 'other')
        size = size_of(stripped)
        out = dict(id='node-' + str(number), kind=kind, typeName=type_name(typ),
                   byteSize=None if size is None else str(size),
                   addressHex=None if address is None else hex(address),
                   addressReason=address_reason if address is None else None)
        if kind in ('pointer', 'reference'):
            out['targetTypeName'] = type_name(stripped.target())
        elif kind == 'array':
            target = stripped.target()
            stride = size_of(target)
            lower, upper, count = None, None, None
            try:
                lo, hi = stripped.range()
                if isinstance(lo, int) and isinstance(hi, int) and -(1 << 63) <= lo <= hi + 1 < (1 << 64):
                    lower, upper, count = lo, hi, max(0, hi - lo + 1)
            except Exception:
                pass
            element_address = None
            if address is not None and size is not None and stride is not None and count is not None and count > 0 and stride * count <= size:
                element_address = address
            out['array'] = dict(lowerBound=None if lower is None else str(lower),
                                upperBound=None if upper is None else str(upper),
                                elementCount=None if count is None else str(count),
                                strideBytes=None if stride is None else str(stride),
                                elementLayout=node(target, element_address,
                                    'array-element-storage-not-proven', depth + 1))
            if count is None or stride is None:
                state['partial'] = True
        elif kind in ('struct', 'union'):
            out['fields'] = []
            # GDB materializes fields as a metadata list. Our traversal and
            # emitted representation are bounded; GDB's debug-info decoding
            # itself remains protected by the adapter's command deadline.
            for field in stripped.fields():
                if state['fields'] >= limits['maxFields']:
                    truncated('field-limit')
                    break
                state['fields'] += 1
                is_base = bool(field.is_base_class)
                has_position = hasattr(field, 'bitpos')
                position = field.bitpos if has_position else None
                bitsize = field.bitsize if hasattr(field, 'bitsize') else 0
                bitsize = int(bitsize) if isinstance(bitsize, int) and 0 <= bitsize <= (1 << 64) - 1 else 0
                # GDB Python does not identify virtual bases. Their bitpos
                # can misleadingly be zero, so ALL base offsets stay unknown.
                reason = 'base-offset-not-proven' if is_base else 'static-member' if not has_position else None
                if reason is not None or not isinstance(position, int) or position < 0 or position > (1 << 64) - 1:
                    position = None
                    reason = reason or 'dynamic-or-unavailable-offset'
                    state['partial'] = True
                child_size = size_of(field.type) if field.type is not None else None
                extent = bitsize if bitsize else None if child_size is None else child_size * 8
                if position is not None and (size is None or extent is None or position + extent > size * 8):
                    position = None
                    reason = 'field-bounds-not-proven'
                    state['partial'] = True
                field_address = None
                field_address_reason = reason or 'parent-storage-unavailable'
                if bitsize:
                    field_address_reason = 'bitfield-not-addressable'
                elif position is not None and position % 8:
                    field_address_reason = 'field-not-byte-aligned'
                elif address is not None and position is not None:
                    candidate = address + position // 8
                    if candidate <= (1 << 64) - 1 and (child_size is None or candidate + child_size <= (1 << 64)):
                        field_address = candidate
                item = dict(name=label(field.name), kind='base' if is_base else 'static' if not has_position else 'member',
                            artificial=bool(field.artificial),
                            bitOffset=None if position is None else str(position),
                            byteOffset=None if position is None else str(position // 8),
                            bitOffsetInByte=None if position is None else position % 8,
                            bitSize=str(bitsize) if bitsize else None,
                            offsetEvidence='dwarf' if position is not None else 'unknown',
                            reason=reason,
                            type=None if field.type is None else node(field.type, field_address, field_address_reason, depth + 1))
                out['fields'].append(item)
        return out
    try:
        frame = gdb.newest_frame()
        for unused in range(level):
            if frame is None:
                break
            frame = frame.older()
        if frame is None:
            result['reason'] = 'frame-unavailable'
        else:
            value = frame.read_var(name)
            reason = None
            address = None
            # Availability predicates can fetch lazy values in some GDB
            # versions. Layout inspection must not read an entire large
            # aggregate just to decide whether its bytes are readable.
            if not value.is_lazy and value.is_optimized_out:
                reason = 'optimized-out'
            elif not value.is_lazy and getattr(value, 'is_unavailable', False):
                reason = 'value-unavailable'
            elif value.type.strip_typedefs().code in (gdb.TYPE_CODE_REF, gdb.TYPE_CODE_RVALUE_REF):
                # Value.address for references denotes the REFERENT, not the
                # implementation's reference slot. Never mislabel that storage.
                reason = 'reference-storage-not-proven'
            else:
                try:
                    pointer = value.address
                    if pointer is None:
                        reason = 'not-addressable'
                    else:
                        candidate = int(pointer)
                        size = size_of(value.type)
                        if 0 <= candidate <= (1 << 64) - 1 and (size is None or candidate + size <= (1 << 64)):
                            address = candidate
                        else:
                            reason = 'address-range-unavailable'
                except Exception:
                    reason = 'location-unavailable'
            result['storage'] = dict(available=address is not None,
                                     addressHex=None if address is None else hex(address), reason=reason)
            result['root'] = node(value.type, address, reason, 0)
            result['available'] = result['root'] is not None
            result['coverage'] = 'truncated' if result['truncationReasons'] else 'partial' if state['partial'] else 'complete'
    except Exception:
        # GDB exception messages can contain arbitrarily large debug names;
        # return a fixed reason rather than serializing or formatting values.
        result['available'] = False
        result['root'] = None
        result['coverage'] = 'none'
        result['reason'] = 'debug-metadata-unavailable'
    text = json.dumps(result, ensure_ascii=True, separators=(',', ':'))
    if len(text) > limits['maxResponseBytes']:
        result['available'] = False
        result['root'] = None
        result['coverage'] = 'truncated'
        result['reason'] = 'response-limit'
        truncated('response-limit')
        text = json.dumps(result, ensure_ascii=True, separators=(',', ':'))
    gdb.write('PHANTOM_VARIABLE_LAYOUT_V1:' + text + '\n')
)PY";
}  // namespace phantom::detail

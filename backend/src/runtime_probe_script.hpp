#pragma once

#include <string_view>

namespace phantom {

// Trusted input to an isolated GDB process. The launcher supplies only the
// backend-owned fixture path; no user expressions, code, or syscall arguments
// are interpolated into this script.
inline constexpr std::string_view runtimeProbeScript = R"GDB(set pagination off
set confirm off
set startup-with-shell off
set debuginfod enabled off
set may-call-functions off
python
import gdb
import json
import os
import signal

MASK64 = (1 << 64) - 1
CONTEXT = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
           'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
           'eflags', 'orig_rax', 'fs_base', 'gs_base', 'rip']
stops = []
gdb.events.stop.connect(lambda event: stops.append(event))

def require(condition, message):
    if not condition:
        raise RuntimeError('runtime probe: ' + message)

def integer(expression):
    return int(gdb.parse_and_eval(expression))

def reg(name):
    return int(gdb.selected_frame().read_register(name)) & MASK64

def set_reg(name, value):
    require(name in CONTEXT, 'unexpected register write')
    gdb.execute('set $%s = 0x%x' % (name, value & MASK64), to_string=True)

gdb.execute('handle all stop print nopass', to_string=True)
gdb.execute('handle SIGINT stop print nopass', to_string=True)
gdb.execute('handle SIGTRAP stop print nopass', to_string=True)
entry_breakpoint = gdb.Breakpoint('*phantom_runtime_probe_entry', internal=True)
gdb.execute('run', to_string=True)
require(len(stops) == 1 and isinstance(stops[0], gdb.BreakpointEvent) and
        entry_breakpoint in stops[0].breakpoints, 'unexpected entry stop')
entry_breakpoint.delete()
inferior = gdb.selected_inferior()
pid = inferior.pid
require(pid > 0 and len(inferior.threads()) == 1, 'expected one live thread')
require(gdb.selected_frame().architecture().name() == 'i386:x86-64',
        'unsupported architecture')
require(gdb.lookup_type('void').pointer().sizeof == 8, 'unsupported pointer size')
require(reg('orig_rax') == MASK64, 'entry has pending syscall state')
page_size = integer('phantom_runtime_probe_page_size')
require(4096 <= page_size <= 1048576 and page_size & (page_size - 1) == 0,
        'unsupported page size')
site = integer('&phantom_runtime_probe_syscall')
entry = integer('&phantom_runtime_probe_entry')
errno_address = integer('phantom_runtime_probe_errno_address')
errno_size = gdb.lookup_type('int').sizeof
require(errno_address > 0 and errno_size == 4, 'invalid errno location')
require(reg('rip') == entry, 'entry PC mismatch')

def memory(address, size):
    return bytes(inferior.read_memory(address, size))

def proc_text(name):
    with open('/proc/%d/%s' % (pid, name), 'r', encoding='utf-8',
              errors='surrogateescape') as stream:
        text = stream.read(1048577)
    require(len(text) <= 1048576, 'proc data exceeds limit')
    return text

def mappings():
    rows = []
    for line in proc_text('maps').splitlines():
        fields = line.split(None, 5)
        lo, hi = (int(value, 16) for value in fields[0].split('-'))
        require(0 <= lo < hi <= MASK64 and len(fields[1]) == 4,
                'invalid process mapping')
        rows.append((lo, hi, fields[1], fields[5] if len(fields) == 6 else ''))
    require(0 < len(rows) <= 4096, 'invalid mapping count')
    return rows

def signal_mask():
    values = [line.split(':', 1)[1].strip()
              for line in proc_text('status').splitlines()
              if line.startswith('SigBlk:')]
    require(len(values) == 1 and len(values[0]) == 16,
            'invalid signal mask')
    return int(values[0], 16)

initial_maps = proc_text('maps')
stack_maps = [item for item in mappings() if item[3] == '[stack]']
require(len(stack_maps) == 1, 'expected one stack mapping')
stack_start, stack_end, stack_permissions, _ = stack_maps[0]
stack_size = stack_end - stack_start
require(4096 <= stack_size <= 1048576 and stack_permissions == 'rw-p',
        'unsupported stack mapping')
require(stack_start <= reg('rsp') < stack_end, 'stack pointer outside mapping')
original_stack = memory(stack_start, stack_size)
original_errno = memory(errno_address, errno_size)
require(int.from_bytes(original_errno, 'little', signed=True) == 123,
        'fixture errno marker missing')
original_mask = signal_mask()
original_site = memory(site, 3)
original_entry = memory(entry, 1)
require(original_site == b'\x0f\x05\xcc' and original_entry == b'\x90',
        'trusted instruction bytes mismatch')

def registers():
    frame = gdb.selected_frame()
    names = {descriptor.name for descriptor in frame.architecture().registers()}
    names.update(CONTEXT)
    require(32 <= len(names) <= 512, 'invalid register count')
    values = {}
    # Value.bytes provides exact little-endian bytes, including FP/vector
    # values. Unsupported/unavailable registers fail the probe rather than
    # silently weakening the restoration assertion to formatted strings.
    for name in sorted(names):
        raw = bytes(frame.read_register(name).bytes)
        require(0 < len(raw) <= 1024, 'invalid register width')
        values[name] = raw
    require(sum(len(value) for value in values.values()) <= 65536,
            'register data exceeds limit')
    require('st0' in values and 'mxcsr' in values and
            any(name in values for name in ['xmm0', 'ymm0', 'zmm0']),
            'FP/vector register evidence unavailable')
    return values

original_registers = registers()
original_context = {name: reg(name) for name in CONTEXT}

def verify_and_restore():
    require(len(inferior.threads()) == 1 and inferior.pid == pid,
            'process/thread identity changed')
    for name in CONTEXT:
        if reg(name) != original_context[name]:
            set_reg(name, original_context[name])
    require(registers() == original_registers, 'register restoration mismatch')
    require(memory(stack_start, stack_size) == original_stack, 'stack changed')
    require(memory(errno_address, errno_size) == original_errno, 'errno changed')
    require(signal_mask() == original_mask, 'signal mask changed')
    require(memory(site, 3) == original_site and
            memory(entry, 1) == original_entry, 'trusted code changed')
    require(integer('phantom_runtime_probe_signal_count') == 0,
            'signal handler unexpectedly executed')

def one_instruction(expected_pc):
    stops.clear()
    gdb.execute('stepi', to_string=True)
    require(len(stops) == 1 and not isinstance(stops[0],
            (gdb.SignalEvent, gdb.BreakpointEvent)), 'unexpected instruction stop')
    require(reg('rip') == expected_pc, 'unexpected instruction PC')

def syscall(number, arguments):
    require(len(arguments) <= 6, 'too many syscall arguments')
    set_reg('rax', number)
    for name, value in zip(['rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9'], arguments):
        set_reg(name, value)
    set_reg('rip', site)
    one_instruction(site + 2)
    result = reg('rax')
    verify_and_restore()
    return result

def scratch_permissions(address, permissions):
    covering = [item for item in mappings()
                if item[0] <= address and address + page_size <= item[1]]
    require(len(covering) == 1 and covering[0][2] == permissions,
            'scratch mapping permissions mismatch')

# A pending signal must stop before the helper instruction; executing an
# inferior signal handler would invalidate the stack/state guarantee.
set_reg('rax', 39)
set_reg('rip', site)
os.kill(pid, signal.SIGUSR1)
stops.clear()
gdb.execute('stepi', to_string=True)
require(len(stops) == 1 and isinstance(stops[0], gdb.SignalEvent) and
        stops[0].stop_signal == 'SIGUSR1' and reg('rip') == site,
        'pending signal was not intercepted before helper execution')
verify_and_restore()

require(syscall(39, []) == pid, 'getpid result mismatch')
scratch = syscall(9, [0, page_size, 3, 0x22, MASK64, 0])
require(0 < scratch < (1 << 63) and scratch % page_size == 0 and
        scratch + page_size <= MASK64, 'mmap failed')
scratch_permissions(scratch, 'rw-p')
require(not any(lo < scratch + page_size and scratch < hi
                for lo, hi, _, _ in stack_maps), 'scratch overlaps stack')

# Fixed, bounded machine code only: movabs $0x5048414e544f4d31,%rax; int3.
# Single-stepping movabs proves instruction fetch from RX memory without any
# call/return, user stack write, shadow-stack change, or arbitrary code input.
payload_value = 0x5048414e544f4d31
payload = b'\x48\xb8' + payload_value.to_bytes(8, 'little') + b'\xcc'
inferior.write_memory(scratch, payload)
require(memory(scratch, len(payload)) == payload, 'scratch write mismatch')
verify_and_restore()
require(syscall(10, [scratch + 1, page_size, 5]) == ((-22) & MASK64),
        'unaligned mprotect did not return EINVAL')
scratch_permissions(scratch, 'rw-p')
require(syscall(10, [scratch, page_size, 5]) == 0, 'mprotect RX failed')
scratch_permissions(scratch, 'r-xp')
require(memory(scratch, len(payload)) == payload, 'RX payload changed')
set_reg('rip', scratch)
one_instruction(scratch + 10)
require(reg('rax') == payload_value, 'fixed payload result mismatch')
verify_and_restore()
require(memory(scratch, len(payload)) == payload, 'executed payload changed')
require(syscall(11, [scratch, page_size]) == 0, 'munmap failed')
require(not any(lo < scratch + page_size and scratch < hi
                for lo, hi, _, _ in mappings()), 'scratch mapping remained')
require(proc_text('maps') == initial_maps, 'original mapping layout changed')
verify_and_restore()

evidence = {
    'profile': 'linux-x86_64-syscall-probe-v1',
    'pid': pid, 'pageSize': page_size, 'scratchAddressHex': hex(scratch),
    'getpid': True, 'allocated': True, 'writable': True, 'executable': True,
    'payloadExecuted': True, 'released': True, 'deniedSyscall': True,
    'registersRestored': True, 'stackUnchanged': True, 'errnoUnchanged': True,
    'signalMaskUnchanged': True, 'codeUnchanged': True,
    'signalStopVerified': True, 'handlerNotRun': True,
    'registerCount': len(original_registers), 'stackBytes': stack_size
}
# Successful restoration must also permit the fixture to finish normally.
exits = []
gdb.events.exited.connect(lambda event: exits.append(event))
stops.clear()
gdb.execute('continue', to_string=True)
require(len(exits) == 1 and getattr(exits[0], 'exit_code', None) == 0,
        'fixture did not exit normally after restoration')
print('PHANTOM_RUNTIME_PROBE_V1:' + json.dumps(evidence, separators=(',', ':')))
end
quit
)GDB";

} // namespace phantom

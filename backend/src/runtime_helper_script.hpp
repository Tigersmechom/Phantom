#pragma once

#include <string_view>

namespace phantom {

// Trusted script only. Preparation never assigns inferior state or calls it.
// Execution is a deliberately separate MI command with a recorded mutation
// boundary. Any exception is handled by terminating the owned debugger and
// inferior in C++; this script never resumes after an unexpected signal.
inline constexpr std::string_view runtimeHelperScript = R"PY(
import gdb
import json
import os
import re

_phantom_runtime_helper_ctx = None
_phantom_runtime_helper_regs = ['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp',
    'r8','r9','r10','r11','r12','r13','r14','r15','eflags','orig_rax','fs_base','gs_base','rip']
_phantom_runtime_helper_mask = (1 << 64) - 1

def _phantom_runtime_helper_require(condition, message):
    if not condition:
        raise RuntimeError('runtime helper: ' + message)

def _phantom_runtime_helper_proc(pid, name):
    with open('/proc/%d/%s' % (pid,name), 'r', encoding='utf-8', errors='surrogateescape') as stream:
        result = stream.read(1048577)
    _phantom_runtime_helper_require(len(result) <= 1048576, 'proc data exceeds limit')
    return result

def _phantom_runtime_helper_status(pid):
    result = {}
    for line in _phantom_runtime_helper_proc(pid,'status').splitlines():
        key, _, value = line.partition(':')
        if key in ['SigBlk','SigPnd','ShdPnd']:
            value = value.strip()
            _phantom_runtime_helper_require(re.fullmatch('[0-9a-fA-F]{16}',value) is not None,
                                            'invalid signal status')
            result[key] = int(value,16)
    _phantom_runtime_helper_require(len(result) == 3, 'signal status unavailable')
    return result

def _phantom_runtime_helper_personality(pid):
    value = _phantom_runtime_helper_proc(pid,'personality').strip()
    _phantom_runtime_helper_require(re.fullmatch('[0-9a-fA-F]{8}',value) is not None,
                                    'personality metadata unavailable')
    return int(value,16)

def _phantom_runtime_helper_maps(pid):
    result = []
    for line in _phantom_runtime_helper_proc(pid,'maps').splitlines():
        fields = line.split(None,5)
        lo, hi = (int(value,16) for value in fields[0].split('-'))
        _phantom_runtime_helper_require(0 <= lo < hi <= _phantom_runtime_helper_mask and
            re.fullmatch('[r-][w-][x-][ps]',fields[1]) is not None, 'invalid mapping')
        result.append((lo,hi,fields[1],fields[5] if len(fields)==6 else ''))
    _phantom_runtime_helper_require(0 < len(result) <= 4096, 'mapping count exceeds limit')
    return result

def _phantom_runtime_helper_policies():
    text = gdb.execute('info signals',to_string=True)
    _phantom_runtime_helper_require(len(text) <= 65536, 'signal policy exceeds limit')
    result = {}
    for line in text.splitlines():
        if not line.startswith('SIG'):
            continue
        fields = line.split()
        _phantom_runtime_helper_require(len(fields) >= 4 and
            re.fullmatch('SIG[A-Z0-9+-]+',fields[0]) is not None and
            all(value in ['Yes','No'] for value in fields[1:4]) and
            fields[0] not in result, 'unsupported signal policy format')
        result[fields[0]] = tuple(value == 'Yes' for value in fields[1:4])
    _phantom_runtime_helper_require(32 <= len(result) <= 256 and
        all(name in result for name in ['SIGINT','SIGTRAP','SIGALRM','SIGUSR1','SIGSEGV','SIGSYS']),
        'signal policy unavailable')
    return result

def _phantom_runtime_helper_registers():
    frame = gdb.selected_frame()
    names = {descriptor.name for descriptor in frame.architecture().registers()}
    names.update(_phantom_runtime_helper_regs)
    _phantom_runtime_helper_require(32 <= len(names) <= 512, 'unsupported register count')
    result = {}
    for name in sorted(names):
        raw = bytes(frame.read_register(name).bytes)
        _phantom_runtime_helper_require(0 < len(raw) <= 1024, 'unsupported register width')
        result[name] = raw
    _phantom_runtime_helper_require(sum(map(len,result.values())) <= 65536 and
        'st0' in result and 'mxcsr' in result and
        any(name in result for name in ['xmm0','ymm0','zmm0']), 'FP/vector evidence unavailable')
    return result

def _phantom_runtime_helper_reg(name):
    return int(gdb.selected_frame().read_register(name)) & _phantom_runtime_helper_mask

def _phantom_runtime_helper_set(name,value):
    _phantom_runtime_helper_require(name in _phantom_runtime_helper_regs, 'unexpected register write')
    gdb.execute('set $%s = 0x%x' % (name,value & _phantom_runtime_helper_mask),to_string=True)

def _phantom_runtime_helper_prepare(manifest,pid,thread,action='scratch',address=0,byte_count=0,
                                    expected_permissions='rw-',replacement_permissions=''):
    global _phantom_runtime_helper_ctx
    _phantom_runtime_helper_ctx = None
    inferior = gdb.selected_inferior()
    require = _phantom_runtime_helper_require
    require(inferior.pid == pid and len(inferior.threads()) == 1 and
        str(gdb.selected_thread().global_num) == thread and gdb.selected_thread().is_stopped(),
        'process/thread identity mismatch')
    require(gdb.selected_frame().level() == 0 and
        gdb.selected_frame().architecture().name() == 'i386:x86-64' and
        gdb.lookup_type('void').pointer().sizeof == 8, 'unsupported ABI')
    require(_phantom_runtime_helper_reg('orig_rax') == _phantom_runtime_helper_mask,
            'pending syscall/restart state')
    status = _phantom_runtime_helper_status(pid)
    require(status['SigPnd'] == 0 and status['ShdPnd'] == 0, 'pending signal')
    require(action in ['scratch','allocate','release','protect'], 'unsupported runtime action')
    personality = _phantom_runtime_helper_personality(pid)
    # READ_IMPLIES_EXEC can silently turn even an initial RW mmap into RWX.
    # Reject before any mutation; release alone never adds access rights.
    require(action == 'release' or personality & 0x00400000 == 0,
            'READ_IMPLIES_EXEC is unsupported for runtime mapping/protection')
    maps = _phantom_runtime_helper_maps(pid)
    site = int(manifest['addressHex'],16)
    require(any(lo <= site and site+3 <= hi and permissions == 'r-xp'
                for lo,hi,permissions,_ in maps), 'helper site is not private RX')
    code = bytes(inferior.read_memory(site,3))
    require(code.hex() == manifest['bytesHex'], 'helper instructions changed')
    stacks = [item for item in maps if item[3] == '[stack]']
    require(len(stacks) == 1, 'expected one main stack mapping')
    low,high,permissions,_ = stacks[0]
    require(4096 <= high-low <= 1048576 and permissions == 'rw-p' and
            low <= _phantom_runtime_helper_reg('rsp') < high, 'unsupported stack mapping')
    # Require actual glibc DWARF TLS metadata. A local variable named errno,
    # unknown libc, missing debug symbols or ambiguous lookup is unsupported.
    # The global lookup can choose an unresolved errno declaration in libm
    # before libc's defining TLS symbol. Restrict lookup to the unique actual
    # libc objfile (its separate DWARF file is linked through owner).
    libraries = [objfile for objfile in gdb.objfiles()
        if objfile.owner is None and os.path.basename(objfile.filename) == 'libc.so.6']
    require(len(libraries) == 1, 'unique glibc object unavailable')
    symbol = libraries[0].lookup_global_symbol('errno')
    require(symbol is not None and symbol.is_variable and symbol.symtab is not None,
            'glibc errno symbol unavailable')
    owner = symbol.symtab.objfile
    if owner.owner is not None:
        owner = owner.owner
    require(owner == libraries[0] and symbol.addr_class == gdb.SYMBOL_LOC_COMPUTED and
        symbol.type.strip_typedefs().code == gdb.TYPE_CODE_INT and symbol.type.sizeof == 4,
        'unverified glibc errno metadata')
    # LOC_COMPUTED alone also describes non-TLS DWARF expressions. Require
    # GDB's read-only TLS description to identify this same defining objfile;
    # never invoke __errno_location or infer TLS from the source filename.
    tls_description = gdb.execute('info address errno',to_string=True)
    require(len(tls_description) <= 4096, 'errno metadata exceeds limit')
    tls_match = re.fullmatch(r'''Symbol "errno" is a thread-local variable at offset (0x[0-9a-f]+) in the thread-local storage for `([^'\n]+)'\.\n?''',
                            tls_description)
    require(tls_match is not None and int(tls_match.group(1),16) < 1 << 63 and
        tls_match.group(2) in [symbol.symtab.objfile.filename,libraries[0].filename],
        'glibc errno TLS identity unavailable')
    errno_pointer = symbol.value().address
    require(errno_pointer is not None, 'errno is not addressable')
    errno_address = int(errno_pointer)
    require(any(lo <= errno_address and errno_address+4 <= hi and permissions == 'rw-p'
                for lo,hi,permissions,_ in maps), 'errno is not readable private storage')
    page_size = os.sysconf('SC_PAGESIZE')
    require(4096 <= page_size <= 1048576 and page_size & (page_size-1) == 0,
            'unsupported page size')
    require(type(address) is int and type(byte_count) is int,
            'unsupported runtime action')
    require(expected_permissions in ['r--','rw-','r-x'] and
        (action != 'protect' or replacement_permissions in ['r--','rw-','r-x']),
        'unsupported runtime permissions')
    if action == 'scratch':
        require(address == 0 and byte_count == 0, 'unexpected scratch arguments')
    elif action == 'allocate':
        require(address == 0 and 1 <= byte_count <= 65536, 'invalid allocation size')
        byte_count = ((byte_count+page_size-1)//page_size)*page_size
        require(byte_count <= 1048576, 'allocation exceeds mapped size limit')
    else:
        require(0 < address < 1 << 63 and address % page_size == 0 and
            1 <= byte_count <= 1048576 and byte_count % page_size == 0 and
            address+byte_count <= 1 << 63, 'invalid owned range')
    target_bytes = bytes(inferior.read_memory(address,byte_count)) if action == 'protect' else None
    registers = _phantom_runtime_helper_registers()
    policies = _phantom_runtime_helper_policies()
    _phantom_runtime_helper_ctx = {
        'inferior':inferior,'pid':pid,'thread':thread,'site':site,'code':code,'pageSize':page_size,
        'action':action,'address':address,'byteCount':byte_count,
        'expectedPermissions':expected_permissions,'replacementPermissions':replacement_permissions,
        'targetBytes':target_bytes,'personality':personality,
        'maps':_phantom_runtime_helper_proc(pid,'maps'),'stackStart':low,
        'stack':bytes(inferior.read_memory(low,high-low)),
        'errnoAddress':errno_address,'errno':bytes(inferior.read_memory(errno_address,4)),
        'mask':status['SigBlk'],'registers':registers,'policies':policies,
        'context':{name:_phantom_runtime_helper_reg(name) for name in _phantom_runtime_helper_regs}}
    print('PHANTOM_RUNTIME_HELPER_PREPARED_V1:' + json.dumps({
        'ready':True,'pid':pid,'threadId':thread,'siteAddressHex':hex(site),
        'registerCount':len(registers),'stackBytes':high-low},separators=(',',':')))

def _phantom_runtime_helper_execute_operation(expected_actions):
    global _phantom_runtime_helper_ctx
    context = _phantom_runtime_helper_ctx
    require = _phantom_runtime_helper_require
    require(context is not None, 'prepared state unavailable')
    require(context['action'] in expected_actions, 'prepared action mismatch')
    inferior = context['inferior']
    stops = []
    def on_stop(event):
        stops.append(event)
    gdb.events.stop.connect(on_stop)
    try:
        def verify():
            require(inferior.pid == context['pid'] and len(inferior.threads()) == 1 and
                str(gdb.selected_thread().global_num) == context['thread'] and
                gdb.selected_thread().is_stopped(), 'process/thread identity changed')
            require(_phantom_runtime_helper_registers() == context['registers'], 'register restoration mismatch')
            require(bytes(inferior.read_memory(context['stackStart'],len(context['stack']))) == context['stack'],
                    'original stack changed')
            require(bytes(inferior.read_memory(context['errnoAddress'],4)) == context['errno'], 'errno changed')
            require(_phantom_runtime_helper_status(context['pid'])['SigBlk'] == context['mask'], 'signal mask changed')
            require(_phantom_runtime_helper_personality(context['pid']) == context['personality'], 'personality changed')
            require(bytes(inferior.read_memory(context['site'],3)) == context['code'], 'helper instructions changed')
            if context['targetBytes'] is not None:
                require(bytes(inferior.read_memory(context['address'],context['byteCount'])) == context['targetBytes'],
                        'owned allocation bytes changed')
        def restore():
            for name in _phantom_runtime_helper_regs:
                if _phantom_runtime_helper_reg(name) != context['context'][name]:
                    _phantom_runtime_helper_set(name,context['context'][name])
            verify()
        def step(expected_pc):
            stops.clear()
            gdb.execute('stepi',to_string=True)
            if len(stops) == 1 and isinstance(stops[0],gdb.SignalEvent):
                raise RuntimeError('runtime helper: unexpected signal '+stops[0].stop_signal)
            require(len(stops) == 1 and not isinstance(stops[0],gdb.BreakpointEvent) and
                _phantom_runtime_helper_reg('rip') == expected_pc, 'unexpected instruction stop')
        def syscall(number,arguments):
            _phantom_runtime_helper_set('rax',number)
            for name,value in zip(['rdi','rsi','rdx','r10','r8','r9'],arguments):
                _phantom_runtime_helper_set(name,value)
            _phantom_runtime_helper_set('rip',context['site'])
            step(context['site']+2)
            result = _phantom_runtime_helper_reg('rax')
            restore()
            return result
        def permissions(address,expected,count=None):
            if count is None:
                count = context['pageSize']
            require(any(lo <= address and address+count <= hi and mode == expected
                for lo,hi,mode,_ in _phantom_runtime_helper_maps(context['pid'])), 'scratch permission mismatch')

        verify()
        status = _phantom_runtime_helper_status(context['pid'])
        require(status['SigPnd'] == 0 and status['ShdPnd'] == 0, 'pending signal after preparation')
        require(_phantom_runtime_helper_proc(context['pid'],'maps') == context['maps'] and
            _phantom_runtime_helper_policies() == context['policies'], 'state changed after preparation')
        gdb.execute('handle all stop print nopass',to_string=True)
        gdb.execute('handle SIGINT stop print nopass',to_string=True)
        gdb.execute('handle SIGTRAP stop print nopass',to_string=True)
        guarded = _phantom_runtime_helper_policies()
        require(set(guarded) == set(context['policies']) and
            all(stop and printed and not passed for name,(stop,printed,passed) in guarded.items()
                if name not in ['SIGKILL','SIGSTOP']), 'signal guard policy mismatch')
        require(syscall(39,[]) == context['pid'], 'getpid mismatch')
        action = context['action']
        if action == 'scratch':
            scratch = syscall(9,[0,context['pageSize'],3,0x22,_phantom_runtime_helper_mask,0])
            require(0 < scratch < 1 << 63 and scratch % context['pageSize'] == 0, 'mmap failed')
            permissions(scratch,'rw-p')
            payload_value = 0x5048414e544f4d31
            payload = b'\x48\xb8' + payload_value.to_bytes(8,'little') + b'\xcc'
            inferior.write_memory(scratch,payload)
            require(bytes(inferior.read_memory(scratch,len(payload))) == payload, 'scratch write mismatch')
            verify()
            require(syscall(10,[scratch,context['pageSize'],5]) == 0, 'mprotect RX failed')
            permissions(scratch,'r-xp')
            require(bytes(inferior.read_memory(scratch,len(payload))) == payload, 'RX payload changed')
            _phantom_runtime_helper_set('rip',scratch)
            step(scratch+10)
            require(_phantom_runtime_helper_reg('rax') == payload_value, 'payload result mismatch')
            restore()
            require(bytes(inferior.read_memory(scratch,len(payload))) == payload, 'payload changed')
            require(syscall(11,[scratch,context['pageSize']]) == 0, 'munmap failed')
            require(_phantom_runtime_helper_proc(context['pid'],'maps') == context['maps'], 'mapping restoration mismatch')
        elif action == 'allocate':
            scratch = syscall(9,[0,context['byteCount'],3,0x22,_phantom_runtime_helper_mask,0])
            require(0 < scratch < 1 << 63 and scratch % context['pageSize'] == 0 and
                scratch+context['byteCount'] <= 1 << 63, 'mmap failed')
            permissions(scratch,'rw-p',context['byteCount'])
            require(bytes(inferior.read_memory(scratch,context['byteCount'])) == bytes(context['byteCount']),
                    'anonymous allocation is not zero initialized')
        elif action == 'release':
            scratch = context['address']
            require(syscall(11,[scratch,context['byteCount']]) == 0, 'munmap failed')
        else:
            scratch = context['address']
            protection = {'r--':1,'rw-':3,'r-x':5}[context['replacementPermissions']]
            require(syscall(10,[scratch,context['byteCount'],protection]) == 0, 'mprotect failed')
            permissions(scratch,context['replacementPermissions']+'p',context['byteCount'])
        for name,(stopped,printed,passed) in context['policies'].items():
            # Restore stop before print: noprint implies nostop in GDB. Valid
            # policy combinations are rechecked as a complete table below.
            command = 'handle %s %s %s %s' % (name,'stop' if stopped else 'nostop',
                'print' if printed else 'noprint','pass' if passed else 'nopass')
            gdb.execute(command,to_string=True)
        require(_phantom_runtime_helper_policies() == context['policies'], 'signal policy restoration mismatch')
        verify()
        evidence = {
            'pid':context['pid'],'pageSize':context['pageSize'],
            'registerCount':len(context['registers']),'stackBytes':len(context['stack']),
            'getpid':True,'registersRestored':True,'stackUnchanged':True,'errnoUnchanged':True,
            'signalMaskUnchanged':True,'signalPolicyRestored':True,'codeUnchanged':True}
        if action == 'scratch':
            prefix = 'PHANTOM_RUNTIME_HELPER_RESULT_V1:'
            evidence.update({'scratchAddressHex':hex(scratch),'allocated':True,'writable':True,
                'executable':True,'payloadExecuted':True,'released':True,'mapsRestored':True})
        elif action == 'protect':
            prefix = 'PHANTOM_RUNTIME_PROTECTION_RESULT_V1:'
            evidence.update({'addressHex':hex(scratch),'byteCount':context['byteCount'],
                'beforePermissions':context['expectedPermissions'],'afterPermissions':context['replacementPermissions'],
                'protectionApplied':True,'bytesUnchanged':True})
        else:
            prefix = 'PHANTOM_RUNTIME_ALLOCATION_RESULT_V1:'
            evidence.update({'addressHex':hex(scratch),'byteCount':context['byteCount'],
                'allocated':action == 'allocate','released':action == 'release','zeroInitialized':action == 'allocate'})
        print(prefix + json.dumps(evidence,separators=(',',':')))
    finally:
        # Never execute cleanup instructions after an unexpected signal. C++
        # closes the debugger/inferior on failure, with the attempt in audit.
        gdb.events.stop.disconnect(on_stop)
        _phantom_runtime_helper_ctx = None

def _phantom_runtime_helper_execute():
    _phantom_runtime_helper_execute_operation(('scratch',))

def _phantom_runtime_allocation_execute():
    _phantom_runtime_helper_execute_operation(('allocate','release'))

def _phantom_runtime_protection_execute():
    _phantom_runtime_helper_execute_operation(('protect',))
)PY";

} // namespace phantom

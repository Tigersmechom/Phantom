"""Real-process inspection, immutable memory comparisons and instruction traces."""
from __future__ import annotations
import base64
import hashlib
import shutil
import sys
import tempfile
from pathlib import Path
from service_integration import Client as TransportClient

TRAFFIC: list[tuple[str, dict]] = []
SOURCE = r'''#include <sys/mman.h>
#include <unistd.h>
int main() {
  write(1, "kept\n", 5);
  volatile unsigned long cell = 0;
  asm volatile("nop\n\tmovq $1,%0\n\tmovq $2,%0\n\tmovq $0,%0\n\tnop" : "+m"(cell) : : "memory"); // TRACE
  cell = 7; // AFTER_TRACE
  const auto page = static_cast<unsigned long>(sysconf(_SC_PAGESIZE));
  void* arena = mmap(nullptr, 3*page, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if (arena == MAP_FAILED) return 91;
  auto* middle = static_cast<unsigned char*>(arena) + page;
  if (mprotect(middle,page,PROT_READ|PROT_WRITE)) return 92;
  middle[0] = 0xa7;
  asm volatile("nop" : : "r"(cell) : "memory"); // MAPPED
  if (mprotect(middle,page,PROT_NONE)) return 93;
  asm volatile("nop" : : "r"(cell) : "memory"); // PROTECTED
  if (munmap(arena,3*page)) return 94;
  asm volatile("nop" : : "r"(cell) : "memory"); // UNMAPPED
  return 0;
}
'''
LIVE = {'step','continue','readMemory','readRegisters','inspectProcess','captureMemory','traceInstructions'}

class Client(TransportClient):
    def __init__(self, executable, workspace):
        super().__init__(executable,workspace)
        self.record_requests = True
        result=self.send({'kind':'connect','supportedProtocolVersions':[1]})
        assert result['ok'],result
        self.workspace=result['workspace']; self.session=None; self.observation=None; self.counter=0
    def send(self,frame):
        if self.record_requests: TRAFFIC.append(('request',frame))
        return super().send(frame)
    def recv(self):
        frame=super().recv(); TRAFFIC.append(('received',frame)); return frame
    def frame(self,command):
        self.counter+=1
        frame={'protocolVersion':1,'requestId':f'advanced-{self.counter}',
               'workspace':self.workspace,'session':self.session,'command':command}
        if command['kind'] in LIVE: frame['expectedStop']=self.observation['stop']
        return frame
    def query(self,command): return self.send(self.frame(command))
    def good(self,command):
        response=self.query(command); assert response['ok'],response; return response['result']
    def execute(self,command):
        frame=self.frame(command); result=self.send(frame); assert result['ok'],result
        if command['kind']=='launch': self.session=result['session']
        events=[]
        while True:
            event=self.recv(); events.append(event)
            assert event.get('causedByRequestId')==frame['requestId'],event
            payload=event['payload']
            if payload['kind']=='observation': self.observation=payload['observation']
            if payload['kind']=='commandFinished': return events
    def launch(self,artifact):
        events=self.execute({'kind':'launch','buildId':artifact['id'],
            'input':{'id':'advanced-input','text':'','encoding':'utf-8','closeAfterWrite':False},
            'argv':[],'environment':{},'stopAtEntry':True,'addressPolicy':'disable-aslr'})
        assert events[-1]['payload']['outcome']=='completed',events
    def bad(self,command,codes=('INVALID_REQUEST','LIMIT_EXCEEDED')):
        self.record_requests=False
        try: result=self.query(command)
        finally: self.record_requests=True
        assert not result['ok'] and result['error']['code'] in codes,result
        return result

def location(marker):
    line=next(i for i,s in enumerate(SOURCE.splitlines(),1) if s.endswith('// '+marker))
    offset=sum(len(s)+1 for s in SOURCE.splitlines()[:line-1])
    return {'documentId':'advanced','revisionId':'advanced-1','range':{'start':offset,'end':offset},
            'start':{'line':line,'column':1},'end':{'line':line,'column':1}}

def variable(observation,name):
    return next(v for v in observation['stack'][0]['variables'] if v['name']==name)

def main():
    if len(sys.argv)!=2: return 2
    if not sys.platform.startswith('linux') or not shutil.which('gdb') or not shutil.which('clang++'): return 77
    with tempfile.TemporaryDirectory(prefix='phantom-advanced-') as directory:
        client=Client(sys.argv[1],Path(directory))
        try:
            artifact=client.good({'kind':'build','source':{'id':'advanced-source','documents':[{
                'documentId':'advanced','revisionId':'advanced-1','path':'advanced.cpp','text':SOURCE,
                'sha256':hashlib.sha256(SOURCE.encode()).hexdigest()}]},'configuration':{
                'revisionId':'advanced-config','compiler':'clang++','flags':['-std=c++20','-g','-O0'],
                'outputDirectory':'.phantom/build','addressProfile':'fixed-executable'},'architecture':'x86_64'})['artifact']
            client.launch(artifact)
            entry=client.observation
            process=client.good({'kind':'inspectProcess'})
            assert process['stop']==entry['stop'] and process['point']==entry['point']
            proc=process['inspection']; assert proc['available'] and proc['identityVerified'],proc
            assert proc['pid']==entry['processInstanceId'] and proc['stat']['pid']==proc['pid'],proc
            assert proc['status']['available'] and int(proc['status']['tracerPid'])>0,proc
            assert int(proc['system']['pageSizeBytes'])>0,proc
            assert 'environ' not in proc and 'cmdline' not in proc
            registers=client.good({'kind':'readRegisters','registers':['rip','rsp','rax']})
            assert [r['name'] for r in registers['registers']]==['rip','rsp','rax'],registers
            assert all(r['available'] for r in registers['registers']),registers
            assert all(isinstance(r['valueHex'],str) for r in registers['registers']),registers
            client.bad({'kind':'inspectProcess','pid':1})
            client.bad({'kind':'readRegisters','registers':['rip','rip']})
            client.bad({'kind':'readRegisters','registers':['rip\n-exec-continue']})
            client.bad({'kind':'readRegisters','registers':['phantom_nonexistent']})
            client.bad({'kind':'traceInstructions','count':257,'memoryRanges':[]})
            client.bad({'kind':'captureMemory','ranges':[{'addressHex':'0xffffffffffffffff','byteCount':1}]})
            client.bad({'kind':'captureMemory','ranges':[{'addressHex':'0x10','byteCount':16},{'addressHex':'0x18','byteCount':1}]})
            client.bad({'kind':'traceInstructions','count':1,'memoryRanges':[{'addressHex':'0x10','byteCount':4097}]})
            for kind in ['inspectProcess','readRegisters','captureMemory','traceInstructions']:
                command={'kind':kind}
                if kind=='captureMemory': command['ranges']=[{'addressHex':'0x0','byteCount':1}]
                if kind=='traceInstructions': command.update(count=1,memoryRanges=[])
                frame=client.frame(command); frame.pop('expectedStop'); client.record_requests=False
                missing=client.send(frame); client.record_requests=True
                assert not missing['ok'] and missing['error']['code']=='INVALID_REQUEST',missing
            markers=['TRACE','AFTER_TRACE','MAPPED','PROTECTED','UNMAPPED']
            bps=client.good({'kind':'setBreakpoints','documentId':'advanced','revisionId':'advanced-1',
                'breakpoints':[{'id':s,'range':location(s),'enabled':True} for s in markers]})
            assert all(b['verified'] for b in bps['breakpoints']),bps
            client.execute({'kind':'continue'})
            before=client.observation
            journal=client.good({'kind':'readOutputJournal','stream':'stdout','fromByte':0,'byteCount':64,'point':before['point']})
            assert base64.b64decode(journal['segments'][0]['bytesBase64'])==b'kept\n',journal
            assert before["stdout"]["text"]=="kept\n",before
            address=variable(before,'cell')['addressHex']; assert address
            ranges=[{'addressHex':address,'byteCount':8}]
            capture=client.good({'kind':'captureMemory','ranges':ranges})['capture']
            assert capture['coverage']=='complete' and base64.b64decode(capture['ranges'][0]['bytesBase64'])==bytes(8),capture
            events=client.execute({'kind':'traceInstructions','count':64,'registers':['rip','rax'],
                                   'memoryRanges':ranges+[{'addressHex':'0x0','byteCount':1}]})
            assert events[-1]['payload']['outcome']=='completed',events[-1]
            recorded=next(e['payload'] for e in events if e['payload']['kind']=='instructionTraceRecorded')
            assert recorded['terminationReason']=='breakpoint-hit',recorded
            trace_id=recorded['traceId']
            trace=client.good({'kind':'readInstructionTrace','traceId':trace_id,'start':0,'count':64})
            assert trace['trace']['beforePoint']==before['point']
            assert trace['trace']['afterPoint']==client.observation['point']
            assert trace['trace']['coverage']['sameValueWrites'] is False
            assert trace['trace']['coverage']['otherThreads']=='not-recorded'
            assert trace['trace']['initialMemory'][1]['available'] is False
            values=[]
            for item in trace['trace']['entries']:
                for change in item['memoryChanges']:
                    if change['addressHex']==address and change['after']['available']:
                        values.append(int.from_bytes(base64.b64decode(change['after']['bytesBase64']),'little'))
            assert values==[1,2,0],values
            one=client.good({'kind':'readInstructionTrace','traceId':trace_id,'start':0,'count':1})
            assert len(one['trace']['entries'])==1 and one['hasMore']
            empty=client.good({'kind':'readInstructionTrace','traceId':trace_id,'start':9007199254740991,'count':64})
            assert empty['trace']['entries']==[] and not empty['hasMore']
            unchanged=client.good({'kind':'captureMemory','ranges':ranges})['capture']
            diff=lambda a,b: client.good({'kind':'diffMemoryCaptures','beforeCaptureId':a['id'],'afterCaptureId':b['id'],'start':0,'count':20})
            assert diff(capture,unchanged)['changedBytes']==0  # Intermediate stores only exist in trace.
            client.execute({'kind':'step','stepKind':'over'})
            changed=client.good({'kind':'captureMemory','ranges':ranges})['capture']
            delta=diff(capture,changed)
            assert delta['changedBytes']==1 and delta['comparedBytes']==8,delta
            assert delta['changes'][0]['beforeBytesHex']=='00' and delta['changes'][0]['afterBytesHex']=='07',delta
            assert client.good({'kind':'readMemoryCapture','captureId':capture['id']})['capture']==capture
            stale=client.frame({'kind':'inspectProcess'}); stale['expectedStop']=before['stop']
            rejected=client.send(stale); assert not rejected['ok'] and rejected['error']['code']=='STALE_CONTEXT',rejected
            unknown=client.good({'kind':'captureMemory','ranges':[{'addressHex':'0x0','byteCount':8}]})['capture']
            partial=diff(unknown,unknown)
            assert partial['coverage']=='partial' and partial['comparedBytes']==0 and partial['unavailableRanges'],partial
            client.bad({'kind':'diffMemoryCaptures','beforeCaptureId':capture['id'],'afterCaptureId':unknown['id'],'start':0,'count':10})
            client.execute({'kind':'continue'}); mapped=client.observation
            assert mapped['location']['start']['line']==location('MAPPED')['start']['line'],mapped
            middle=variable(mapped,'middle')['value']['value']['addressHex']
            middle_capture=client.good({'kind':'captureMemory','ranges':[{'addressHex':middle,'byteCount':1}]})['capture']
            client.execute({'kind':'continue'}); protected=client.observation
            client.execute({'kind':'continue'}); unmapped=client.observation
            changes=client.good({'kind':'diffMemoryMaps','beforePoint':mapped['point'],'afterPoint':protected['point'],'start':0,'count':1024})
            assert changes['changes'],changes
            gone=client.good({'kind':'diffMemoryMaps','beforePoint':protected['point'],'afterPoint':unmapped['point'],'start':0,'count':1024})
            removed=[c['before'] for c in gone['changes'] if c['kind']=='removed']
            assert any(int(r['startAddressHex'],16)<=int(middle,16)<int(r['endAddressHex'],16) for r in removed),gone
            no_memory=client.good({'kind':'captureMemory','ranges':[{'addressHex':middle,'byteCount':1}]})['capture']
            assert diff(middle_capture,no_memory)['coverage']=='partial'
            assert base64.b64decode(client.good({'kind':'readMemoryCapture','captureId':middle_capture['id']})['capture']['ranges'][0]['bytesBase64'])==b'\xa7'
            client.execute({'kind':'continue'})
            state=client.good({'kind':'getState'}); assert state['state']['phase']=='terminated'
            assert client.good({'kind':'readInstructionTrace','traceId':trace_id,'start':0,'count':64})==trace
            assert client.good({'kind':'readHistory','point':before['point']})['observation']==before
            client.bad({'kind':'inspectProcess'},('STALE_CONTEXT',))
            old_session=client.session
            client.launch(artifact)
            client.bad({'kind':'readMemoryCapture','captureId':capture['id']},('HISTORY_EVICTED',))
            frame=client.frame({'kind':'readInstructionTrace','traceId':trace_id,'start':0,'count':1}); frame['session']=old_session
            stale=client.send(frame); assert not stale['ok'] and stale['error']['code']=='STALE_CONTEXT',stale
            # Exercise eviction by count, with bounded tiny captures, then recovery.
            first=client.good({'kind':'captureMemory','ranges':[{'addressHex':'0x0','byteCount':1}]})['capture']
            for _ in range(128): client.good({'kind':'captureMemory','ranges':[{'addressHex':'0x0','byteCount':1}]})
            client.bad({'kind':'readMemoryCapture','captureId':first['id']},('HISTORY_EVICTED',))
            # Controls race trace startup; each accepted request must terminate exactly once.
            trace_frame=client.frame({'kind':'traceInstructions','count':256,'memoryRanges':[]})
            cancel=client.frame({'kind':'cancel','targetRequestId':trace_frame['requestId']})
            TRAFFIC.extend([('request',trace_frame),('request',cancel)])
            client.send_many([trace_frame,cancel]); terminals={}; responses={}
            while len(terminals)<2:
                frame=client.recv()
                if 'requestId' in frame: responses[frame['requestId']]=frame
                if frame.get('payload',{}).get('kind')=='observation': client.observation=frame['payload']['observation']
                if frame.get('payload',{}).get('kind')=='commandFinished':
                    rid=frame['payload']['requestId']; assert rid not in terminals; terminals[rid]=frame['payload']
            assert all(r['ok'] for r in responses.values()),responses
            assert terminals[trace_frame['requestId']]['outcome']=='cancelled',terminals
            assert client.good({'kind':'getState'})['state']['phase']=='stopped'
            # A semantically invalid register fails before executing anything.
            prior=client.good({'kind':'getState'})
            failed=client.execute({'kind':'traceInstructions','count':1,'registers':['phantom_nonexistent'],'memoryRanges':[]})
            assert failed[-1]['payload']['outcome']=='failed',failed
            assert client.good({'kind':'getState'})['observation']==prior['observation']
            client.good({'kind':'setBreakpoints','documentId':'advanced','revisionId':'advanced-1',
                'breakpoints':[{'id':'trace-again','range':location('TRACE'),'enabled':True}]})
            client.execute({'kind':'continue'})
            assert client.observation['stdout']['text']=='kept\n'
            trace_frame=client.frame({'kind':'traceInstructions','count':256,'memoryRanges':[]})
            stop_frame=client.frame({'kind':'stop'})
            TRAFFIC.extend([('request',trace_frame),('request',stop_frame)])
            client.send_many([trace_frame,stop_frame]); terminals={}
            while len(terminals)<2:
                event=client.recv()
                if 'requestId' in event: assert event['ok'],event
                payload=event.get('payload',{})
                if payload.get('kind')=='commandFinished':
                    assert payload['requestId'] not in terminals
                    terminals[payload['requestId']]=payload
            state=client.good({'kind':'getState'})
            assert state['state']['phase']=='terminated' and state['observation']['stdout']['text']=='kept\n',state
        finally: client.close()
    print('advanced gateways: process identity, registers, intermediate stores, immutable captures/maps, pagination, eviction, stale context and cancellation passed')
    return 0

if __name__=='__main__': raise SystemExit(main())

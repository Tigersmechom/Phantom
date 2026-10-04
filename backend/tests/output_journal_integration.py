"""Physical output journal retains bytes separately from immutable stop snapshots."""
from __future__ import annotations
import base64
import hashlib
import shutil
import sys
import tempfile
from pathlib import Path
from memory_gateway_integration import Client

SOURCE = r'''#include <unistd.h>
#include <cstring>
int main() {
  const unsigned char raw[] = {0,255,240,159,152,128};
  write(1,raw,sizeof(raw));
  write(2,"err\0tail",8);
  int phase = 1;
  asm volatile("" : : "r"(phase) : "memory"); // FIRST
  char block[8192];
  memset(block,'A',sizeof(block));
  for (int i=0;i<80;++i) write(1,block,sizeof(block));
  phase = 2;
  asm volatile("" : : "r"(phase) : "memory"); // SECOND
  memset(block,'B',sizeof(block));
  for (int i=0;i<320;++i) write(1,block,sizeof(block));
  phase = 3;
  asm volatile("" : : "r"(phase) : "memory"); // THIRD
  return 0;
}
'''

def location(marker):
    line=next(i for i,text in enumerate(SOURCE.splitlines(),1) if text.endswith('// '+marker))
    offset=sum(len(text)+1 for text in SOURCE.splitlines()[:line-1])
    return {'documentId':'journal','revisionId':'journal-1','range':{'start':offset,'end':offset},
            'start':{'line':line,'column':1},'end':{'line':line,'column':1}}

def read(client,stream='stdout',start=0,count=65536,point=None):
    command={'kind':'readOutputJournal','stream':stream,'fromByte':start,'byteCount':count}
    if point is not None: command['point']=point
    result=client.query(command)
    assert result['ok'],result
    return result['result']

def main():
    if len(sys.argv)!=2: return 2
    if not shutil.which('gdb') or not shutil.which('clang++'): return 77
    with tempfile.TemporaryDirectory(prefix='phantom-output-journal-') as directory:
        client=Client(sys.argv[1],Path(directory))
        try:
            missing=client.query({'kind':'readOutputJournal','stream':'stdout','fromByte':0,'byteCount':1})
            assert not missing['ok'] and missing['error']['code']=='STALE_CONTEXT',missing
            response=client.query({'kind':'build','source':{'id':'journal-source','documents':[{
                'documentId':'journal','revisionId':'journal-1','path':'journal.cpp','text':SOURCE,
                'sha256':hashlib.sha256(SOURCE.encode()).hexdigest()}]},'configuration':{
                'revisionId':'journal-config','compiler':'clang++','flags':['-std=c++20','-g','-O0'],
                'outputDirectory':'.phantom/build'},'architecture':'x86_64'})
            assert response['ok'] and response['result']['success'],response
            artifact=response['result']['artifact']; client.launch(artifact)
            empty=read(client); assert empty['totalBytes']==0 and empty['segments']==[]
            bps=client.query({'kind':'setBreakpoints','documentId':'journal','revisionId':'journal-1',
                 'breakpoints':[{'id':m,'range':location(m),'enabled':True} for m in ['FIRST','SECOND','THIRD']]})
            assert bps['ok'] and all(b['verified'] for b in bps['result']['breakpoints']),bps
            client.execute({'kind':'continue'}); first=client.observation
            raw=read(client,count=6,point=first['point'])
            assert raw['totalBytes']==6 and raw['selectedThroughByte']==6 and raw['coverage']=='complete',raw
            assert base64.b64decode(raw['segments'][0]['bytesBase64'])==b'\x00\xff\xf0\x9f\x98\x80',raw
            assert base64.b64decode(read(client,'stderr')['segments'][0]['bytesBase64'])==b'err\0tail'
            client.execute({'kind':'continue'}); second=client.observation
            assert second['stdout']['totalBytes']==6+8192*80,second['stdout']
            client.execute({'kind':'continue'}); third=client.observation
            total=6+8192*400
            assert third['stdout']['totalBytes']==total and third['stdout']['truncated']
            assert third['stdout']['retainedFromByte']>6  # Native tail lost the beginning.
            # Journal keeps bytes from earlier checkpoints and the later tail.
            original=read(client,count=6,point=first['point'])
            assert original['consistent'] and original['totalBytes']==total
            assert original['selectedThroughByte']==6 and original['selectedPoint']==first['point']
            assert original['segments']==raw['segments']
            assert original['retentionHasGaps'] and original['coverage']=='complete'
            gap=read(client,start=6+8192*80-2,count=8)
            assert [s['kind'] for s in gap['segments']]==['bytes','gap'],gap
            assert base64.b64decode(gap['segments'][0]['bytesBase64'])==b'AA',gap
            assert gap['segments'][1]['throughByte']-gap['segments'][1]['fromByte']==6,gap
            assert gap['coverage']=='partial'
            assert base64.b64decode(read(client,start=total-4,count=4)['segments'][0]['bytesBase64'])==b'BBBB'
            assert read(client,start=9007199254740991,count=1)['segments']==[]
            for _ in range(3):
                history=client.query({'kind':'readHistory','point':first['point']})
                assert history['ok'] and history['result']['observation']==first
                assert read(client,count=6,point=first['point'])==original
            stale=client.frame({'kind':'readOutputJournal','stream':'stdout','fromByte':0,'byteCount':1})
            stale['session']=None
            result=client.send(stale); assert not result['ok'] and result['error']['code']=='STALE_CONTEXT',result
            client.execute({'kind':'continue'})
            assert read(client,count=6,point=first['point'])==original
            client.launch(artifact)
            assert read(client)['totalBytes']==0
        finally: client.close()
    print('output journal integration: binary bytes, separate streams, retained prefix, explicit gap, history roundtrip and session reset passed')
    return 0

if __name__=='__main__': raise SystemExit(main())

#!/usr/bin/env node
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
const root = path.resolve(new URL('.', import.meta.url).pathname, '../..');
const backend = process.argv[2] || path.join(root, 'backend/out/linux-debug/phantom-backend');
const workspace = await mkdtemp(path.join(tmpdir(), 'phantom-harness-smoke-'));
const port = 4199;
const server = spawn(process.execPath, [path.join(root,'tools/frontend-harness/server.mjs'),'--backend',backend,'--workspace',workspace,'--port',String(port)], {cwd:root,stdio:['ignore','pipe','pipe']});
const wait = ms => new Promise(resolve => setTimeout(resolve,ms));
async function post(pathname, value={}) { const r=await fetch(`http://127.0.0.1:${port}${pathname}`, {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(value)}); const x=await r.json(); if(!r.ok || x.ok===false) throw new Error(JSON.stringify(x)); return x; }
async function events() { return (await (await fetch(`http://127.0.0.1:${port}/api/events`)).json()).events; }
try {
  await wait(150);
  const source = '#include <iostream>\nint main(){ std::cout << "ok\\n"; return 0; }\n';
  const build = await post('/api/request',{command:{kind:'build',source:{id:'smoke-source',documents:[{documentId:'main.cpp',revisionId:'rev-1',path:'main.cpp',text:source,sha256:createHash('sha256').update(source).digest('hex')}]},configuration:{revisionId:'cfg-1',compiler:'clang++',flags:['-std=c++20','-g','-O0'],outputDirectory:'.phantom/harness-build'},architecture:'x86_64'}});
  if (!build.result?.artifact) throw new Error('build produced no artifact');
  const launch = await post('/api/request',{command:{kind:'launch',buildId:build.result.artifact.id,input:{id:'input-1',text:'',encoding:'utf-8',closeAfterWrite:true},argv:[],environment:{},stopAtEntry:true}});
  if (launch.result?.kind !== 'launchAccepted') throw new Error('launch was not accepted');
  let stop; for (let i=0;i<30 && !stop;i++){ await wait(40); for(const e of await events()) if(e.payload?.kind==='observation') stop=e.payload.observation.stop; }
  if (!stop) throw new Error('launch observation was not emitted');
  const step = await post('/api/request',{session:launch.result.session,expectedStop:stop,command:{kind:'step',stepKind:'over'}});
  if (step.result?.kind !== 'accepted') throw new Error('step was not accepted');
  const stopResponse = await post('/api/request',{session:launch.result.session,expectedStop:stop,command:{kind:'stop'}});
  if (stopResponse.result?.kind !== 'accepted') throw new Error('stop was not accepted');
  console.log('PASS frontend harness build → launch → step → stop');
} finally { server.kill('SIGTERM'); await rm(workspace,{recursive:true,force:true}); }

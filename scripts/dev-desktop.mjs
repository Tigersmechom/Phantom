import { spawn } from 'node:child_process';
import { createServer } from 'vite';
import electron from 'electron';
const server=await createServer({server:{host:'127.0.0.1',port:5173}});await server.listen();
const address=server.resolvedUrls.local[0];
const env={...process.env,FRAME_DEV_URL:address};delete env.ELECTRON_RUN_AS_NODE;
const child=spawn(electron,['.','--workspace',process.cwd()],{stdio:'inherit',env});
let stopping=false;async function stop(code=0){if(stopping)return;stopping=true;child.kill();await server.close();process.exit(code)}
child.on('exit',code=>void stop(code??0));child.on('error',error=>{console.error(error);void stop(1)});
process.on('SIGINT',()=>void stop());process.on('SIGTERM',()=>void stop());

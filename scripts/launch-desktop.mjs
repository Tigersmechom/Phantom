import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import electron from 'electron';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const env={...process.env};delete env.ELECTRON_RUN_AS_NODE;delete env.FRAME_DEV_URL;
if(!existsSync(path.join(root,'dist/index.html'))){console.error('Сначала выполните npm run build.');process.exit(1)}
const child=spawn(electron,[root,'--workspace',root,...process.argv.slice(2)],{cwd:root,stdio:'inherit',env});
child.on('error',error=>{console.error(error);process.exit(1)});child.on('exit',code=>process.exit(code??0));
process.on('SIGINT',()=>child.kill('SIGINT'));process.on('SIGTERM',()=>child.kill('SIGTERM'));

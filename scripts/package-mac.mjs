import { packager } from '@electron/packager';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { archiveMac } from './archive-mac.mjs';
const pkg=JSON.parse(await readFile('package.json','utf8'));
const apps=await packager({dir:process.cwd(),name:'phantom',platform:'darwin',arch:'arm64',out:'release',overwrite:true,electronVersion:pkg.devDependencies.electron,appBundleId:'local.phantom.ide',appCategoryType:'public.app-category.developer-tools',appVersion:pkg.version,icon:'assets/phantom.icns',asar:{unpackDir:'node_modules/node-pty/**'},prune:true,ignore:[/^\/(unreal|previews|docs|scripts|src|tests|examples|\.frame|release|\.git|public|assets)(\/|$)/,/^\/(Start\.command|README\.md|tsconfig\.json|vite\.config\.ts|package-lock\.json)$/]});
for(const directory of apps){const app=path.join(directory,'phantom.app');const result=spawnSync('/usr/bin/codesign',['--force','--deep','--sign','-',app],{stdio:'inherit'});if(result.status!==0)throw Error('Не удалось подписать локальную сборку');console.log('Готово:',path.resolve(app));await archiveMac(app,'release/phantom-macOS-arm64.zip');}

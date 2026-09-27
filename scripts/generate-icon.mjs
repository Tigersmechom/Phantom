import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
const staging = await mkdtemp(path.join(os.tmpdir(), 'phantom-icon-'));
const run = (command, args) => {
  const result = spawnSync(command, args, { stdio: 'inherit', env: { ...process.env, SWIFT_MODULECACHE_PATH: path.join(staging, 'swift-cache'), CLANG_MODULE_CACHE_PATH: path.join(staging, 'clang-cache') } });
  if (result.error) throw result.error;
  if (result.status !== 0) throw Error(`${command}: ${result.status}`);
};
try {
  const source = path.join(staging, 'phantom.png'), iconset = path.join(staging, 'phantom.iconset');
  await mkdir(iconset); await mkdir('assets', { recursive: true });
  run('/usr/bin/swift', ['scripts/icon.swift', source]);
  for (const size of [16, 32, 128, 256, 512]) for (const scale of [1, 2]) {
    const pixels = String(size * scale);
    run('/usr/bin/sips', ['-z', pixels, pixels, source, '--out', path.join(iconset, `icon_${size}x${size}${scale === 2 ? '@2x' : ''}.png`)]);
  }
  run('/usr/bin/iconutil', ['-c', 'icns', iconset, '-o', 'assets/phantom.icns']);
} finally { await rm(staging, { recursive: true, force: true }); }

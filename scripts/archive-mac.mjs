import { mkdtemp, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export async function archiveMac(app, output) {
  const staging = await mkdtemp(path.join(os.tmpdir(), 'phantom-package-'));
  const copy = path.join(staging, 'phantom.app');
  const run = (command, args) => {
    const result = spawnSync(command, args, { stdio: 'inherit' });
    if (result.error) throw result.error;
    if (result.status !== 0) throw Error(`${command} завершился с кодом ${result.status}`);
  };
  try {
    // File Provider can add FinderInfo to an app stored on an iCloud Desktop.
    // Verify and archive a copy without that filesystem metadata.
    run('/usr/bin/ditto', ['--norsrc', '--noextattr', '--noacl', app, copy]);
    run('/usr/bin/codesign', ['--verify', '--deep', '--strict', copy]);
    run('/usr/bin/ditto', ['-c', '-k', '--keepParent', '--norsrc', '--noextattr', copy, output]);
    console.log('Архив с проверенной локальной подписью:', path.resolve(output));
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  await archiveMac(process.argv[2] || 'release/phantom-darwin-arm64/phantom.app', process.argv[3] || 'release/phantom-macOS-arm64.zip');
}

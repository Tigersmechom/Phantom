import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { ProjectService } = require('../electron/project-service.cjs');
const { migrateLegacyProfile } = require('../electron/profile-service.cjs');

test('phantom copies legacy workspace/preferences once without touching either existing profile', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'phantom-profile-'));
  const oldProfile = path.join(root, 'FRAME'), current = path.join(root, 'phantom');
  try {
    await mkdir(path.join(oldProfile, 'Local Storage', 'leveldb'), { recursive: true });
    await mkdir(current);
    await writeFile(path.join(oldProfile, 'workspace.json'), '{"workspace":"/old/project"}');
    await writeFile(path.join(oldProfile, 'Preferences'), '{"old":true}');
    await writeFile(path.join(oldProfile, 'Local Storage', 'leveldb', '000003.log'), 'appearance-state');
    await writeFile(path.join(oldProfile, 'Local Storage', 'leveldb', 'LOCK'), '');
    await writeFile(path.join(current, 'Preferences'), '{"current":true}');
    migrateLegacyProfile(oldProfile, current);
    assert.equal(await readFile(path.join(current, 'workspace.json'), 'utf8'), '{"workspace":"/old/project"}');
    assert.equal(await readFile(path.join(current, 'Preferences'), 'utf8'), '{"current":true}');
    assert.equal(await readFile(path.join(current, 'Local Storage', 'leveldb', '000003.log'), 'utf8'), 'appearance-state');
    await assert.rejects(readFile(path.join(current, 'Local Storage', 'leveldb', 'LOCK')), { code: 'ENOENT' });
    await writeFile(path.join(current, 'workspace.json'), '{"workspace":"/new/project"}');
    migrateLegacyProfile(oldProfile, current);
    assert.equal(await readFile(path.join(current, 'workspace.json'), 'utf8'), '{"workspace":"/new/project"}');
    assert.equal(await readFile(path.join(oldProfile, 'workspace.json'), 'utf8'), '{"workspace":"/old/project"}');
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('project saves config, compiles with flags, executes real stdin and invalidates failed builds', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'frame-native-'));
  const source = '#include <iostream>\n#ifndef FRAME_FACTOR\n#error missing configured flag\n#endif\nint main() { int value; std::cin >> value; std::cout << value * FRAME_FACTOR << "\\n"; }\n';
  const project = new ProjectService(root);
  try {
    await mkdir(path.join(root, 'examples'));
    await writeFile(path.join(root, 'examples', 'prefix_sum.cpp'), source);
    const initial = await project.initialize();
    assert.equal(initial.document.name, 'prefix_sum.cpp');
    assert.deepEqual(JSON.parse(await readFile(initial.configPath, 'utf8')), initial.config);
    await project.saveBuildConfig({ ...initial.config, flags: ['-std=c++20', '-DFRAME_FACTOR=7'] });
    const built = await project.compile({ content: source, architecture: 'arm64' });
    assert.equal(built.success, true, built.stderr);
    assert.ok(built.command.includes('-DFRAME_FACTOR=7'));
    assert.ok(built.outputPath.startsWith(path.join(initial.root, '.frame', 'build')));
    const result = await project.execute({ stdin: '6\n' });
    assert.equal(result.stdout, '42\n');
    assert.equal(result.exitCode, 0);
    assert.equal(result.truncated, false);
    const intel = await project.compile({ content: source, architecture: 'x86_64' });
    assert.equal(intel.success, true, intel.stderr);
    assert.ok(intel.command.includes('x86_64'));
    assert.equal((await project.execute({ stdin: '6\n' })).stdout, '42\n');
    const bad = await project.compile({ content: 'this is not C++', architecture: 'arm64' });
    assert.equal(bad.success, false);
    assert.notEqual(bad.exitCode, 0);
    await assert.rejects(project.execute({ stdin: '' }), /Сначала успешно соберите/);
    await assert.rejects(project.saveDocument({ path: '../escape.cpp', content: '' }), /внутри открытого проекта/);
    await assert.rejects(project.saveBuildConfig({ ...initial.config, outputDirectory: '../outside' }), /внутри открытого проекта/);
  } finally { project.dispose(); await rm(root, { recursive: true, force: true }); }
});

test('native execution can be stopped and its cwd is the workspace', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'frame-native-stop-'));
  const project = new ProjectService(root);
  try {
    await project.initialize();
    const content = '#include <unistd.h>\n#include <iostream>\nint main(){char cwd[4096]; getcwd(cwd,sizeof(cwd)); std::cout << cwd << std::endl; for(;;) pause();}\n';
    assert.equal((await project.compile({ content, architecture: 'arm64' })).success, true);
    const running = project.execute({ stdin: '' });
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Program did not become ready')), 5000);
      project.runProcess.stdout.once('data', () => { clearTimeout(timer); resolve(); });
      project.runProcess.once('error', reject);
    });
    project.stopExecution();
    const result = await running;
    assert.equal(result.stdout.trim(), await import('node:fs/promises').then(fs => fs.realpath(root)));
    assert.equal(result.signal, 'SIGTERM');
  } finally { project.dispose(); await rm(root, { recursive: true, force: true }); }
});

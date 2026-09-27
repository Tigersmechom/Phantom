'use strict';
const fs = require('node:fs');
const path = require('node:path');

// Copy only persistent state. Lock files, sockets and browser caches belong to
// the running app and must never be inherited from the previous installation.
function migrateLegacyProfile(previous, current) {
  const marker = path.join(current, '.frame-profile-migrated');
  if (!fs.existsSync(previous) || fs.existsSync(marker) || previous === current) return;
  fs.mkdirSync(current, { recursive: true });
  for (const name of ['workspace.json', 'Preferences', 'Local State', 'Local Storage', 'IndexedDB', 'Session Storage']) {
    const source = path.join(previous, name), destination = path.join(current, name);
    if (fs.existsSync(source) && !fs.existsSync(destination)) fs.cpSync(source, destination, { recursive: true, force: false, filter: filename => path.basename(filename) !== 'LOCK' });
  }
  fs.writeFileSync(marker, 'Migrated persistent state from FRAME without changing its profile.\n', { flag: 'wx' });
}
module.exports = { migrateLegacyProfile };

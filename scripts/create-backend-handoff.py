#!/usr/bin/env python3
"""Create an isolated source baseline for the backend agent, without build output."""
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

root = Path(__file__).resolve().parent.parent
output = root / "release" / "phantom-backend-source.zip"
directories = ("src", "electron", "examples", "public", "assets", "docs", "scripts", "tests")
root_files = (
    "README.md", "Start.command", "index.html", "package.json", "package-lock.json",
    "tsconfig.json", "vite.config.ts", ".gitignore", ".frame/build.json",
)
files = [root / name for name in root_files if (root / name).is_file()]
for directory in directories:
    files.extend(path for path in (root / directory).rglob("*")
                 if path.is_file() and not path.is_symlink()
                 and path.name != ".DS_Store" and "__pycache__" not in path.parts)
contents = {path.relative_to(root).as_posix(): path.read_bytes() for path in sorted(set(files))}
manifest = {
    "schemaVersion": 1,
    "createdAt": datetime.now(timezone.utc).isoformat(),
    "purpose": "Shared source baseline for independent frontend/backend changes and later merging.",
    "entryPoint": "docs/BACKEND_HANDOFF.md",
    "excluded": ["node_modules", "dist", "release", "unreal", "previews/images", ".frame/build", "user profiles"],
    "files": {name: sha256(data).hexdigest() for name, data in contents.items()},
}
output.parent.mkdir(parents=True, exist_ok=True)
prefix = "phantom-backend-source/"
with ZipFile(output, "w", ZIP_DEFLATED, compresslevel=9) as archive:
    for name, data in contents.items():
        metadata = ZipInfo.from_file(root / name, prefix + name)
        metadata.compress_type = ZIP_DEFLATED
        archive.writestr(metadata, data)
    archive.writestr(prefix + "BACKEND_BASELINE.json", json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    # Existing browser/desktop checks write screenshots to this directory.
    archive.writestr(prefix + "previews/README.md", "Screenshots are generated here by the UI checks.\n")
with ZipFile(output) as archive:
    assert archive.testzip() is None
    for name, digest in manifest["files"].items():
        assert sha256(archive.read(prefix + name)).hexdigest() == digest
print(f"{output}\n{len(contents)} source files, SHA-256 baseline verified, {output.stat().st_size:,} bytes")

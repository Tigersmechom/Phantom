#!/usr/bin/env bash
# Read-only inventory. Never installs packages or changes kernel/ptrace settings.
set -u

if [[ $# -gt 0 ]]; then
  if [[ $# -eq 1 && "$1" == "--help" ]]; then
    printf 'Usage: bash scripts/backend-doctor.sh\n'
    printf 'Read-only inventory; missing tools do not fail the command.\n'
    printf 'There is no --strict mode. Use CMake/CTest and the rr fixture for validation.\n'
    exit 0
  fi
  printf 'Unsupported option. Use --help; this inventory has no --strict mode.\n' >&2
  exit 2
fi

printf 'phantom backend environment (read-only; no replay support verdict)\n'
printf 'OS/kernel: %s\n' "$(uname -sr)"
printf 'Architecture: %s\n' "$(uname -m)"

if [[ -r /etc/os-release ]]; then
  # Read the label as data; do not source an arbitrary OS file as shell code.
  sed -n 's/^PRETTY_NAME=/Distribution: /p' /etc/os-release
fi

case "$(uname -s)" in
  Linux)
    if command -v lscpu >/dev/null 2>&1; then
      LC_ALL=C lscpu | sed -n '/^Architecture:/p; /^Vendor ID:/p; /^Model name:/p; /^Hypervisor vendor:/p; /^Virtualization type:/p'
    fi
    for setting in /proc/sys/kernel/perf_event_paranoid /proc/sys/kernel/yama/ptrace_scope; do
      if [[ -r "$setting" ]]; then
        printf '%s: %s\n' "$setting" "$(cat "$setting")"
      else
        printf '%s: unavailable\n' "$setting"
      fi
    done
    ;;
  Darwin)
    printf 'macOS can build the scaffold; rr execution requires Linux.\n'
    ;;
esac

for tool in git clang++ clangd lldb gdb cmake ninja pkg-config python3 rr; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf '%-12s %s\n' "$tool" "$(command -v "$tool")"
    "$tool" --version 2>&1 | sed -n '1,2p'
  else
    printf '%-12s MISSING\n' "$tool"
  fi
done

if command -v pkg-config >/dev/null 2>&1; then
  if pkg-config --exists sqlite3; then
    printf 'sqlite3 development package: %s\n' "$(pkg-config --modversion sqlite3)"
  else
    printf 'sqlite3 development package: MISSING (not needed for scaffold)\n'
  fi
fi

printf '\nInventory complete. Missing tools do not change this command exit status.\n'
printf 'The rr binary, CPU label or sysctl value alone does not establish support.\n'
printf 'Run the record/replay fixture in docs/LINUX_BACKEND.md on the target Linux host.\n'

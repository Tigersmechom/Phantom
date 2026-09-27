# phantom backend

Linux backend service на C++20. Процесс работает без Electron и UI и говорит с
клиентом по UTF-8 NDJSON через stdin/stdout. Реализованный P0-срез проходит
реальный цикл `build → launch → stop at entry → step → history` через GDB/MI.

Поддерживаемая конфигурация текущего адаптера: Linux x86_64, Clang/GCC-подобный
компилятор, GDB с MI2. Исходники сначала проверяются и сохраняются в immutable
snapshot, затем сборка и отладчик работают только с этим snapshot и артефактом.
Пути ограничены workspace, команды компилятора запускаются без shell, а stdout,
stderr, JSON, страницы переменных, память и история имеют явные лимиты.
Аргументы inferior проходят проверку границ MI, а POSIX-окружение задаётся
самой отлаживаемой программе после запуска GDB; `PATH`/`LD_*` из запроса не
меняют процесс отладчика.

## Сборка и проверки

Нужны C++20 compiler, CMake >= 3.21, Ninja, Python >= 3.8 и GDB. Linux preset
использует `clang++` из PATH.

```bash
cd backend
cmake --preset linux-debug
cmake --build --preset linux-debug
ctest --preset linux-debug
./out/linux-debug/phantom-backend --self-check
```

CTest включает CLI doctor, SHA-256, process/MI parser, strict DTO validation,
bounded NDJSON transport и headless service integration. Последний тест компилирует небольшую C++20
программу, запускает её через настоящий GDB и проверяет порядок событий,
source identity, UTF-16 location, step, variables, history, stop, target-only
environment и same-packet control для долгого continue.

Для ручного запуска:

```bash
./out/linux-debug/phantom-backend --stdio --workspace /path/to/project
```

Первый frame должен быть `{"kind":"connect","supportedProtocolVersions":[1]}`.
Дальше идут v1 request frames; каждый response/event занимает одну строку.
`--help`, `--version` и `--self-check` не являются handshake и не заменяют
protocol capabilities.

## Честные границы текущего среза

- `capabilities.architectures` содержит только `x86_64`; arm64 отклоняется.
- Настоящие source breakpoints, stack frames, line locations, stepping
  (`over/into/out/instruction`) и immutable in-memory history работают через
  GDB/MI. Location — zero-width span в начале подтверждённой строки: GDB обычно
  не даёт колонку.
- `inputTracking` равно `transport-only`. Inferior получает отдельный PTY, а MI
  pipe никогда не доступен пользовательской программе. Submitted input
  сохраняет точный текст и ID, а принятые PTY bytes получают deterministic EOF;
  backend не выдаёт запись bytes за доказательство успешного C++ extraction.
  Канонический PTY ограничивает каждую строку системным `MAX_CANON` (на
  текущем Linux обычно 255 bytes); такой ввод отклоняется до запуска. Ввод с
  PTY EOF control byte также отклоняется, чтобы не потерять байт молча.
  PTY объединяет stdout/stderr, поэтому stderr snapshot пока пуст и отдельный
  stream capture будет отдельным transport-профилем.
- `variableWrite`, conditional/hit-count breakpoints, rr record/replay,
  expression traces, source disassembly и verified restore выключены и отвечают
  `UNSUPPORTED`. Чтение памяти и disassembly по PC принимают только явный адрес
  и проверяют лимиты.
- GDB values без надёжного type information помечаются `unavailable`, а не
  выдаются за типизированный результат. Оптимизированные/неизвестные значения
  сохраняют явную причину неполноты.

После EOF transport отменяет активную операцию, дренирует уже принятую очередь
и только затем освобождает GDB/process group. Отмена и stop не оставляют
принадлежащих сессии дочерних процессов.

## Структура

| Путь | Назначение |
| --- | --- |
| `src/main.cpp` | NDJSON framing, bounded frames, worker queue, CLI doctor |
| `src/validation.cpp` | pre-DOM bounds, duplicate keys, UTF-8/UTF-16 и DTO validation |
| `src/process.cpp` | shell-free fork/exec, pipes, deadlines, process groups, SIGPIPE safety |
| `src/mi.cpp` | strict reusable GDB/MI records и line buffering |
| `src/gdb.cpp` | GDB/MI adapter, source mapping, stack/variables/memory/asm |
| `src/service.cpp` | build identity, lifecycle, events, history и capability gate |
| `src/sha256.cpp` | dependency-free SHA-256 для source/artifact identity |
| `tests/service_integration.py` | headless real-debugger acceptance path |
| `tests/transport_test.py` | bounded NDJSON framing, EOF and signal cleanup |

Главный план, DTO semantics, recorder/instrumentation research и P0–P10 остаются
в [BACKEND_HANDOFF.md](../docs/BACKEND_HANDOFF.md). Документ проверки контрактов
и framing находится в [contract-review.md](docs/contract-review.md). Подготовка
Linux toolchain и результаты rr probe сохранены в `.phantom/setup/`.

## Следующие backend-профили

Следующий transport-профиль может заменить PTY на доверенный pipe-wrapper: это
даст раздельные stdout/stderr, произвольные бинарные bytes и half-close без
канонического лимита строки. Он должен быть отдельным capability-gated режимом,
а текущий merged PTY нельзя выдавать за него.

После этого можно добавлять rr только с manifest артефакта, проверкой PMU/ptrace
ограничений и явным `REPLAY_DIVERGED`; отсутствие rr не должно маскироваться
обычным GDB запуском. Expression/lifetime instrumentation требует совместимого
Clang/LLVM toolchain, immutable event schema и coverage gaps — эти функции не
должны появляться в capabilities до наличия соответствующих доказательств.

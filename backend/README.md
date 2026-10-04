# phantom backend

Linux backend service на C++20. Процесс работает без Electron и UI и говорит с
клиентом по UTF-8 NDJSON через stdin/stdout. Реализованный P0-срез проходит
реальный цикл `build → launch → stop at entry → step → history` через GDB/MI.

Поддерживаемая конфигурация текущего адаптера: Linux x86_64, Clang/GCC-подобный
компилятор, GDB с MI2. Исходники сначала проверяются и сохраняются в immutable
snapshot, затем сборка и отладчик работают только с этим snapshot и артефактом.
Пути ограничены workspace, команды компилятора запускаются без shell, а stdout,
stderr, JSON, страницы переменных, память и история имеют явные лимиты.
Аргументы inferior проходят проверку границ MI. Wrapper применяет POSIX-окружение
непосредственно перед `exec` отлаживаемой программы; `PATH`/`LD_*`/`BASH_ENV`
из запроса не меняют GDB, его стартовую оболочку или загрузку самого wrapper.

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

CTest включает CLI, SHA-256, process/MI parser, DTO validation, NDJSON transport
и интеграционные сценарии с настоящим GDB: шаги, история, отмена, смерть
отладчика, таймауты, бинарные управляющие байты stdin и раздельный вывод.
Если доступен `tsc`, реальные кадры также проверяются по frontend TypeScript
DTO; для этой проверки Electron и React не нужны. См.
[frontend-compatibility.md](docs/frontend-compatibility.md).

Отдельная сборка с AddressSanitizer и UndefinedBehaviorSanitizer (из `backend`):

```bash
cmake -S . -B out/linux-asan -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'
cmake --build out/linux-asan -j2
ctest --test-dir out/linux-asan --output-on-failure
```

Санитайзеры проверяют service, engine, wrapper и тестовые executable. Только
отлаживаемая fixture собирается без них: LeakSanitizer не работает под ptrace
и меняет её stderr/код завершения. Пользовательские программы в интеграционных
тестах также собираются обычным compiler-профилем.

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
- `inputTracking` равно `transport-only`; `interactiveInput` позволяет оставить
  stdin открытым и передавать `appendInput`/`closeInput` во время `continue`.
  Inferior получает stdin, stdout и
  stderr через отдельный доверенный `phantom-io-wrapper` и приватные FIFO; MI
  pipe никогда не доступен пользовательской программе. Submitted input
  сохраняет точный текст и ID; `closeAfterWrite:true` даёт deterministic EOF,
  а `false` ждёт явного `closeInput`;
  backend не выдаёт запись bytes за доказательство успешного C++ extraction.
  У pipe нет терминального `MAX_CANON`: NUL, Ctrl-D, CR/LF и длинные строки
  передаются без редактирования. v1 принимает UTF-8 текст до 1 MiB, а не
  произвольный массив невалидных UTF-8 байтов.
  stdout и stderr сохраняются раздельно: до 1 MiB исходных байтов на поток с
  `retainedFromByte` и `truncated`. В текстовом DTO невалидные байты вывода
  заменяются U+FFFD; счётчики сохраняют размеры исходного потока.
  На остановке сохраняется весь уже ожидающий хвост, включая увеличенные FIFO.
  Для Linux/glibc остановка может дополнительно содержать подтверждённый
  `stdout.buffered`: pending bytes, активное write-window, физическую ёмкость
  хранилища и режим буферизации. `capacityBytes`/`remainingCapacityBytes` —
  совместимые имена активного окна, `storageCapacityBytes` — отдельная
  физическая ёмкость. Это диагностическое окно, а не точный обратный отсчёт
  до flush: `endl`, `flush`, связанный `cin` и крупная запись могут сбросить
  данные раньше.
- Для локальных переменных Observation может содержать `addressHex` и
  bounded `storage.rawBytesHex` собственного storage. `state:observed` означает
  только успешное чтение байтов; `lifetime:unknown` не превращается в
  подтверждённое C++ значение, особенно для stack slots до начала lifetime.
- MI обрабатывается потоково: потреблённые ответы GDB не накапливаются за всё
  время сессии. Лимит отдельной записи и ограниченные порции чтения сохраняют
  границы памяти и возможность вовремя обработать timeout/cancel.
- `writeMemory` с явным native-профилем меняет до 256 storage bytes после
  проверки ожидаемых bytes и `rw-p` VMA. Результат повторно читается;
  immutable audit, lineage branches и повтор запроса без повторной записи
  доступны через протокол. Только один остановленный поток, без record-full.
  [Контракт и границы](../docs/INSPECTION_GATEWAYS.md#checked-native-memory-interventions).
- `variableWrite`, conditional/hit-count breakpoints, rr record/replay,
  expression traces, source disassembly и verified restore выключены и отвечают
  `UNSUPPORTED`. Чтение памяти и disassembly по PC принимают только явный адрес
  и проверяют лимиты.
- GDB values без надёжного type information помечаются `unavailable`, а не
  выдаются за типизированный результат. Оптимизированные/неизвестные значения
  сохраняют явную причину неполноты.

После EOF transport отменяет активную операцию и отклоняет ещё не начатые
build/launch/execution команды. Ответы на принятые запросы чтения дренируются.
GDB и непосредственно отлаживаемый процесс освобождаются, в том числе после
аварии GDB (pidfd и parent-death signal). Изоляция произвольно демонизирующихся
потомков требует отдельного supervisor/cgroup-профиля; backend не является sandbox.

## Структура

| Путь | Назначение |
| --- | --- |
| `src/main.cpp` | NDJSON framing, bounded frames, worker queue, CLI doctor |
| `src/validation.cpp` | pre-DOM bounds, duplicate keys, UTF-8/UTF-16 и DTO validation |
| `src/process.cpp` | shell-free fork/exec, pipes, deadlines, process groups, SIGPIPE safety |
| `src/mi.cpp` | strict reusable GDB/MI records и line buffering |
| `src/gdb.cpp` | GDB/MI adapter, pipe capture, source mapping, stack/variables/memory/asm |
| `src/io_wrapper.cpp` | shell-free inferior fd wrapper for separate binary streams |
| `src/service.cpp` | build identity, lifecycle, events, history и capability gate |
| `src/sha256.cpp` | dependency-free SHA-256 для source/artifact identity |
| `tests/service_integration.py` | headless real-debugger acceptance path |
| `tests/transport_test.py` | bounded NDJSON framing, EOF and signal cleanup |
| `tests/io_integration.py` | exact stdin, stream limits, invalid UTF-8, early close |
| `tests/lifecycle_integration.py` | control races, state after debugger failure |
| `tests/frontend_contract_test.py` | real wire traffic checked by TypeScript |

Главный план, DTO semantics, recorder/instrumentation research и P0–P10 остаются
в [BACKEND_HANDOFF.md](../docs/BACKEND_HANDOFF.md). Документ проверки контрактов
и framing находится в [contract-review.md](docs/contract-review.md). Подготовка
Linux toolchain и результаты rr probe сохранены в `.phantom/setup/`.

## Следующие backend-профили

Транспорт inferior уже использует доверенный pipe-wrapper. Wrapper не принимает
команды от target: он только открывает одноразовые FIFO, делает `dup2` на fd
0/1/2 и выполняет target напрямую. Если helper недоступен, запуск завершается
явной `LAUNCH_FAILED`, а backend не подменяет семантику pipe старым merged PTY.

После этого можно добавлять rr только с manifest артефакта, проверкой PMU/ptrace
ограничений и явным `REPLAY_DIVERGED`; отсутствие rr не должно маскироваться
обычным GDB запуском. Expression/lifetime instrumentation требует совместимого
Clang/LLVM toolchain, immutable event schema и coverage gaps — эти функции не
должны появляться в capabilities до наличия соответствующих доказательств.


## Запись исполнения и дополнительные шлюзы

Опциональный launch-профиль `gdb-record-full` поддерживает `readRecording`,
`reverseInstruction` и `seekRecording`. Native остаётся профилем по умолчанию.
Это реальное восстановление поддерживаемых GDB регистров/памяти внутри
сохранённого журнала; внешние эффекты и состояние ядра ОС не откатываются.
Неподдерживаемые инструкции, включая некоторые в стандартной библиотеке,
дают ошибку с фактической остановкой. Профиль требует конечного начального
ввода и работающего pidfd; интерактивный ввод сохраняется в native.

`probeRecorders` проверяет маленькую поставляемую программу отдельно от текущей
сессии. `inspectModules` связывает ELF-сегменты с `/proc/<pid>/maps`,
`readModuleSnapshot` читает сохранённые снимки. `readOutputJournal` возвращает
точные байты stdout/stderr и явно отмеченные пропуски хранения. Эти шлюзы
предназначены для frontend-интеграции; 2D renderer карты памяти сюда не входит.

`inspectModuleSymbols` / `readModuleSymbols` добавляют секции и символы ELF
с проверенными runtime-диапазонами и сохранённой пагинацией. Имена vtable/RTTI
дают классификацию символов. `inspectVariableLayout` / `readVariableLayout`
сохраняют declared type, размер, адрес storage и структуру полей/массивов из
GDB/DWARF. Указатели не разыменовываются, inferior functions не вызываются,
наличие адреса не считается доказательством начала lifetime переменной.

`inspectVtable` / `readVtableSnapshot` сохраняют связь выбранного vptr slot
с адресом таблицы, её заголовок, смещение к предполагаемому началу объекта,
RTTI pointer и ограниченное окно сырых слов с ELF-подписями. Клиент явно выбирает
профиль `itanium-x86_64-absolute-v1`; ABI/lifetime не устанавливаются автоматически.
Слова таблицы не выдаются за число методов; чтения не вызывают inferior functions.

Контракты и примеры: [RECORDING.md](../docs/RECORDING.md) и
[INSPECTION_GATEWAYS.md](../docs/INSPECTION_GATEWAYS.md).

# phantom backend — Linux starting point

Статус: **компилируемый каркас самостоятельного процесса C++20**. Он не запускает
отладчик, не исполняет Protocol v1, не записывает программы и не подключён к UI.
`--self-check` печатает отчёт о своей сборке; все исследовательские возможности
в нём выключены. Это не handshake и не доказательство работоспособности rr.

Основной план и критерии приёмки: [BACKEND_HANDOFF.md](../docs/BACKEND_HANDOFF.md).
Установка Linux, команды клонирования и проверка rr:
[LINUX_BACKEND.md](../docs/LINUX_BACKEND.md).

## Сборка без frontend

Нужны C++20 compiler, CMake >= 3.21, Ninja и Python >= 3.8 для smoke test.
Node.js, npm, Electron, Unreal, LLVM development libraries и SQLite для этого
каркаса не нужны. Linux preset использует `clang++` из PATH.

```bash
cd backend
cmake --preset linux-debug
cmake --build --preset linux-debug
ctest --preset linux-debug
./out/linux-debug/phantom-backend --version
./out/linux-debug/phantom-backend --self-check
```

На macOS с установленным Ninja предусмотрен `macos-debug` (Apple Clang).
Для проверки переносимой части без Ninja можно использовать Make:

```bash
cmake -S backend -B backend/out/macos-make -G 'Unix Makefiles' \
  -DCMAKE_CXX_COMPILER=/usr/bin/clang++ -DCMAKE_BUILD_TYPE=Debug
cmake --build backend/out/macos-make
ctest --test-dir backend/out/macos-make --output-on-failure
```

Сборка каркаса на macOS не означает поддержку будущего Linux recorder на macOS.
Локальные пути и выбранный compiler можно задавать в игнорируемом
`CMakeUserPresets.json`; общие presets должны оставаться переносимыми.

## Границы будущих компонентов

Это направления следующей реализации, а не уже существующие модули:

| Слой | Ответственность |
| --- | --- |
| `protocol` | Версионирование, framing/transport, команды/события, cancellation, capabilities и проверка входных сообщений |
| `engine` | Управление процессом/отладчиком, настоящие остановки и восстановление; Linux rr/GDB и возможный отдельный LLDB adapter |
| `trace` | Неизменяемые события, идентичность объектов/активаций, точные значения, покрытие записи и контрольные точки |
| `query` | Индексы и чистые запросы к истории, temporal predicates, отсутствие побочных эффектов в исследуемой программе |
| `instrumentation` | Clang/LLVM и runtime для наблюдаемых вычислений/жизненных циклов; отдельный opt-in профиль сборки |

Создавать каталоги и зависимости следует вместе с первой работающей функцией.
Форматы C++ и TypeScript должны проверяться общими fixtures; JSON из
`--self-check` намеренно не является дублирующим контрактом отладчика.

## Первые задачи backend-агента

1. Выполнить doctor и реальную rr fixture на Linux, сохранить версии CPU/kernel/
   compiler/debugger и результат прямого/обратного прохода. Не выдавать наличие
   исполняемого файла за capability. rr event number не равен source step.
2. По основному handoff согласовать семантику шага, объектной идентичности,
   неполных наблюдений и transport. Все отсутствующие capabilities остаются off.
3. Сделать минимальный настоящий цикл launch → stop → read → step → exit с
   отдельным жизненным циклом процесса и тестом без UI.
4. Исследовать точную трассу выражения и жизненного цикла, запись/воспроизведение
   и вмешательство как разные прототипы. Фиксировать ограничения, не заменять
   ненаблюдаемые данные догадками.
5. До разработки Clang-плагина зафиксировать одну major-версию LLVM и полный
   набор совместимых Clang/LLVM headers/libraries/toolchain. Текущий scaffold
   не зависит от ABI LLVM и ничего о совместимости будущего плагина не обещает.

`fixtures/rr-smoke.cpp` — обычная C++ программа для внешней проверки rr;
по умолчанию она не собирается. `tests/cli_smoke.py` проверяет границу процесса,
честность отчёта и отказ неподдерживаемых команд. Проверок debugger/trace пока нет.

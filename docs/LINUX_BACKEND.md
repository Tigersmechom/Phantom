# Linux: начало работы над backend phantom

Ветка: **`backend/linux`**. Общая линия интерфейса и согласованных контрактов:
**`main`**. Приоритеты исследований находятся в
[BACKEND_HANDOFF.md](BACKEND_HANDOFF.md), устройство каркаса — в
[backend/README.md](../backend/README.md).

## Какую ОС выбрать

Рекомендованная исходная среда: **Ubuntu Desktop 24.04 LTS, x86_64**, если компьютер
использует Intel/AMD. Это консервативная база с поддержкой до мая 2029 года;
существование более новой 26.04 LTS не требует переустановки уже работающего Linux.
Для машины, доступной только по SSH, подходит Ubuntu Server с теми же пакетами.
Выбор 24.04 не является обещанием поддержки любого CPU со стороны rr.
[Сроки Ubuntu](https://ubuntu.com/about/release-cycle),
[release notes 24.04](https://documentation.ubuntu.com/release-notes/24.04/).

Лучше начать на физическом Linux-компьютере. rr требует поддерживаемый CPU,
Linux kernel и аппаратные performance counters; в VM нужны виртуализированные
счётчики. ARM64 возможен на определённых процессорах, но требует отдельной
проверки. Docker сам по себе не создаёт недоступные аппаратные возможности.
[Требования rr](https://github.com/rr-debugger/rr#system-requirements).

Приложение на Mac и backend на Linux могут разрабатываться одновременно.
Удалённый transport пока не реализован: на этой ветке сейчас собирается только
standalone CLI. Будущая Linux-сессия исследует Linux executable/ABI/библиотеки;
она не выдаёт его поведение за нативное поведение той же программы на macOS.

## Клонирование и минимальные зависимости

Для SSH-варианта ключ пользователя должен иметь доступ к репозиторию. Команды
выполняются на Linux в терминале; исходники копировать вручную с Mac не нужно.

```bash
sudo apt update
sudo apt install git build-essential clang clangd lldb gdb cmake ninja-build \
  pkg-config libsqlite3-dev python3 rr
git clone git@github.com:Tigersmechom/Phantom.git
cd Phantom
git checkout backend/linux
bash scripts/backend-doctor.sh
```

Репозиторий публичный: если SSH-ключ на Linux ещё не настроен, вместо команды
`git clone` выше можно использовать HTTPS. Для клонирования ключ не нужен;
для будущего push агент отдельно настроит свою авторизацию на Linux. Приватный
SSH-ключ с Mac переносить не требуется.

```bash
git clone https://github.com/Tigersmechom/Phantom.git
cd Phantom
git checkout backend/linux
```

Если пакет `rr` недоступен в подключённых репозиториях, сначала проверить
`apt-cache policy rr` и официальную инструкцию установки rr. Это не блокирует
сборку каркаса. Нужна запись точной версии rr и kernel: пакеты дистрибутива
не обязательно совпадают с последним upstream release.
[Установка rr](https://github.com/rr-debugger/rr/wiki/Building-And-Installing).

`clang`, `clangd` и `lldb` здесь — имена пакетов дистрибутива, а не обещание
последнего API LLVM. Перед инструментацией выбрать одну major-версию, установить
соответствующие versioned packages и development headers/libraries, закрепить её
в presets/CI и описать миграции. Не смешивать произвольные версии compiler,
Clang plugin и libLLVM. Для текущего C++20 CLI LLVM dev packages не требуются.

```bash
cd backend
cmake --preset linux-debug
cmake --build --preset linux-debug
ctest --preset linux-debug
./out/linux-debug/phantom-backend --self-check
```

Последняя команда должна показать `status: scaffold-only`,
`protocol: not-implemented` и все capabilities `false`.
Это успешная проверка каркаса, **не готовый debugger**.

Workflow [.github/workflows/backend-linux.yml](../.github/workflows/backend-linux.yml)
собирает каркас и выполняет CTest на `ubuntu-24.04` при изменениях backend-ветки.
Он также запускает fixture как обычную программу. Запись и обратное исполнение
rr проверяются отдельно на выбранном компьютере: стандартный CI runner не
считается проверенной средой с нужными аппаратными счётчиками.

## Проверка rr на настоящем компьютере

`scripts/backend-doctor.sh` только читает сведения об ОС, CPU, версиях инструментов,
`perf_event_paranoid` и `ptrace_scope`. Он не устанавливает пакеты, не меняет sysctl,
не запускает запись и не объявляет replay поддерживаемым. Отсутствующий tool
выводится как `MISSING`; код завершения doctor не служит проверкой готовности.
Режима `--strict` нет: неизвестные аргументы отвергаются с кодом `2`. Сборку
проверяют CMake/CTest, а rr — отдельный пример ниже.

После сборки, находясь в `Phantom/backend`:

```bash
cmake --build --preset linux-debug --target phantom-rr-fixture
./out/linux-debug/phantom-rr-fixture
```

Ожидаемый обычный вывод: `total=12`, код завершения `0`. Затем создать отдельную
запись. Каталог создаётся заново, чтобы не перезаписывать прежнее исследование:

```bash
phantom_rr_dir=$(mktemp -d "$PWD/out/rr-probe.XXXXXX")
rr record -o "$phantom_rr_dir/trace" ./out/linux-debug/phantom-rr-fixture
rr replay -a "$phantom_rr_dir/trace"
rr replay "$phantom_rr_dir/trace"
```

В открывшемся GDB:

```text
break phantom_checkpoint
continue
print phantom_rr_total
continue
print phantom_rr_total
reverse-continue
print phantom_rr_total
quit
```

Критерий приёмки: две остановки дают **5**, затем **12**; обратный переход к
предыдущему вызову даёт **5**. Сохранить версии, команды, вывод и фактические
ограничения выбранного компьютера. Успех этого примера подтверждает только этот
пример на данной конфигурации, а не работу всех программ/санитайзеров/вмешательств.
Запись и replay запускать последовательно; не пересобирать fixture между ними.
Для архивирования зависимых файлов трассы изучить `rr pack`.
[Команды записи, replay и обратного хода](https://github.com/rr-debugger/rr/wiki/Usage).

Если запись запрещена настройками performance counters, сначала сопоставить
ошибку с версиями rr/kernel. Например, rr 5.9 на kernel >= 6.10 умеет работать
с `perf_event_paranoid=2`; blanket-требование всегда ставить `1` устарело.
Не менять `ptrace_scope` или perf sysctl автоматически и не запускать IDE от root.
Если конкретной конфигурации нужна корректировка, исследовать минимальную
необходимую настройку и задокументировать её отдельно.
[Release notes rr](https://github.com/rr-debugger/rr/releases).

## Работа двух агентов

- Backend-агент работает в `backend/linux`, в основном в `backend/**`; frontend
  продолжает развиваться на `main` или отдельных frontend-ветках.
- Изменения общего `src/backend-contract.ts` и семантики DTO согласуются отдельным
  небольшим PR вместе с fixtures и описанием совместимости. Не менять renderer
  для обхода отсутствующего наблюдения.
- Регулярно подтягивать общую линию, решая конфликты до следующего большого этапа:

```bash
git fetch origin
git checkout backend/linux
git merge origin/main
```

- Готовые законченные части с проверками отдавать через PR `backend/linux → main`.
  Не ждать завершения всего бэкенда перед первой интеграцией. После merge снова
  синхронизировать ветку с `main`; не делать принудительный push общей ветки.
- Сгенерированные binaries, CMake cache, trace, core dumps и зависимости в Git
  не добавляются. `backend/out/` и `backend/CMakeUserPresets.json` игнорируются.

## Интерфейс на Linux — отдельная проверка

Node/npm, Electron, Three.js и Unreal не нужны для работы над standalone backend.
Если потребуется UI, установить подходящий Node для текущих `package.json`/
lockfile и выполнить из корня:

```bash
npm ci
npm run build
npm run dev
```

Это browser frontend с демонстрационными данными; само по себе оно не включает
настоящий debugger. Для Electron отдельно нужны native rebuild `node-pty` и
проверка Linux shell, окон, клавиш и запуска процесса. Нынешняя macOS упаковка
и Apple-флаг `-arch` в существующем Basic compiler требуют отдельной адаптации;
успех standalone C++ сборки не является проверкой Linux desktop-приложения.
Не переносить `node_modules` и готовую `.app` с Mac. Unreal сейчас не требуется.

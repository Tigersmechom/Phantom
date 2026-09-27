# Первый backend frontend harness

Это отдельный маленький devtool для оценки Linux backend. Он не входит в Electron renderer и не требует React, Vite или node-pty: Node запускает `phantom-backend` как дочерний процесс, браузер получает простую панель через локальный HTTP server.

Из корня репозитория:

```bash
node tools/frontend-harness/server.mjs \
  --backend backend/out/linux-debug/phantom-backend \
  --workspace /tmp/phantom-harness-workspace
# открыть http://127.0.0.1:4177
```

Проверки стенда без браузерных зависимостей:

```bash
node tools/frontend-harness/ui-smoke.mjs
node tools/frontend-harness/smoke.mjs backend/out/linux-debug/phantom-backend
```

`--workspace` должен существовать или быть создан заранее. Backend сам создаёт `.phantom/backend-build`; исходник из поля редактора отправляется как immutable `main.cpp` snapshot.

Стенд использует тот же wire protocol: `connect`, `build`, `launch`, `step`, `continue`, `pause`, `stop`, `getState`, `listHistory`. Он показывает состояние, observation, оба потока вывода, ошибки и события/ответы NDJSON. Кнопка «Перезапустить backend» завершает дочерний процесс и начинает новую сессию. Для аргументов и environment используются отдельные строки; пробелы внутри значения сохраняются.

Поле «Ожидаемый cout» строит безопасную эвристику по строковым литералам в `std::cout`; оно не исполняет выражения и само по себе не является runtime-наблюдением. Поле «Незасброшенный cout (runtime)» заполняется только из явно подтверждённого backend-снимка внутреннего буфера glibc (`stdout.buffered`) и честно показывает недоступность для другой ABI или несинхронизированного `iostream`. Реальный stdout ниже содержит только уже сброшенные байты: при выводе в pipe `std::cout << "text\\n"` может оставаться в буфере до `std::flush`, `std::endl` или завершения программы.

Журнал событий читается курсором через `/api/events?after=N`. Если сервер сообщает `gap`, часть журнала уже вытеснена; после этого нужно запросить `Get state` и не считать пропущенную команду успешно завершённой. Стенд рассчитан на одну активную вкладку: несколько вкладок используют один backend и могут менять общую сессию.

## Что проверить вручную

1. Build и Launch: после Launch дождись `state.phase=stopped`, проверь `stop.reason=entry`, source location и `processInstanceId`.
2. Step/Continue/Pause/Stop: порядок `accepted`, `observation`, `state`, `commandFinished`; после Stop должны сохраниться stdout и stderr. Для долгого Continue кнопка Pause остаётся доступной.
3. Введите Unicode, `NUL` нельзя вставить обычным textarea; проверьте большие строки через отдельный тест backend.
4. Укажите аргументы и environment по одному на строку (`KEY=value`), убедитесь, что они доходят до программы.
5. History после нескольких остановок: панель покажет номера остановок, их label и `stopId`; это индекс снимков, а не перемотка процесса.
6. Закройте backend или нажмите Restart во время операции: UI должен показать ошибку/новую сессию, а не продолжить старое состояние.
7. Переполните журнал большим числом событий: после `gap` состояние нужно сверить через `Get state`.
8. Для `while (true) { continue; }` Step не может найти следующую source line: через короткий timeout появится `step-timeout`/`STEP_TIMEOUT`, сессия останется живой. Используй Continue → Pause или instruction step.

Это диагностический стенд, поэтому assertion ignore, memory, variables write, replay и настоящий frontend Electron пока явно не обещаются capabilities backend.

События harness читаются курсором: `/api/events?after=N` возвращает только записи
после `N`, `nextCursor` и признак `gap`. Это предотвращает потерю событий при
параллельных запросах одного клиента; при `gap:true` нужно заново запросить
state и не считать пропущенную команду успешно завершённой.

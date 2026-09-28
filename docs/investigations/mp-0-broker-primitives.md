# MP-0: пробник примитивов брокера на папку

Дата: 2026-09-28. Машина: Windows 10 Pro 10.0.19045 x64. Снимок плана: `docs/multiprocess-broker-plan.md` (`4882ebb`).

Пробники: `probes/winjob.py` (ctypes-обвязка), `probes/mp0_probe.py` (оркестратор,
пункты 1-4), `probes/broker_helper.py`, `probes/client_helper.py` (третьи
процессы), `probes/killtest.py`, `probes/killtest2.py` (точечная проверка
KILL_ON_JOB_CLOSE / IOCP). `winrsbox/crates/winrsbox-policy/examples/mp0_redb_probe.rs`
(redb, пункт 5). `probes/` не коммитится — рабочая площадка.

## Итог одной строкой на пункт

1. Вложенные job (папка → сессия → сторонний job с хэндлом 0x901) — **подтверждено полностью**.
2. `JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO` на job папки после всех сессий — **подтверждено**.
3. `IsProcessInJob` из третьего процесса по дублированному хэндлу — **подтверждено**; минимальное право — `JOB_OBJECT_QUERY`.
4. `DuplicateHandle` job-хэндла брокер→клиент, клиент назначает процессы — **подтверждено**.
5. redb: `DatabaseAlreadyOpen` у второго открытия, восстановление после `TerminateProcess` — **подтверждено**, восстановление быстрее, чем предполагалось (~8-12 мс, с первой попытки).
6. Хук при разрыве pipe: переподключение + повторный `Hello` — **подтверждено кодом**; найден реальный блокер для MP-5 (см. ниже).
7. WFP: пересечение фильтров двух сессий — **не пересекаются, опровергнутых допущений плана нет**.

---

## 1. Вложенные job (папка → сессия → сторонний job)

Пробник: `probes/mp0_probe.py` (`session_a_setup`, `session_b_setup`,
`third_level_nesting_0x901`, `kill_on_job_close_scoping`).

Сценарий: `folder_job = CreateJobObjectW(NULL, NULL)` без единого вызова
`SetInformationJobObject` (без лимитов, без `KILL_ON_JOB_CLOSE`, без
`BREAKAWAY_OK` — просто ничего не выставлено, значит breakaway запрещён по
умолчанию ОС). Гость A: `AssignProcessToJobObject(folder_job, hA)`, затем
создан `session_job_A` (`JOBOBJECT_BASIC_UI_RESTRICTIONS.UIRestrictionsClass =
JOB_OBJECT_UILIMIT_HANDLES`, `JOBOBJECT_EXTENDED_LIMIT_INFORMATION.LimitFlags =
KILL_ON_JOB_CLOSE | PROCESS_MEMORY`, `ProcessMemoryLimit = 256 МБ`),
`AssignProcessToJobObject(session_job_A, hA)` — второй уровень вложения.
Аналогично гость B в `session_job_B`.

Результат (реальный прогон):
```
assign_folder_ok=True assign_session_ok=True   (оба уровня, оба гостя)
guestA_in_folder_job=True guestB_in_folder_job=True
```

Третий уровень (как codex/process-wrap кладёт СВОЕГО ребёнка в свой job):
`job_codex = CreateJobObjectW(...)`, затем `OpenProcess(pidA, 0x901)` —
маска `0x901 = PROCESS_TERMINATE(0x1) | PROCESS_SET_QUOTA(0x100) |
PROCESS_SUSPEND_RESUME(0x800)`, **без** `PROCESS_QUERY_(LIMITED_)INFORMATION`
(та же маска, что реально видел codex — `docs/checkpoints/2026-09-23-2300.md:24`).
`AssignProcessToJobObject(job_codex, h_0x901)` **успешен**:
```
assign_ok=True assign_err=0
query_call_denied_as_expected=True   -- GetExitCodeProcess(h_0x901) реально падает без query-прав
guestA_in_job_codex_after_assign=True
```
Подтверждает документированное требование `AssignProcessToJobObject`:
хэндлу процесса достаточно `PROCESS_SET_QUOTA | PROCESS_TERMINATE` — `QUERY`
не нужен, и именно поэтому реальный хэндл codex (0x901) работает для
третьего уровня вложения, но не годится для `GetProcessId`/`GetExitCodeProcess`
(что и заставило launcher опознавать такие хэндлы через `NtCompareObjects`,
см. чекпойнт).

KILL_ON_JOB_CLOSE — область поражения (`probes/killtest.py`,
`probes/killtest2.py`, `mp0_probe.py::kill_on_job_close_scoping`): закрытие
**последнего** хэндла `session_job_A` убивает дерево A и **не трогает** B:
```
a_alive_before=True  b_alive_before=True
a_alive_after_session_job_close=False   b_alive_after_session_job_close=True
```
Процесс A после убийства всё ещё числится в `folder_job`
(`IsProcessInJob` возвращает True для мёртвого, но не закрытого хэндла) —
не мешает плану, просто нюанс поведения ядра (хэндл процесса ещё открыт,
объект процесса в zombie-состоянии).

Вывод для плана: раздел «Объекты папки» (архитектура, п. Job папки / Job
сессии) и MP-1 подтверждены без изменений. Про breakaway отдельно
эмпирически не проверялось (никто не пытался реально «сбежать» из job) —
это документированное поведение ОС по умолчанию, на которое уже полагается
существующий sandbox-job проекта; переоткрывать не требуется.

## 2. `JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO` на job папки

Пробник: `mp0_probe.py::iocp_active_process_zero`, `probes/killtest2.py`.

IOCP создан один раз и ассоциирован **только** с `folder_job`
(`JobObjectAssociateCompletionPort`). Полный прогон с двумя сессиями:
```
exit_process_events: ... 43436(client) @0.478s, 37280/30972 @~3.23s, 14272/14464(B) @13.15s
active_process_zero_events: [13.16]
```
`ACTIVE_PROCESS_ZERO` пришёл **один раз**, ровно после того, как умер
последний процесс последней ещё живой сессии (B), а не после каждой сессии
по отдельности — подтверждает: сообщение приходит на **весь** job папки
(агрегированный счётчик активных процессов по всей вложенной иерархии), как
и написано в плане.

Отдельный нюанс, не влияющий на план, но полезный для MP-8 (`status`): при
убийстве через `KILL_ON_JOB_CLOSE` (закрытие последнего хэндла
`session_job_*`) кернел **не** шлёт `JOB_OBJECT_MSG_EXIT_PROCESS` для убитых
процессов — только `ACTIVE_PROCESS_ZERO`, если это опустошило job папки
(`probes/killtest2.py`: 3 процесса созданы, 0 `EXIT_PROCESS`, `ACTIVE_PROCESS_ZERO`
через 5 мс после закрытия). Если план в MP-8 захочет считать процессы через
`EXIT_PROCESS`-сообщения — на пути KILL_ON_JOB_CLOSE это не сработает; для
одной сессии `ACTIVE_PROCESS_ZERO` на `session_job` (если бы IOCP был
ассоциирован ещё и с ним) — не проверялось, план этого и не предполагает.
Правок в план не требует (план опирается только на `ACTIVE_PROCESS_ZERO`
на job папки), фиксирую как замечание.

## 3. `IsProcessInJob` из третьего процесса (брокера)

Пробник: `probes/broker_helper.py`, запущен как отдельный `python.exe`
процесс через `subprocess.Popen` (не через `CreateProcess` из пробника
напрямую — то есть настоящий третий, независимый процесс). Хэндл job папки
передан ТОЛЬКО через `DuplicateHandle(текущий_процесс, folder_job,
hBrokerProcess, ..., <права>, FALSE, 0)` — брокер job не создавал и не
называл по имени (job безымянный).

Три варианта прав протестированы:
- `JOB_OBJECT_QUERY` (0x4) на гостя ДРУГОЙ сессии (B) → `IsProcessInJob = True`, `err=0`.
- та же маска на процесс вне job (сам пробник-оркестратор, `os.getpid()`) → `IsProcessInJob = False`, `err=0`.
- `JOB_OBJECT_ASSIGN_PROCESS` (0x1) БЕЗ `QUERY` на того же гостя B → `IsProcessInJob` **падает**, `GetLastError=5` (`ERROR_ACCESS_DENIED`).

```json
"guest_in_folder_job_with_query_rights": {"ok": true, "err": 0}
"outside_process_in_folder_job": {"ok": false, "err": 0}
"is_process_in_job_needs_query_right": {"ok": null, "err": 5}
```

Вывод: минимальное право на хэндл job для `IsProcessInJob` — **`JOB_OBJECT_QUERY`**
(0x4). `JOB_OBJECT_ASSIGN_PROCESS` его не заменяет. Для MP-3/MP-4 (брокер
должен опознавать гостей через `IsProcessInJob`) брокеру достаточно
дубликата с `JOB_OBJECT_QUERY` — подтверждает план (стр. 53 плана уже
указывает `JOB_OBJECT_ASSIGN_PROCESS | JOB_OBJECT_QUERY` для клиентского
хэндла, что покрывает оба назначения — опознание и назначение).

## 4. `DuplicateHandle` job-хэндла: брокер → клиент, клиент назначает

Пробник: `probes/client_helper.py`, отдельный процесс, никогда не
создававший `folder_job`. Получил дубликат с правами ровно
`JOB_OBJECT_ASSIGN_PROCESS | JOB_OBJECT_QUERY` (0x5) — та же комбинация, что
план указывает для шага 4 архитектуры («Брокер... дублирует... folder job
(`JOB_OBJECT_ASSIGN_PROCESS | JOB_OBJECT_QUERY`)»). Клиент запустил
собственного гостя и назначил его в job папки через дублированный хэндл:
```json
"assign_to_dup_folder_job": {"ok": true, "err": 0}
"guest_confirmed_in_job": {"ok": true, "err": 0}
"guest_alive_after_assign": true
```
Полное совпадение с планом — правки не требуются.

## 5. redb 2.6.3: `DatabaseAlreadyOpen` и восстановление после `TerminateProcess`

Файл: `winrsbox/crates/winrsbox-policy/examples/mp0_redb_probe.rs`.
Запуск: `cargo run -p winrsbox-policy --example mp0_redb_probe`.

БД предзаполнена 5000 записей (~80 байт значение, путь-подобная строка) —
файл 1 589 248 байт, порядок величины реальной `policy.redb` после долгой
сессии. Процесс-владелец открывает `Database::create` (эквивалент
`Policy::open_or_create_with_layout`), сигналит готовность, блокируется.
Оркестратор:

1. Второй `Database::create` на тот же путь, пока владелец жив:
   `Err(DatabaseAlreadyOpen)` — 100% совпадений в 4 прогонах, занимает
   233-483 мкс (не блокирует, падает сразу).
2. `child.kill()` (= `TerminateProcess` на Windows) — без `Drop`, без flush.
3. Цикл `Database::create` до успеха: **успех с первой попытки** во всех 4
   прогонах, за 7.3-11.8 мс.
4. Данные после восстановления — все 5000 записей на месте.

```
[orchestrator] second Database::create while owner alive -> Err(DatabaseAlreadyOpen) is_DatabaseAlreadyOpen=true (took 379.2µs)
[orchestrator] owner TerminateProcess'd + reaped in 909.5µs
[orchestrator] recovery: Database::create succeeded after 1 attempt(s), 7.3092ms
[orchestrator] post-recovery row count: 5000
```

Вывод для плана: подтверждает раздел «Смена брокера (failover)» (стр. 69:
«Кто открыл — новый брокер: redb сам восстанавливает базу после падения»).
Фактическая цифра (~8-12 мс, первая попытка) лучше, чем можно было
закладывать «на глаз» — polling-цикл в MP-7 может быть простым (например,
retry раз в 20-50 мс без экспоненциального backoff) и не нуждается в долгом
бюджете. Один нюанс: `DatabaseAlreadyOpen` определяется мгновенно (файловая
блокировка ОС, не application-level heartbeat) — значит выбор роли по
блокировке базы (MP-2) не потребует таймаутов вовсе, только один вызов
`Database::create`.

## 6. Хук при разрыве pipe (анализ кода, без запуска)

Файлы: `winrsbox/crates/winrsbox-hook/src/ipc/ipc_client/mod.rs`,
`.../ipc/trusted_boot.rs`, `winrsbox/crates/winrsbox-launcher/src/pipe_server/ownership.rs`.

- **Переподключение**: `ensure_ipc_and` (`ipc_client/mod.rs:419-500`) — если
  `pt.ipc` пуст, `SyncClient::connect(PIPE_NAME)`, проверка
  `verify_pipe_server_identity`, и **безусловно** отправляет `Hello` на
  КАЖДОЕ новое соединение (`ipc_client/mod.rs:461-465`, комментарий:
  «Always re-send Hello on every new connection — the server handler for
  any previous connection is gone»). Отправка `Hello` НЕ зависит от
  `hello_sent` — `hello_sent` гейтит только одноразовые побочные эффекты
  (`flush_install_errors`, `inject_guard::arm()`), не сам факт отправки.
  **Подтверждает план дословно** («После переподключения хук заново шлёт
  Hello»).
- **`hello_sent` не сбрасывается при `*opt = None`** (план это уже
  фиксирует, стр. 60) — подтверждено чтением кода: `PerThread.hello_sent`
  живёт в FLS-слоте на весь процесс жизни ОС-потока, `try_send` на ошибке
  только обнуляет `opt`, флаг не трогает. Последствие ровно то, что план
  описывает: пере-Hello после failover будет отправлен (это не зависит от
  флага), но повторной «первой» инициализации (flush install errors, arm
  guard) не будет — не критично, эти эффекты одноразовые по замыслу.
- **Сервер не знает PID → fail-closed**: `decide_context(conn_pid: Option<u32>)`
  (`ownership.rs:188-193`) — `conn_pid.ok_or(())?`, затем ищет запись в
  `global_proc_info`; отсутствие Hello ИЛИ отсутствие/протухшая запись →
  `Err`. Тесты `decide_context_requires_hello`,
  `decide_context_refuses_when_entry_missing` (`ownership.rs:546-560`)
  закрепляют именно это — никакого permissive fallback. Подтверждает план.
- **Реальный блокер для MP-5, обнаруженный при чтении кода (не был явно
  назван в плане)**: `PIPE_NAME: OnceLock<String>` (`ipc_client/mod.rs:140`)
  устанавливается **один раз** (`OnceLock::set`, молча игнорирует повторный
  set) при первой успешной загрузке конфигурации. **Сегодня в коде нет
  пути, которым хук мог бы узнать НОВОЕ имя pipe после failover** — после
  смены брокера `ensure_ipc_and` продолжит вызывать
  `SyncClient::connect(PIPE_NAME.get())` со СТАРЫМ именем, которое умерший
  брокер уже не слушает; переподключение технически «сработает» (Hello
  будет отправлен), но подключаться будет некуда. План (MP-5, стр. 103:
  «Хук: pipe и доверенный набор из folder section») уже подразумевает
  замену источника конфигурации, но конкретный механизм — что мешает
  сегодня — это именно неизменяемость `PIPE_NAME` (`OnceLock`, а не,
  например, `RwLock`/atomic swap). Фиксирую как уточнение для MP-5:
  реализация должна заменить `OnceLock<String>` на что-то перезаписываемое
  (или добавить отдельный «текущее имя pipe» источник, читаемый из folder
  section при каждом реконнекте, как и планировалось).

## 7. WFP: пересечение фильтров/провайдеров/сублееров двух сессий

Файл: `winrsbox/crates/winrsbox-launcher/src/contain/wfp/mod.rs` (анализ
кода, без запуска — по заданию допустимо).

- Никакого собственного provider/sublayer не создаётся. Все фильтры кладутся
  в **встроенный** `FWPM_SUBLAYER_UNIVERSAL` (строки 274, 369, 455, 525, 594).
  Значит, коллизий по GUID/имени provider/sublayer в принципе не существует
  — нет объектов, которые могли бы столкнуться.
- Каждая сессия открывает **отдельную** `FWPM_SESSION0` с флагом
  `FWPM_SESSION_FLAG_DYNAMIC` (строка 213). Динамическая сессия WFP:
  фильтры, добавленные в её рамках, автоматически удаляются ядром при
  закрытии её engine-хэндла ИЛИ при завершении процесса-владельца (даже
  аварийном) — то есть сессия A не может пережить свой процесс и задеть
  сессию B ни при штатном, ни при аварийном выходе.
- Каждый `FwpmFilterAdd0` вызывается с `FWPM_FILTER0{ ..Default::default() }`
  — `filterKey` остаётся нулевым GUID, что по документации WFP означает
  «ядро присвоит новый уникальный GUID и `filterId`» на каждый вызов.
  `displayData.name` (`"winrsbox-block"`/`"winrsbox-permit"`/
  `"winrsbox-block-v6-cidr"`/`"winrsbox-block-port-{port}"`/...) —
  косметическая строка, не ключ; две сессии могут получить БАЙТ-В-БАЙТ
  одинаковое `displayData.name`, это не создаёт коллизии.
- Очистка при выходе (`impl Drop for WfpEngine`, строки 623-635) удаляет
  **только** ID из собственного `Vec<u64> filter_ids`, набранного вызовами
  ЭТОГО ЖЕ `WfpEngine` — никакого перечисления/удаления «по имени» или «по
  провайдеру», значит чужие фильтры физически не могут быть задеты кодом.
- Единственный сценарий пересечения — если ДВЕ сессии сэндбоксят один и тот
  же `app_path` (тогда оба набора фильтров получат идентичный
  `FWPM_CONDITION_ALE_APP_ID`). Это не коллизия, а безопасное дублирование:
  у обоих разные `filterId`, у BLOCK выставлен
  `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` (жёсткий блок, строки 372, 457,
  520, 589) — оба фильтра независимо и одинаково блокируют, конфликта нет.

Вывод: план (открытый вопрос, стр. 122: «WFP-фильтры ставит каждый launcher
для своей цели. Нужно проверить, что имена и ключи фильтров двух сессий не
пересекаются») — **закрыт**. Пересечений нет ни по имени, ни по ключу, ни по
sublayer/provider, потому что собственных именованных объектов WFP-код не
создаёт вообще, а `filterId`/`filterKey` присваивает ядро уникально на
каждый вызов. Правка внесена в план (раздел «Открытые вопросы» → отмечен
закрытым по MP-0).

---

## Файлы

- `probes/winjob.py`, `probes/mp0_probe.py`, `probes/broker_helper.py`,
  `probes/client_helper.py`, `probes/killtest.py`, `probes/killtest2.py` —
  Python ctypes-пробники (не коммитятся, рабочая площадка).
- `winrsbox/crates/winrsbox-policy/examples/mp0_redb_probe.rs` — Rust-пробник
  redb (без новых зависимостей).
- `docs/multiprocess-broker-plan.md` — обновлён (см. пометки «по MP-0»).

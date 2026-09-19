# Аудит безопасности winrsbox — 2026-09-19

Метод: 6 параллельных суб-агентов аудитили ~48k строк по зонам (hook core, dir_filter/IPC, proc/memory/token/system guards, reg/shell/com/alpc/ui guards, policy, ipc/launcher); npm-инсталлер и сборку проверены отдельно. Каждая находка уровня critical/high дополнительно верифицирована построчным перечитыванием кода.

Обозначения: ✅ = подтверждено чтением кода (не live-эксплуатация — репро не запускались, только трассировка).

## 🔴 Critical

### 1. `..`-обход: запись на реальный диск вне песочницы ✅
`compute()` решает по литеральной гостевой строке: `path_contained_in` (policy/src/decide.rs:320-330) — голый префикс-тест, `nt_to_dos_lower` (policy/src/path.rs:18-39) не фолдит `..`, комментарий hooks.rs:679-682 прямо говорит: «`..` пусть разрешает ядро». Passthrough-рука (hook/src/fs_hooks.rs:313-363) отдаёт ObjectName ядру как есть. `NtCreateFile("\??\d:\<proj>\..\..\payload.exe", CREATE_ALWAYS)` — префикс совпал с project_root → Passthrough → ядро резолвит `..` → файл создаётся на реальном диске. При этом `mirror_into_overlay` (policy/src/path.rs:105-118) `..` вырезает — санитизация применена всюду, кроме единственного места, которому разрешено трогать реальный диск.
Фикс: фолд/отвергать ParentDir-компоненты до decide() и containment-теста (как dest_is_escape для rename).

### 2. `Req::RecordOverlay` без валидации → произвольный путь записи CoW ✅
launcher/src/pipe_server.rs:1080-1083 кладёт гостевую строку `overlay` в OVERLAY_IDX как есть (decide.rs:369: `t.insert(key, overlay)`), а `compute()` на индекс-хит возвращает её как destination (decide.rs:998-999, 1020-1024). Hook-сторона не проверяет: `prepare_overlay` (hooks.rs:1014-1041) делает create_dir_all + fs::copy по любому пути. Гость — легитимный pipe-клиент — шлёт `RecordOverlay{orig: "D:\proj\f.txt", overlay: "C:\...\Startup\pwn.bat"}` и следующая запись в `f.txt` летит в реальный Startup. Deny-правила спасают, дефолтная CoW-изоляция — нет.
Фикс: валидировать `overlay` ∈ опубликованных overlay_roots и == mirror(orig).

### 3. Секция `Local\WinRsBoxSession`: фиксированное имя, PAGE_READWRITE, дефолтный DACL ✅
launcher/src/session_section.rs:57-67 (CreateFileMappingW, security attrs = None), имя в ipc/src/lib.rs:22, проверка ALREADY_EXISTS отсутствует. Любой процесс той же сессии — включая гостя — переписывает `pipe_name`, `dll_path`, `overlay_roots`, `disable_hooks`, `allow_rwx` (SessionConfig, ipc/src/lib.rs:28-52). Отравленный `dll_path` → в новые дочерние процессы инъектится чужой DLL; отравленный `pipe_name` → все решения отдаёт атакерский pipe. Hook доверяет секции слепо.
Фикс: случайное имя + отказ при коллизии + DACL или HMAC над содержимым.

## 🟠 High

- ✅ Env-килл-ключи из гостевого окружения: `FS_SANDBOX_DISABLE_HOOKS` (hook/src/memory_guard.rs:1113, hooks.rs:1599), `FS_SANDBOX_ALLOW_RWX` перечитывается на каждом решении (memory_guard.rs:136). Гость делает SetEnvironmentVariable + spawn — ребёнок с выключенным memory guard. Конфиг гвардии — out-of-band.
- ✅ Системный паттерн «сиблинг-API не закрыт» (грепы по всему репо — экспортов нет): `NtAllocateVirtualMemoryEx` (VirtualAlloc2 обходит RWX/foreign-alloc guards), `NtAlpcConnectPortEx`/`NtSecureConnectPort` (весь ALPC guard мимо, имя порта в ObjectAttributes), `ShellExecuteA`/`ExA`, win32u `NtUserSendInput` (мимо ui_guard), `DllGetClassObject` (in-proc COM-активация без deny/kill).
- ✅ Спуф denylist спавна: `extract_image_path` (hook/src/proc_guard.rs:883-899) читает `params->ImagePathName` (0x60) из caller-supplied блока, тогда как ядро грузит образ по `PsAttributeImageName` (доступор attr-5 уже есть — proc_guard.rs:793). Фикс: матчить denylist по атрибуту 5.
- ✅ token_guard fail-open: `owner_pid != 0 && ...` в обоих хуках (hook/src/token_guard.rs:444, 512) — при неудаче `thread_owner_pid` → 0 → call_original() → импersonация чужого потока/токена. Нужен deny при `owner_pid == 0`.
- ✅ Неверный NTSTATUS: `STATUS_NO_MORE_FILES = 0x0000_0104` (hook/src/dir_filter.rs:776) — это STATUS_NO_MORE_ENTRIES, severity SUCCESS. NT_SUCCESS(0x104)=true, запись в буфере не вычищена, Information не обнулён (dir_filter.rs:436-438) → FindNextFile отдаёт скрытый файл (whiteout/`.winrsbox`). Правильно: 0x80000006 + Information=0.
- ✅ PID-гейт пайпа insert-only: нет `.remove()` в launcher (grep); `is_owned_client_pid` (pipe_server.rs:239-257) доверяет номеру PID + parent-walk без liveness. Реюз PID → внешние процессы становятся пирами протокола (умножает Critical №2). Фикс: prune по смерти + проверка creation time.
- ✅ Самозамена hook.dll через passthrough-политику: дефолтные правила дают `write: passthrough` на `%APPDATA%\Roaming\npm` (launcher/src/sandbox.rs:116-119), инсталлер кладёт `hook.dll` ровно туда (npm/winrsbox/scripts/install.js → native/). Гость перезаписывает DLL на реальном диске → следующий запуск лоадера вне песочницы. Тот же класс: `.cargo/.rustup/.npm`.
- ✅ Async-энумерация мимо фильтра: STATUS_PENDING возвращает управление до заполнения буфера → фильтрация не выполняется → гостю уходит сырой листинг (hook/src/dir_filter.rs process_dir_output, статус-шорткат :729-731).
- ✅ Class-48 маскинг мёртв для Path-1 layout: `rewrite_file_name_information` зовёт только `unmirror_from_overlay` (hook/src/path_info_guard.rs:181-187), который требует legacy-компоненту `<диск>` (policy/src/path.rs:269-288 → None) → raw `.winrsbox\...` путь утекает через GetFinalPathNameByHandleW. Задокументированный residual «class-9» на деле шире; sibling hooks.rs dual-layout уже умеет (дрейф миграции).

## 🟡 Medium

- Unaligned-UB старого класса (фикс 9d73d34 применён не везде): fs_metadata_guard.rs:271-272, 451-464; inject.rs:221-229; walker'ы dir_filter.rs:414-435, 599-621.
- `FILE_WRITE_ATTRIBUTES` не считается записью (hooks.rs:235-240) → SetFileTime мутирует реальные файлы вне project_root.
- Case-folding анархия: запись ключей `to_lowercase()`, чтение `ensure_lower()` → на не-ASCII путях OVERLAY_IDX/whiteout расходятся (decide.rs:367 vs 997/560/574; registry.rs:192-208 vs 121); `project_root_lower` фулл-юникодом vs гостевой ASCII-фолд — İ-класс префикс-алиас.
- `when.exe` хранится не в нижнем регистре (launcher/src/cli/rule.rs:76, policy/src/db.rs:193), матч против lowercased (db.rs:252-256) — exe-scoped правила мертвы.
- `pattern_matches_exact` без фильтра пустых сегментов (policy/src/path.rs:415-416 vs 331-333) — моки обходятся `c:\fake\\x`.
- Реестр: `NtCreateKey(KEY_READ)` создаёт ключи под deny-префиксами (reg_hooks.rs:412); tombstone не проверяется при `value_name=None` (registry.rs:157-175).
- memory_guard: substring `\windows\system32\` как trusted-path + 64MB cap скана (memory_guard.rs:279-285, 809-875); `NtWriteVirtualMemory` — контент-скан вместо deny (:922-937).
- Unbounded walks по hostile буферам (attr-list `TotalLength` proc_guard.rs:814-830; params 0x60) → AV в hook-контексте.
- `anti_rec` fail-open: любой код внутри hook-фрейма вызывает API неограждённым (anti_rec.rs:60-71).
- inject_guard: спуф по basename `hook.dll` + empty stack → «system» (inject_guard.rs:121, 126-141).
- violations.log — ручной JSON без экранирования control-символов → фальшивые записи (pipe_server.rs:1173-1252).
- trust.rs декоративен: вердикт подписи только в println (launcher/src/main.rs:626-634).
- WFP: APP_ID-условие не реализовано (`_app_path` игнорируется, wfp.rs:137), без элевации — молча нет network-контейнмента, с элевацией — блоки на всю машину; NetDecide всегда allow (pipe_server.rs:1323-1338).
- Рост памяти: hot_stats insert-only; RegisterChild >64 ломает WaitForMultipleObjects (main.rs:877); 16MiB×128 слотов.
- `build_cmdline` портит не-ASCII аргументы (byte→char, sandbox.rs:464).
- Шелл-guard: lpParameters скан обрезан на 1024 байтах, lpVerb («runas») не проверяется (shell_guard.rs:230-236, 417-438).

## Low

`FS_SANDBOX_NO_TRACK` и sentinel `create_time==0` в process_tracker (fail-closed, но тестовые механизмы в prod); Mock fail-open на malformed decision (fs_hooks.rs:479-484, 709-714); decide_traced расходится с compute (decide.rs:691 vs 944-946); rule_upsert не обновляет snapshot/кэш (policy_impl.rs:133-149); init-event spoof при отказе RNG (main.rs:199-204); rename-Passthrough сохраняет racy RootDirectory (fs_metadata_guard.rs:351-353); `resolve_handle_path` не валидирует `returned` (inject.rs:204-237); unmirror legacy-дискриминатор «first comp == drive» misfire на `c:\c\...`; bare-relative CWD ветка без unmirror (hooks.rs:439-451); host-подавление `eprintln!` в ipc_client fail-path (ipc_client.rs:290-385).

## npm installer (install.js)

Клонирует mutable HEAD без пиннинга коммита/тега (`git clone --depth 1`, npm/winrsbox/scripts/install.js:71) — доверие репо на момент установки; `--locked` спасает зависимости, но не код. Рекомендация: пиннить тег. Остальное чисто.

## Системные паттерны и порядок фиксов

1. Все решения о контейнменте принимаются по гостевой строке без нормализации компонентов — фолд `..`/`.` один раз в compute() закрывает Critical №1 и часть полиси-багов.
2. Валидировать wire-данные политики: RecordOverlay.overlay ∈ overlay_roots и == mirror(orig); секции сессии — ACL/имя/HMAC.
3. Конфиг гвардии out-of-band вместо env.
4. Правило «закрыл API — закрой сиблингов» + CI-чек по списку unhooked-экспортов.
5. Инвертировать все `== 0 → allow` ветки в deny.
6. Дрейф миграций (Path-1, alignment, C1-фикс) применялся точечно — пройтись по сиблингам каждого фикса.

## Ограничения

Live-эксплуатация не проводилась — все находки получены трассировкой кода. LOW-находки и часть MEDIUM не ре-верифицированы построчно оркестратором (помечены по отчётам суб-агентов).

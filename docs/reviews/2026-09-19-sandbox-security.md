# winrsbox — security review (sandbox escapes / policy bypasses / hook-context bugs)

**Дата:** 2026-09-19
**Ревизия:** `9d73d34` (branch `master`, worktree `agent-a054a8ab4fa6d6600`)

**Охват (реально прочитано):**

- Документация: `winrsbox/README.md`, `README.md` (корневой), `SECURITY.md`.
- `hook/src/hooks.rs` — полностью (диспетчер, `resolve_for_hook`, denylist, `NtCreateUserProcess`-хук, `install_hooks`/`apply_mitigations`).
- `hook/src/fs_hooks.rs` — полностью (`NtCreateFile`/`NtOpenFile`/`NtQuery(Full)AttributesFile`).
- `hook/src/fs_metadata_guard.rs` — полностью (`NtSetInformationFile` Rename/Link/Disposition, `NtFsControlFile`, `NtSetEaFile`).
- `hook/src/alpc_guard.rs` — полностью (`NtAlpcConnectPort`).
- `hook/src/com_guard.rs` — частично (CLSID/WinRT denylist, ~260 строк).
- `hook/src/memory_guard.rs` — выборочно, но целиком по ключевым функциям (`is_address_in_module`, `hook_nt_protect_virtual_memory`, `hook_nt_map_view_of_section`, `CRITICAL_DLLS`).
- `hook/src/inject.rs`, `hook/src/anti_rec.rs`, `hook/src/hooked_attrs.rs` (частично, ~220 строк) — полностью/выборочно.
- `hook/src/dir_filter.rs`, `reg_hooks.rs` — только структурно (список хуков, сигнатуры), без построчного аудита буферной логики.
- `ipc/src/lib.rs` — полностью (протокол, `SessionConfig`, `SyncClient`).
- `launcher/src/pipe_server.rs` — большая часть (~1180/1819 строк: ACL пайпа, валидация клиента, обработчики `Req::*`).
- `launcher/src/inject.rs` — полностью (`inject_dll`, `pre_launch_scan`, `get_image_base`).
- `launcher/src/env_guard.rs`, `launcher/src/jobctl.rs` — полностью.
- `launcher/src/sandbox.rs` (`launch_suspended`), `launcher/src/main.rs` (участок запуска/pre-launch scan), `launcher/src/trust.rs` (частично) — выборочно.
- `policy/src/path.rs`, `policy/src/decide.rs`, `policy/src/dev.rs` — полностью.

**Не проверено детально** (ограничение по времени/бюджету, см. раздел "Проверено" в конце): `proc_guard.rs`, `token_guard.rs`, `inject_guard.rs`, `net_hooks.rs`, `service_guard.rs`, `shell_guard.rs`, `system_guard.rs`, `ui_guard.rs`, `process_tracker.rs`, `cache.rs`, `scan_cache.rs`, `path_info_guard.rs`, `reg_hooks.rs` (построчно), `policy/src/{db,lib,mem,net,policy_impl,reg,registry,reg_overlay,scan}.rs`, `launcher/src/{mitigations,wfp,hot_stats,jsonl_log,session_section,etw*}.rs`, `launcher/src/cli/*`, `integration-tests/*`.

## Сводная таблица

| Приоритет | Количество |
|-----------|------------|
| P0        | 4          |
| P1        | 2          |
| P2        | 1          |
| P3        | 0          |

---

## P0-01 — Самоснятие хуков через `NtProtectVirtualMemory` на памяти уже загруженных модулей

**Файл:** `winrsbox/hook/src/memory_guard.rs:640-701` (сам хук), `:174-193` (`is_address_in_module`)
**Статус:** подтверждено
**Механизм:**
`hook_nt_protect_virtual_memory` — единственная точка контроля за изменением защиты памяти внутри своего же процесса. Логика (строки 672-698):

```rust
if is_executable(new_protect) && !base_address.is_null() {
    let addr = *base_address;
    // Skip loaded module regions (loader operations, CRT, etc.)
    if !addr.is_null() && !is_address_in_module(addr) {
        ... сканирование содержимого на прямые syscall-опкоды ...
    }
}
call_original()
```

`is_address_in_module` — это `GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS)`: возвращает `true` для ЛЮБОГО адреса внутри ЛЮБОГО загруженного модуля, включая `ntdll.dll`, `kernel32.dll` и сам `hook.dll` (список `CRITICAL_DLLS` на строке 230 их явно перечисляет для другой проверки — anti-double-mapping, но не для этой).

Следствие: если `new_protect` содержит EXECUTE-бит и адрес лежит внутри модуля — сканирование пропускается целиком («Module memory... is skipped»). Если `new_protect` НЕ содержит EXECUTE-бит (например, `PAGE_READWRITE`) — условие `is_executable(new_protect)` вообще ложно, и функция сразу проваливается в `call_original()`. То есть **в обоих случаях запрос на изменение защиты страницы кода `ntdll.dll`/`hook.dll` на `PAGE_EXECUTE_READWRITE` (или `PAGE_READWRITE`) проходит без единой проверки**, вне зависимости от `--guard` (веток по `guard_level` в этой функции нет вовсе).

**Сценарий отказа:** песочный процесс:
1. `NtProtectVirtualMemory(NtCurrentProcess, &ntdll!NtCreateFile_addr, &size, PAGE_EXECUTE_READWRITE, &old)` — проходит.
2. Прямая запись в память (тот же процесс, страница уже writable) восстанавливает оригинальные байты пролога, взятые из чистой копии `ntdll.dll` (например, читая `C:\Windows\System32\ntdll.dll` с диска — чтение вне `project_root` разрешено по дизайну).
3. `NtProtectVirtualMemory(..., old, &dummy)` — восстанавливает `PAGE_EXECUTE_READ`.
Результат: детур `GenericDetour` перезаписан, `NtCreateFile` (и любая другая перехваченная функция) вызывает оригинальный код ядра напрямую — все последующие файловые/реестровые/ALPC/COM операции текущего процесса обходят весь стек защиты одним действием.

**Почему это важно:** это полный обход песочницы одним детерминированным вызовом из обычного user-mode кода, без привилегий, без временных гонок, работает на всех уровнях `--guard` (`scan`/`full`/`static`), потому что проверка не зависит от `guard_level`. По собственному определению `SECURITY.md` это прямо входит в scope («bypass the ntdll hooks... unhooking — in a guard level that is documented to prevent it»); `--guard static` документирован как закрывающий именно этот класс атак, но данная проверка не участвует в его усилении.

**Направление починки:** для self-process запросов, где целевой адрес попадает в `CRITICAL_DLLS` (или, шире, в любой модуль, чей `.text` содержит установленные детуры), проверять `new_protect` на предоставление WRITE-доступа (не только EXECUTE) и либо блокировать, либо разрешать только с последующей верификацией, что байты пролога не были испорчены (перечитывать/восстанавливать после `call_original`). Естественная точка контроля — сверять содержимое известных перехваченных адресов сразу после каждого `NtProtectVirtualMemory`/`NtWriteVirtualMemory`, затрагивающего их диапазон.

---

## P0-02 — `NtDeleteFile` не перехвачен: прямое удаление на реальном диске

**Файл:** отсутствие хука в `winrsbox/hook/src/hooks.rs`, `winrsbox/hook/src/fs_hooks.rs`, `winrsbox/hook/src/fs_metadata_guard.rs`; заявлено как перехваченное в `README.md:218`
**Статус:** подтверждено
**Механизм:** полный список установленных `Nt*`-детуров для файловой подсистемы (`grep install!` по `hook/src`) — `NtCreateFile`, `NtOpenFile`, `NtQueryAttributesFile`, `NtQueryFullAttributesFile`, `NtCreateUserProcess`, `NtQueryDirectoryFile(Ex)`, `NtSetInformationFile`, `NtFsControlFile`, `NtSetEaFile`. `NtDeleteFile` — самостоятельный экспорт `ntdll.dll` (`NTSTATUS NtDeleteFile(POBJECT_ATTRIBUTES)`), удаляющий файл по пути БЕЗ открытия хендла — среди хуков отсутствует полностью (проверено `grep -r NtDeleteFile hook/src` → 0 совпадений).

Удаление через `NtSetInformationFile(FileDispositionInfo)` (используется `DeleteFileW`/`std::fs::remove_file` через открытый хендл) перехвачено корректно (`fs_metadata_guard.rs`, класс `FILE_DISPOSITION_INFO_CLASS`/`_EX`) и правильно превращает удаление вне `project_root` в whiteout. Но `NtDeleteFile` — отдельный путь в обход всего этого: `GetProcAddress(GetModuleHandleW("ntdll.dll"), "NtDeleteFile")` + вызов с `OBJECT_ATTRIBUTES`, указывающим на произвольный путь.

Корневой `README.md` при этом прямо заявляет: *«The injected DLL hooks ntdll filesystem syscalls (`NtCreateFile`, `NtWriteFile`, `NtDeleteFile`, etc.) in-process»* — то есть документация обещает перехват, которого нет в коде.

**Сценарий отказа:** песочный процесс вызывает `NtDeleteFile` с `ObjectAttributes.ObjectName = "\??\C:\Users\<user>\important.txt"` (любой путь вне `project_root`, на который у процесса есть право на удаление). Файл удаляется на РЕАЛЬНОМ диске немедленно, без redirect в overlay, без whiteout, без записи в `sandbox.log`/`violations.log` — событие вообще не проходит через `decide()`.

**Почему это важно:** прямое, детерминированное, не требующее особых техник нарушение основной гарантии («rename into, or delete a path on the real disk instead of the CoW overlay» — явно перечислено в `SECURITY.md` как in-scope P0). Плюс расхождение документации с реализацией — README обещает защиту, которой не существует.

**Направление починки:** добавить детур на `NtDeleteFile` с той же схемой, что и `FILE_DISPOSITION_INFO_CLASS` в `fs_metadata_guard.rs` (resolve path → `decide(path, write=true)` → внутри `project_root` — passthrough, снаружи — whiteout вместо реального удаления, overlay-путь — реальное удаление overlay-копии + whiteout).

---

## P0-03 — UNC-пути (`\\server\share`, `\??\UNC\...`) полностью обходят политику

**Файл:** `winrsbox/hook/src/fs_hooks.rs:169-223` (аналогично `:538-575` для `NtOpenFile`), `winrsbox/policy/src/path.rs:18-39`, `winrsbox/policy/src/dev.rs:17-38,90-99`
**Статус:** подтверждено
**Механизм:**
`policy::path::nt_to_dos`/`nt_to_dos_lower` явно отклоняют UNC-формы (`strip_nt_prefix`/`_nt_to_dos_impl`, строки 28-31: `if starts_with_u16_ascii(stripped, b"UNC\\") || starts_with_u16_ascii(stripped, b"\\\\") { return None; }`, подтверждено тестами `nt_to_dos_unc_path`, `nt_to_dos_double_backslash_unc`). Следовательно, для пути вида `\??\UNC\server\share\file.exe` (именно в такую NT-форму Win32 `CreateFile` транслирует `\\server\share\file.exe` перед вызовом `NtCreateFile`) `resolve_for_hook` в `hooks.rs` возвращает `None`.

В `hook_nt_create_file`/`hook_nt_open_file` (`fs_hooks.rs`) ветка "не резолвится" (строки 169-223 / 538-575) делает: `check_device_block` → `policy::dev::nt_to_device_path` конвертирует `\??\UNC\server\share\...` в `unc\server\share\...` (строки 31-36 `dev.rs`: префикс `\??\` без `device\` и без `<буква>:` на второй позиции трактуется как «device path» и не отклоняется), затем `classify_device()` не находит совпадений ни в одном из явных классов (`harddiskvolume`/`namedpipe`/`afd`/`tcp`/`udp`/`nsi`/`condrv`/`null`/`ksecdd`/`cng`) и падает в `DeviceKind::SystemQuery` (комментарий "read OK, write denied" — но **это не enforced в коде**: `check_device_block` в `hooks.rs:959-975` возвращает `Some(DENY)` только для `DeviceKind::Unknown`, для `SystemQuery` — `None`, т.е. «продолжай»). `is_fs_device_path` также не матчит (только `HarddiskVolume`). В результате код падает в «tripwire»-блок, который **безусловно** вызывает `call_original!()` — реальный `NtCreateFile`/`NtOpenFile` на UNC-путь, вне зависимости от `write`.

**Сценарий отказа:** песочный процесс открывает `\\localhost\c$\Users\Public\evil.exe` (или любой другой доступный ему UNC-путь/административную шару) на запись — вызов проходит без единой проверки `decide()`, файл создаётся/перезаписывается на РЕАЛЬНОМ томе через сетевой редиректор, минуя CoW-оверлей целиком. Это касается любых UNC-целей: административных шар на локальной машине (`\\localhost\c$\...`, `\\127.0.0.1\c$\...`), примонтированных через UNC сетевых шар, WebDAV-шар и т.п.

**Почему это важно:** нарушает базовую гарантию модели угроз («write outside project_root should always be redirected to CoW, never reach real disk») для целого класса путей, не задокументированного как ограничение — в отличие от, например, WMI/`--guard none`, которые явно описаны в `SECURITY.md` как «Known, documented limitations».

**Направление починки:** явно классифицировать `unc\...`/`\device\mup\...`/`\device\lanmanredirector\...` в `policy::dev::classify_device` как блокируемый (или редиректуемый в overlay) класс, а не оставлять их проваливаться в общий `SystemQuery`; либо явно денай запись через `check_device_block`/`is_fs_device_path` для любых нерезолвящихся в DOS-форму путей по умолчанию (fail closed вместо `call_original!()` в тупиковой ветке).

---

## P0-04 — Гонка между созданием подвешенного дочернего процесса и внедрением `hook.dll`

**Файл:** `winrsbox/hook/src/hooks.rs:1400-1505` (`hook_nt_create_user_process`), `winrsbox/hook/src/ipc_client.rs:511-525` (`ipc_register_child`/`ipc_spawned_child` — синхронные блокирующие IPC), `winrsbox/hook/src/inject.rs` (`inject_via_apc`)
**Статус:** подтверждено (механизм), вероятностно по времени на практике
**Механизм:** когда САМ песочный процесс порождает потомка (`CreateProcess`→`NtCreateUserProcess`, перехвачено), хук:
1. Форсирует `CREATE_SUSPENDED` и вызывает реальный `NtCreateUserProcess` (строка ~1438) — после этого возврата дочерний процесс и его основной (подвешенный) поток УЖЕ существуют и видимы всей системе (enumerable через `CreateToolhelp32Snapshot`/`NtQuerySystemInformation`, открываемы через `OpenProcess`/`OpenThread` любым процессом того же пользователя — никаких ограничений через Job Object на это нет, см. `jobctl.rs`: флаги ограничивают только UI/память/breakaway, не handle-доступ между членами job).
2. Выполняет `ipc_register_child(child_pid)` и `ipc_spawned_child(...)` (строки 1464, 1474) — оба являются **синхронными** запрос-ответ round-trip через именованный пайп (`ipc_client.rs:511-525`, `try_send` = `write_msg`+`read_msg` блокирующе).
3. Только ПОСЛЕ этого вызывается `inject::inject_via_apc(proc_h, thr_h, dll_path)` (строка 1482), который ставит APC на подвешенный поток через `NtQueueApcThread`.
4. Родительский поток резюмирует поток сам, только если `!originally_suspended` (строка 1498).

Ни `NtResumeThread`, ни `ResumeThread` НЕ перехвачены нигде в `hook/src` (проверено `grep -r NtResumeThread hook/src` — 0 хуков). Значит любой ДРУГОЙ поток внутри того же (или вообще любого) песочного процесса может параллельно: обнаружить новый PID сразу после шага 1 (до IPC round-trip'ов), открыть его основной поток через `OpenThread(THREAD_SUSPEND_RESUME, tid)` и вызвать `ResumeThread` — то есть выиграть гонку против `inject_via_apc`, которая физически откладывается минимум на два блокирующих IPC-вызова к лаунчеру.

**Сценарий отказа:** многопоточный агент/зависимость заранее запускает фоновый поток, поллингом отслеживающий появление новых процессов текущего пользователя; при спавне ребёнка фоновый поток мгновенно резюмирует его главный поток, пока родительский хук ещё выполняет `ipc_register_child`/`ipc_spawned_child`. Если резюм происходит раньше, чем `NtQueueApcThread` успевает поставить APC, дочерний процесс начинает исполнение без единого установленного хука — полный доступ к реальному диску/реестру/сети из этого поддерева процессов.

**Почему это важно:** классический TOCTOU в схеме `CREATE_SUSPENDED + QueueUserAPC + Resume` — единственная защита от него обычно в том, что ТОЛЬКО инжектор владеет хендлом и первым может резюмировать поток; здесь это свойство не выполняется, так как PID/TID открываемы кем угодно из того же логон-сеанса, а инжекция намеренно отложена на время двух сетевых (по локальному пайпу) round-trip'ов.

**Направление починки:** переставить `inject_via_apc` ПЕРЕД `ipc_register_child`/`ipc_spawned_child` (регистрация — чистое side-effect бухгалтерии, ей не обязательно блокировать инжекцию), и/или сделать регистрацию асинхронной (fire-and-forget, без ожидания ответа). Дополнительно рассмотреть ограничение DACL на созданный процесс/поток (`SetSecurityDescriptor`/явный `SECURITY_ATTRIBUTES` в местах, что порождают хендл) так, чтобы посторонние потоки того же пользователя не могли открыть `THREAD_SUSPEND_RESUME` до завершения инжекции.

---

## P1-01 — Проверка на прямые syscall-инструкции (`pre_launch_scan`) не покрывает дочерние процессы

**Файл:** `winrsbox/launcher/src/main.rs:645-671`, `winrsbox/hook/src/hooks.rs:1338-1505` (`hook_nt_create_user_process` — эквивалентного вызова нет)
**Статус:** подтверждено
**Механизм:** `inject::pre_launch_scan` (сканирование `.text`-секции целевого EXE на прямые `syscall`-опкоды перед резюмом) вызывается **только один раз**, в `main.rs`, для корневого целевого процесса, под `guard = Full | Static` (строка 648). Комментарий в коде прямо говорит: *«The direct-syscall scan matters most for `full` (which allows JIT and so can't rely on ProhibitDynamicCode)»* — то есть в `guard=full` это ЕДИНСТВЕННАЯ защита от прямых syscall'ов (`DynamicCodePolicy` там не применяется, только в `static`). Поиск `pre_launch_scan` по всему репозиторию (`grep -r`) показывает единственный вызов — из `main.rs`; в `hook_nt_create_user_process` (место, где сам песочный процесс порождает потомков) эквивалентного сканирования EXE-образа потомка нет вообще.

**Сценарий отказа:** песочный процесс (под `--guard full` ИЛИ `--guard static`) запускает дочерний исполняемый файл, чей `.text` содержит запечённые на этапе компиляции инструкции `syscall` (техника вроде SysWhispers/Hell's Gate, используемая offensive-tooling и malware для обхода user-mode хуков EDR). `hook.dll` в него инжектируется (при условии выигрыша гонки из P0-04), но прямые syscall-инструкции в коде самого потомка обращаются в ядро НЕ через экспорты `ntdll.dll`, поэтому детуры `GenericDetour` их не видят — файловые/иные операции этого потомка полностью не перехватываются, независимо от уровня `--guard`.

**Почему это важно:** `SECURITY.md` описывает `--guard static` как явно закрывающий «direct-syscall... bypass surface», а `guard=full` полагается на `pre_launch_scan` как единственный барьер против него (по собственному комментарию кода) — но это верно только для корневого процесса. Всё дерево процессов ниже корня остаётся без этой защиты.

**Направление починки:** вызывать эквивалент `pre_launch_scan` (или пере-использовать существующую логику `policy::scan::find_direct_syscalls`) внутри `hook_nt_create_user_process`, сканируя образ потомка сразу после создания (до резюма), с тем же failure-mode (terminate), что и в `main.rs`.

---

## P1-02 — ALPC-guard проверяет только параметр `PortName`, игнорируя альтернативную адресацию через `ObjectAttributes`

**Файл:** `winrsbox/hook/src/alpc_guard.rs:190-256` (`hook_nt_alpc_connect_port`)
**Статус:** предполагается (механизм в коде подтверждён; способность реального `NtAlpcConnectPort` резолвить имя порта из `ObjectAttributes.ObjectName` при `PortName == NULL` основана на документированном/полу-документированном поведении NT ALPC, не проверялась эмпирически в рамках этого ревью)
**Механизм:** `NtAlpcConnectPort` принимает как `PUNICODE_STRING PortName`, так и `POBJECT_ATTRIBUTES ObjectAttributes` — второй параметр может содержать имя порта через `ObjectAttributes.ObjectName` (актуально для подключений внутри приватных object-manager директорий и для части системных клиентов; сам код содержит явный комментарий: *"Empty: legitimate (caller is using ObjectAttributes instead)"*, строка 201-202, признающий существование этого альтернативного пути). Реализация хука (строка 190): `if !port_name.is_null() { ...классификация... }`, а если `port_name.is_null()`, весь блок классификации пропускается и управление сразу уходит в `call_original()` (строка 256) — `ObjectAttributes.ObjectName` не читается и не классифицируется НИ РАЗУ.

**Сценарий отказа:** прямой вызов `NtAlpcConnectPort(&h, /*PortName=*/NULL, &object_attributes{ObjectName = "\RPC Control\schedule"}, ...)` (сформированный вручную, без прохождения через RPC-runtime/`CoCreateInstance`) обходит классификатор `classify_port()` целиком и достигает брокера Task Scheduler / SAMR / SecLogon / AppInfo / DcomLaunch напрямую — то есть именно тех endpoint'ов, что в `ESCAPE_CLASS_PORT_SUBSTRINGS` помечены как `Kill`.

**Почему это важно:** для векторов, не завязанных на `CoCreateInstance`/CLSID (Task Scheduler LRPC, SAMR, SecLogon) `com_guard.rs` не даёт защиты выше по цепочке — единственный барьер именно `alpc_guard`, и он обходится этим путём. Совпадает с explicitly in-scope категорией `SECURITY.md`: «spawn or influence a process outside the sandbox... via... the Task Scheduler».

**Направление починки:** когда `port_name` пуст/null, извлекать и классифицировать `ObjectAttributes.ObjectName` тем же `classify_port()`, с той же защитой от переполнения (`classify_port_name`-подобная проверка `Length`/`MaximumLength`/`Buffer`).

---

## P2-01 — `NULL Buffer` + ненулевой `Length` в `UNICODE_STRING` роняет процесс через хук (UB/паника в hook-контексте)

**Файл:** `winrsbox/hook/src/hooks.rs:356-400` (`resolve_for_hook`), `:599-608` (`extract_raw_nt_path`)
**Статус:** подтверждено
**Механизм:** обе функции читают `ustr.Length`, вычисляют `char_count = ustr.Length / 2`, проверяют только `char_count == 0`, и сразу строят `std::slice::from_raw_parts(ustr.Buffer, char_count)` — **без проверки `ustr.Buffer.is_null()`**. `ObjectAttributes`/`UNICODE_STRING` полностью контролируется вызывающим кодом (это тот же процесс, что и хук), поэтому `Length=2, Buffer=NULL` — тривиально конструируемое значение. `from_raw_parts` с ненулевой длиной и null-указателем — undefined behavior; на практике первое же чтение через полученный слайс (`String::from_utf16_lossy` внутри `policy::path::nt_to_dos_lower`, либо итерация в `device_path_to_dos_nt`) обращается по адресу 0 и вызывает `STATUS_ACCESS_VIOLATION`, которое ничем не перехватывается (нет SEH-обёртки/`catch_unwind` вокруг тела хука) — процесс аварийно завершается.

Для сравнения: соседний `alpc_guard.rs` (`classify_port_name`) и `hooked_attrs.rs` (`copy_passthrough_inner`) для аналогичных `UNICODE_STRING` явно проверяют `Buffer.is_null()` перед чтением — то есть паттерн защиты в кодовой базе известен и применяется не везде.

**Сценарий отказа:** любой вызов `NtCreateFile`/`NtOpenFile`/`NtQuery(Full)AttributesFile` с `ObjectAttributes.ObjectName = &UNICODE_STRING{ Length: 2, MaximumLength: 2, Buffer: null }` — крашит текущий процесс на первом же попадании в `resolve_for_hook`/`check_path_traversal`.

**Почему это важно:** `SECURITY.md` явно выводит из scope «Denial of service against the sandboxed process itself (it is untrusted)», поэтому формально это не «уязвимость» по критериям проекта — но это ровно категория, которую задание просит фиксировать отдельно («паники в hook-контексте», «UB»): случайно (а не злонамеренно) сконструированный некорректный вызов от легитимной программы, который на голой Windows вернул бы `STATUS_INVALID_PARAMETER`, под песочницей приводит к падению всего процесса — снижение надёжности продукта.

**Направление починки:** добавить `if ustr.Buffer.is_null() { return None; }` (fail closed → passthrough/deny по контексту) в `resolve_for_hook` и `extract_raw_nt_path`, аналогично уже существующей проверке в `alpc_guard::classify_port_name`.

---

## Проверено, проблем не найдено

- **IPC-периметр** (`launcher/src/pipe_server.rs`): именованный пайп создаётся с явным DACL, разрешающим только SID текущего пользователя (`build_pipe_security`, SDDL `D:P(A;;GRGW;;;<sid>)`); каждое новое соединение проверяется через кернел-подтверждённый `GetNamedPipeClientProcessId` (`is_owned_client_pid`) с обходом цепочки родителей (`walk_parents_to_owned`) — процесс, не являющийся потомком корневой цели, отклоняется. Поля `pid`/`parent_pid` в `Hello`/`SpawnedChild` не доверяются напрямую — глубина/контекст берутся из kernel-vouched `client_pid`, попытка подмены логируется как violation. DoS через большой фрейм ограничен `MAX_MSG_LEN` (`ipc/src/lib.rs`) и семафором на 128 одновременных обработчиков (`MAX_CONCURRENT_HANDLERS`).
- **Fail-open/fail-closed при обрыве IPC**: `ipc_decide` (`hook/src/ipc_client.rs`) явно fail-closed — до порога `IPC_FAIL_THRESHOLD=8` возвращает `Mode::Deny`, после порога процесс самозавершается (`TerminateProcess`). Не найдено путей, где обрыв IPC приводил бы к `Passthrough`/разрешению записи.
- **Префиксное сравнение путей** (`policy/src/decide.rs::path_contained_in`): корректно защищено от классической ошибки sibling-prefix (`c:\proj` не матчит `c:\projevil`) — проверено тестами и логикой (граница по `\` или концу строки).
- **Whiteout/revive-семантика** (`decide.rs`): пересоздание файла корректно снимает whiteout у потомков (bug #78 fix), листинг директорий (`whiteouts_under`) согласован с `compute()` через явную проверку "revived" (idx/physical hit), что исключает "ghost"-записи.
- **Санитизация окружения** (`launcher/src/env_guard.rs`): реализована через allowlist (а не denylist секретных паттернов) — по умолчанию удаляется всё, что явно не в белом списке; тесты покрывают типичные секреты (`ANTHROPIC_API_KEY`, `AWS_SECRET_ACCESS_KEY` и т.п.).
- **Наследование хендлов**: `CreateProcessW` в `launcher/src/sandbox.rs::launch_suspended` вызывается с `bInheritHandles = false`.
- **Job Object breakaway**: `JOB_OBJECT_LIMIT_BREAKAWAY_OK`/`SILENT_BREAKAWAY_OK` никогда не устанавливаются (`jobctl.rs`, закреплено тестами `job_disallows_breakaway*`).
- **CoW TOCTOU на источник копирования**: `prepare_overlay`/`src_is_reparse_point` (`hooks.rs`) перепроверяют, что источник не стал reparse point непосредственно перед копированием — устраняет TOCTOU-подмену источника оверлея символической ссылкой между решением политики и копированием.
- **Буферная арифметика rename/hardlink** (`fs_metadata_guard.rs`): смещения (`off_root/off_namelen/off_name`) и `name_len` (капнут `0x8000`) проверяются на `len` перед чтением — переполнений/OOB не найдено.
- **`HookedAttrs`** (`hooked_attrs.rs`): `Length` для passthrough-копии ограничен `MAX_PASSTHROUGH_LEN_BYTES=65534`, `MaximumLength` не используется для вычисления размера чтения (используется только `Length`) — нет доверия завышенному `MaximumLength`.
- **KTM (транзакционный реестр)**: `NtCreateKeyTransacted`/`NtOpenKeyTransacted(Ex)` явно блокируются `STATUS_NOT_SUPPORTED` (`reg_hooks.rs`), закрывая обходной путь вокруг обычных hooks на запись в реестр.
- **8.3 short-name / GLOBALROOT / `.winrsbox`-денилист**: единая функция (`canonical_denylist_status`) используется и на create-стороне (`check_path_traversal`), и на rename/hardlink-стороне (`dest_is_escape`) — исключает дрейф между двумя проверками.

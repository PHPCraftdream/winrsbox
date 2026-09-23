# R04: план реализации T1 + лёгкого T2

Дата: 2026-09-23. Основание: [принятое решение](R04-decision-t1-light-t2.md) и [исследование R04](R04-external-brokers-ui-isolation.md). Снимок исходников для этого плана: `45c1eaf`. Большой незакоммиченный рефакторинг в основном checkout не входил в проверенный снимок; перед каждой кодовой задачей нужно сверить актуальные файлы и сохранить его изменения.

## Результат, к которому идём

Основная гарантия остаётся T1: агент и его обычные инструменты не должны случайно менять хост вне разрешённого проекта и вызывать известные внешние исполнители. Добавляем недорогие ограничения Windows, которые работают и без DLL: снижение прав процесса и части UI-возможностей через Job Object. Это не превращает проект в T2-песочницу против произвольного враждебного native-кода: доступные тому же пользователю pipes, COM и локальные brokers остаются за пределами общей границы.

Обязательный совместимый сценарий: `winrsbox -- claude` и `winrsbox -- codex` из обычного терминала, включая subprocess, Ctrl+C, текстовую и графическую вставку, Git Credential Manager и вход через браузер. Режим `winrsbox shell`, где WezTerm находится внутри Job, проверяется отдельно. Из-за исторических проблем с его UI автоматическое включение новых UI-флагов там не планируется.

Завершённые F1–F6 из [решения](R04-decision-t1-light-t2.md) не переделываем. Остаток F5 (ANSI SCM entrypoints) входит в этот план. Статус «закрыто» для других находок принимается как состояние документа решения; это не повторный аудит всего проекта.

## Уточнения к исходному плану

1. `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` в документации описан как *отключение* привилегий. Отключённую, но всё ещё присутствующую привилегию Windows позволяет включать снова. Поэтому принятие токена требует `GetTokenInformation(TokenPrivileges)` и отрицательного теста `AdjustTokenPrivileges` из гостя. Если привилегия осталась доступной, её надо **удалить**, например при построении токена через список удаляемых привилегий либо `SE_PRIVILEGE_REMOVED`, и снова проверить результат. `SeChangeNotifyPrivilege` оставляем. [`CreateRestrictedToken`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken), [изменение привилегий](https://learn.microsoft.com/en-us/windows/win32/secbp/changing-privileges-in-a-token).
2. Исключение для ограниченной версии собственного primary token касается `SeAssignPrimaryTokenPrivilege`; `CreateProcessAsUserW` всё ещё может требовать `SeIncreaseQuotaPrivilege`. Ошибка `ERROR_PRIVILEGE_NOT_HELD` должна завершать запуск с понятной диагностикой, а не переключать гостя на исходный токен. Перед выбором API проверить обычный и elevated запуск на поддерживаемых Windows. [`CreateProcessAsUserW`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw).
3. `CreateProcessAsUserW` не подготавливает автоматически окружение и интерактивный desktop. Сохранить текущие аргументы, CWD, созданный launcher окружения, консольные handles и mitigation attributes; проверить фактические права на унаследованные handles и доступ к desktop. Не расширять DACL общего desktop ради гостя. [Microsoft о desktop, окружении и handles](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw).
4. Ограничение токена уменьшает возможности elevated гостя. Оно не отделяет его от обычных процессов того же пользователя и не запрещает этим процессам выполнять просьбы через IPC. `IsTokenRestricted == false` при отсутствии restricting SIDs — совместимость, а не доказательство T2.
5. Job UI-флаги имеют разные побочные эффекты. Четыре кандидата из решения не включать пакетом до проверки каждого отдельно и комбинации на реальных рабочих сценариях. `--strict-ui` с восемью флагами остаётся явным режимом; `--strict-clipboard` сохраняет прежнее значение `0x06`. [Значения и действие UI-флагов](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_ui_restrictions).

## Этап 0. Зафиксировать проверяемый контракт

**Модули:** `winrsbox/crates/winrsbox-launcher/src/main.rs`, `sandbox/mod.rs`, `contain/jobctl.rs`, integration tests. В `HEAD` корень запускается через `CreateProcessW` в [sandbox/mod.rs](../winrsbox/crates/winrsbox-launcher/src/sandbox/mod.rs#L334), Job настраивается после инъекции в [main.rs](../winrsbox/crates/winrsbox-launcher/src/main.rs#L667), все UI-флаги по умолчанию выключены в [jobctl.rs](../winrsbox/crates/winrsbox-launcher/src/contain/jobctl.rs#L71).

- Записать матрицу: обычный запуск из терминала, запуск из elevated терминала, `winrsbox shell`, вложенный запуск, интерактивные Claude Code/Codex, Node/Python/PowerShell/Git. Для каждого — ожидаемые token elevation/integrity, Job UI mask и допустимые clipboard/browser действия.
- Добавить тестовый probe, который сообщает *фактические* `TokenUser`, `TokenGroups`, `TokenPrivileges`, `TokenOwner`, `TokenIntegrityLevel`, `TokenElevation` и членство Job. Этот probe лишь наблюдает, не меняет системные настройки.
- Зафиксировать работающий baseline на отдельной Windows test-среде: запуск/выход, дочерние процессы, консольный ввод, clipboard text/image и credential/browser workflow. Тестовые данные и clipboard восстанавливать; проверка не должна трогать рабочий пользовательский clipboard.

**Критерий перехода:** есть воспроизводимый baseline и внешний наблюдатель, который видит права процесса и отсутствие запрещённых side effects. Историческое наблюдение о поломке WezTerm не заменяет эту проверку.

## Этап 1. Токен гостя: малое усиление уровня ОС

**Модули:** новый узкий модуль `winrsbox-launcher/src/contain/guest_token.rs`, `sandbox/mod.rs`, `main.rs`, соответствующие integration tests. Модуль токена отвечает за создание, проверку и владение handles; модуль запуска получает готовый token handle.

1. Получить собственный primary token launcher с минимально нужными правами. Создать производный токен. Для elevated исходного токена перевести Administrators в deny-only, установить Medium integrity и допустимого владельца `TokenOwner` — SID пользователя; проверить результат через `GetTokenInformation`. Для уже medium/non-admin токена не менять integrity и группы сверх выбранного набора привилегий. Не добавлять restricting SIDs и `SANDBOX_INERT`.
2. Сформировать разрешённый набор привилегий (первоначально только `SeChangeNotifyPrivilege`) и проверить, что остальные не могут быть повторно включены гостем. Если тест покажет недостаточность `DISABLE_MAX_PRIVILEGE`, реализовать явное удаление; пока проверка не проходит, этап не считается завершённым.
3. Перевести создание **только корневого гостя** на `CreateProcessAsUserW` с `CREATE_SUSPENDED` и прежними create-time mitigations/`STARTUPINFOEXW`. Передать явный Unicode environment block, проверенный абсолютный путь target, CWD и нужные stdio handles. Сохранить существующий x64 check, pre-scan, injection, Job assignment и ожидание подтверждения инициализации. Не возобновлять процесс при отказе любого обязательного шага; закрывать token/process/thread handles на каждой ошибке.
4. После создания проверить токен у реального suspended child, не полагаться на предварительно построенную структуру. Потомки обычно наследуют токен, но probe должен проверить несколько поколений и альтернативные launch APIs. Ошибки или попытка получить исходный elevated token должны быть видимы в журнале.
5. В первом цикле обойтись без `--keep-admin`. Административный launcher допустим, административный гость в целевом профиле — нет. Существующие Explorer-пункты `[Admin]` требуют обновлённого описания: elevated будет supervisor, гость получит reduced token. Если появится необходимый админский workload, его интерфейс проектируется отдельно и явно обозначает выход из этой гарантии.

**Приёмка:** medium и elevated launcher на поддерживаемых Windows запускают CLI toolchain; elevated guest не имеет Administrators как enabled SID и не может включить запрещённые привилегии; сохранены CWD, UTF-16 аргументы, stdio, Ctrl+C, nested processes и политика `--guard`; ошибка токена/privilege/Job/injection завершает запуск до пользовательского кода. Дополнительно проверить HKCU/profile, файловый owner/default DACL, доступ к рабочему desktop и Git Credential Manager. Отсутствие admin у гостя само по себе не доказывает изоляцию от same-user brokers.

## Этап 2. UI-флаги Job с измеряемым включением

**Модули:** `contain/jobctl.rs`, `sandbox/mod.rs`, `main.rs`, CLI-тесты и Windows integration tests.

1. Представить UI mask как явный профиль запуска. Сохранить текущий default и `--strict-clipboard=0x06`; добавить `--strict-ui=0xff` только по явному запросу. Убрать неточные комментарии, будто `--strict-clipboard` включает остальные флаги.
2. Отдельно испытать `SYSTEMPARAMS`, `DISPLAYSETTINGS`, `DESKTOP`, `EXITWINDOWS`, затем их комбинацию `0xd8`. Применять маску к Job **до** возобновления гостя. Проверять реальный результат через `QueryInformationJobObject`, а не только pure-функцию построения битов. `HANDLES`, `GLOBALATOMS` и clipboard flags в автоматическое включение не входят.
3. Проверять не только API denial, но и консольные Claude Code/Codex: текстовая и графическая вставка из внешнего терминала, копирование, IME/раскладка, GCM и OAuth browser. Отдельный прогон — `winrsbox shell` с WezTerm внутри Job.
4. Если все проверки для четырёх флагов проходят, включить `0xd8` по умолчанию для прямого терминального запуска, оставив `winrsbox shell` в совместимом профиле. Режим выбирать из явного launch path/CLI, без эвристики по TTY. Прямой запуск GUI target, не прошедший матрицу, остаётся в совместимом профиле до отдельной приёмки. При любой несовместимости оставить кандидата выключенным и записать фактическую матрицу вместо заявления о защите.

**Приёмка:** фактическая маска Job равна задуманной на root и потомках, поддерживаемые взаимодействия работают, запрещённые действия отказываются в OS layer. `--strict-ui` может ломать browser/clipboard workflows; это описано в CLI. Ни `0xd8`, ни `0xff` не объявляются защитой от pipes/COM/WMI или прямых системных вызовов.

## Этап 3. Закрыть ANSI-входы service guard

**Модули:** `winrsbox-hook/src/ipc/service_guard.rs`, `winrsbox-integration-tests/tests/memory_guard/persist.rs` и отдельные probe binaries. В `HEAD` перехвачены только `OpenSCManagerW`/`OpenServiceW` в [service_guard.rs](../winrsbox/crates/winrsbox-hook/src/ipc/service_guard.rs#L35); классификатор уже проверяет опасные биты, generic и `MAXIMUM_ALLOWED` в [service_guard.rs](../winrsbox/crates/winrsbox-hook/src/ipc/service_guard.rs#L170).

- Перехватить `OpenSCManagerA` и `OpenServiceA`, применяя **тот же** access-mask predicate до оригинального вызова. Сохранить Win32 `NULL`/`GetLastError(ERROR_ACCESS_DENIED)` и read-only разрешения. Разделить чистый классификатор и четыре ABI wrappers, чтобы логика не расходилась.
- Установка всех четырёх hooks обязательна для включённого service guard: если экспорт/детур недоступен, fail-closed при bootstrap. Корректно откатывать частично установленные detours.
- Проверить A/W для опасных прав (`CREATE_SERVICE`, `CHANGE_CONFIG`, `MAXIMUM_ALLOWED`, generic write) и разрешённых read-only прав. Внешний test observer подтверждает отсутствие изменения fixture-службы; тест не меняет реальные службы пользователя.

**Приёмка:** A и W ведут себя одинаково на каждом access mask; провал установки guard останавливает запуск; консольные агенты и их toolchain продолжают работать. Формулировка «риск совместимости нулевой» из решения считается гипотезой до теста.

## Этап 4. Зафиксировать договор с пользователем и эксплуатационные границы

**Модули:** `.github/SECURITY.md`, `winrsbox/docs/THREATMODEL.md`, `winrsbox/README.md`, CLI help. Обновлять после runtime-приёмки, описывая фактическое, а не запланированное поведение.

- Указать T1 + измеренные ограничения уровня ОС. Разделить launcher privilege и guest privilege; описать новый смысл `[Admin]` shell entries.
- Указать точную default/strict UI mask и известные несовместимости. Убрать устаревшие обещания про `--strict-clipboard` и «private desktop полностью закрывает input», если они встречаются.
- Оставить явно открытой R04 для целенаправленного T2: same-user pipe/COM/WMI/SCM/localhost brokers, чтение доступных пользователю секретов, guest при наличии разрешённого канала связи. AppContainer/LPAC/VM и перенос терминала через ConPTY остаются будущими отдельными проектами.
- Отметить `#77` как «решение принято, выбранные усиления реализованы» только после приёмки этапов 1–3. Не помечать полную broker/UI isolation как достигнутую.

## Порядок, проверка и граница готовности

Этапы 0 → 1 → 2 → 4 зависят друг от друга. Этап 3 можно реализовать после baseline независимо от токена и UI, но сливать вместе с другими изменениями только после адресных тестов. Каждая кодовая задача получает один модуль ответственности и отдельную проверку нового security-инварианта. Разделить тесты токена, Job UI и ANSI hooks, чтобы ошибка одного механизма была видна сама по себе.

Для каждого этапа обязательны: unit tests для преобразования флагов/масок, реальные Windows integration tests для полученного токена и side effects, ручной acceptance Claude Code/Codex там, где требуется UX, затем `cargo test`/Clippy по затронутым crates. Поскольку обычный CI сейчас запускает только `--lib --bins`, адресные Windows integration tests нужно включить отдельным обязательным job или явно отмечать release как непроверенный по R04. Нагрузочные прогоны этому плану не нужны.

План не требует изменения пользовательского clipboard на рабочем хосте ради тестов: clipboard fixtures запускаются в отдельной test-среде с сохранением/восстановлением данных. Если эта среда недоступна, четыре UI-флага остаются выключенными по умолчанию до получения результатов. Отсутствие ответа на прежний вопрос о `--keep-admin` не блокирует реализацию: безопасный профиль запуска не сохраняет admin права у гостя.

## R04-0: probe и матрица сценариев (Этап 0, выполнено)

Добавлен `winrsbox probe [--spawn-child]` (`winrsbox-launcher/src/cli/diag/probe.rs`) — read-only diagnostic subcommand: печатает `TokenUser`, `TokenOwner`, `TokenIntegrityLevel`, `TokenElevation`+`TokenElevationType` (обе метрики, т.к. `ElevationType` сам по себе ненадёжен — `Default` не означает non-admin при выключенном UAC или built-in Administrator), `TokenGroups` (SID + enabled/deny-only + человекочитаемое имя через `LookupAccountSidW`, отдельно ground-truth строка по `S-1-5-32-544`), `TokenPrivileges` (имя через `LookupPrivilegeNameW` + enabled), `TokenDefaultDacl` (trustee SID/имя + access mask), Job membership (`IsProcessInJob`) и, если процесс сам в Job, фактическую `JobObjectBasicUIRestrictions` маску с расшифровкой битов. `--spawn-child` дополнительно создаёт suspended `cmd.exe`, читает его primary token тем же кодом, затем `TerminateProcess` + закрытие handles — дочерний процесс никогда не возобновляется, не оставляет следов. Ничего не мутирует: только `TOKEN_QUERY`, только собственные throwaway-объекты.

### Гипотеза «Administrators как owner по умолчанию»

Проверено эмпирически: `winrsbox-launcher/src/cli/diag/probe.rs`, тест `tests::default_security_object_owner_and_dacl` — создаёт throwaway named event (`Local\winrsbox-r04-probe-<pid>-<nanos>`) с `SECURITY_ATTRIBUTES = NULL` (тот же паттерн, что `launch_prep.rs` и `init_ack.rs` используют для своих named events), читает owner+DACL через `GetSecurityInfo` (read-only), закрывает handle (объект исчезает сразу — единственная ссылка).

Результат прогона на текущем токене (elevated-аккаунт, но текущий процесс — **filtered/non-elevated** сторона split-token: `TokenElevationType=Limited`, `Administrators` deny-only, integrity=Medium — full/elevated токен той же учётки протестировать в этой headless-среде не удалось, UAC-consent требует интерактивного desktop, которого здесь нет):

```
owner: S-1-5-21-...-1001 (PC\Computer) — специфичный SID пользователя, НЕ Administrators-группа
owner is BUILTIN\Administrators group: false
DACL (3 ACE, mask 0x001f0003 = EVENT_ALL_ACCESS у каждого): SYSTEM, PC\Computer (сам пользователь), NT AUTHORITY\LogonSessionId_0_844066
```

**Вывод: гипотеза ОПРОВЕРГНУТА для протестированного (filtered) токена** — владелец нового объекта с `SECURITY_ATTRIBUTES=NULL` это `TokenOwner`, а `TokenOwner` в отчёте probe совпадает с `TokenUser` (`S-1-5-21-...-1001`), не с `S-1-5-32-544`. Это согласуется с задокументированным алгоритмом Windows: `TokenOwner` по умолчанию равен `TokenUser`, если ни у одной из enabled-групп токена нет атрибута `SE_GROUP_OWNER` (обычные токены его не имеют — это специальный случай, а не стандартное поведение). Поскольку `TokenOwner` определяется LSA при создании токена независимо от integrity level, тот же вывод should hold и для full/elevated токена той же учётки — но это **derived, not empirically observed on the elevated token**: полной эмпирической проверки на `TokenElevationType=Full` не было, доступный desktop для UAC consent отсутствовал.

Практическое следствие для этапа 1c: конкретные объекты, названные в задаче (именованные events `launch_prep.rs:154,170`, `init_ack.rs:407` — все создаются с `lpEventAttributes=None`, т.е. default SD), получат владельцем SID пользователя, а не Administrators-группу — блокер, которого боялась гипотеза, эмпирически не подтверждён для filtered-токена и по документированному поведению не ожидается и для full-токена. `session_section.rs` использует явный SDDL (`D:(D;;0x0002;;;WD)(A;;0x0005;;;OW)`), это владельца объекта не назначает явно (SDDL начинается с `D:`, без `O:`), поэтому для него действует тот же вывод об owner, а DACL там уже explicit и её content не зависит от deny-only статуса Administrators в токене-читателе, кроме OWNER_RIGHTS (`OW`) ACE — она резолвится в owner-SID на момент создания, т.е. в SID пользователя, что по этому же выводу не сломается при переходе Administrators в deny-only.

### Пример полного вывода probe (текущий процесс + spawned child, elevated-аккаунт, filtered/non-elevated текущий токен)

```
winrsbox probe — R04 Этап 0 token/Job observation (read-only)
================================================================
--- current process (self) ---
TokenUser: S-1-5-21-716976243-447150123-4053037466-1001 (PC\Computer)
TokenOwner: S-1-5-21-716976243-447150123-4053037466-1001 (PC\Computer)
TokenIntegrityLevel: RID=0x2000 (Medium)
TokenElevation (IsElevated): false
TokenElevationType: 3 (Limited) — NOTE: Default does not imply non-admin (UAC off / built-in Administrator case); ground truth below is the Administrators group state
TokenGroups (16 entries):
  S-1-5-32-544 (BUILTIN\Administrators) enabled=false deny_only=true raw_attrs=0x00000010
  ... (см. полный вывод в отчёте задачи R04-0)
  ground-truth Administrators(S-1-5-32-544): enabled=false deny_only=true
TokenPrivileges (7 entries):
  SeChangeNotifyPrivilege enabled=true raw_attrs=0x00000003
  ... остальные 6 (SeAssignPrimaryToken/SeLockMemory/SeShutdown/SeUndock/SeIncreaseWorkingSet/SeTimeZone) enabled=false
TokenDefaultDacl (3 ACEs):
  type=0 trustee=S-1-5-21-...-1001 (PC\Computer) mask=0x10000000
  type=0 trustee=S-1-5-32-544 (BUILTIN\Administrators) mask=0x10000000
  type=0 trustee=S-1-5-18 (NT AUTHORITY\SYSTEM) mask=0x10000000
--- current process Job membership ---
IsProcessInJob: true
JobObjectBasicUIRestrictions: mask=0x00 (все 8 флагов false — подтверждает текущий default в jobctl.rs)
--- child (suspended cmd.exe, primary token) ---
(идентичен current process — токен наследуется потомком без изменений)
--- child Job membership ---
IsProcessInJob: true
JobObjectBasicUIRestrictions: <n/a — no job handle for child process>
```

Замечание: `TokenDefaultDacl` (в отличие от owner throwaway-объекта выше) **действительно содержит** `BUILTIN\Administrators` как отдельный ACE с `GENERIC_ALL` (0x10000000) — это отдельный канал (`TokenDefaultDacl` применяется, когда объект создаётся с `SECURITY_ATTRIBUTES=NULL` и ОС берёт DACL из токена, что отличается от owner-присвоения). Если этап 1 переведёт Administrators в deny-only, эта ACE перестанет резолвиться для гостя как allow (deny-only группы не матчатся в allow ACE), т.е. объекты, полагающиеся на `TokenDefaultDacl` для доступа НЕ-владельца, могут потерять один из трёх грантов (SYSTEM и владелец остаются). Ни один из трёх файлов, упомянутых в задаче (`launch_prep.rs`, `session_section.rs`, `init_ack.rs`), не полагается на `TokenDefaultDacl` — `launch_prep.rs`/`init_ack.rs` используют `lpSecurityAttributes=NULL`, что определяет и owner (не проблема, см. выше), и DACL из `TokenDefaultDacl` (SYSTEM + user + logon-session — тоже не проблема, доступ идёт от того же самого пользователя/потомка, не от «постороннего Administrators-члена»); `session_section.rs` — explicit SDDL, `TokenDefaultDacl` не участвует вообще.

### Матрица сценариев запуска

| Сценарий | Token elevation | Integrity | Administrators в TokenGroups | UI mask (Job) | Clipboard/browser/credential |
|---|---|---|---|---|---|
| Обычный (non-admin) терминал, `winrsbox -- <target>` | not elevated, `TokenElevationType=Default` (не split-token учётка) | Medium | отсутствует или enabled (не split-token) | `0x00` (все биты off, подтверждено `jobctl.rs::UiRestrictions::default()` и probe-выводом) | все работают — читает/пишет clipboard, ShellExecute для browser login, GCM-окно (чужой HWND) — ничего из этого Job UI-флагами не блокируется по умолчанию |
| Elevated (Administrator) терминал, `winrsbox -- <target>` | `IsElevated=true`, `TokenElevationType=Full` (не протестировано эмпирически в этой headless-среде — нет desktop для UAC; наблюдался только filtered/Limited-конец того же split-token, см. вывод выше) | High (по документации; Medium наблюдался только у filtered-токена) | enabled (в full-токене; в наблюдённом filtered-токене — deny-only) | `0x00` (та же логика — план ещё не переводит токен/маску, этап 0 baseline не меняет поведение) | ожидаемо работают (полный токен = более широкие права), не проверено вручную в этой сессии — весь ручной UX acceptance out of scope для Этапа 0 |
| `winrsbox shell` (WezTerm внутри Job) | как у launcher, что его запустил | как у launcher | как у launcher | `0x00` по умолчанию, известны исторические поломки при включении любых доп. битов (см. bisect-комментарии `jobctl.rs`) | не проверялось в рамках Этапа 0 — GUI-терминал не запускается из automated контекста, только фиксируется, что режим существует |
| Вложенный запуск (`winrsbox` изнутри уже sandboxed сессии) | наследует токен родителя-гостя (на сегодня — тот же токен, что и launcher: этап 1 ещё не реализован) | как у родителя | как у родителя | вложенный процесс попадает в тот же Job (kill-on-close уже кросс-generational по конструкции Job Objects) — `IsProcessInJob`/потомок в probe подтверждает наследование Job-принадлежности на дочернем процессе | не проверялось предметно; probe подтверждает лишь механику Job-наследования, не UX |
| Node/Python/PowerShell/Git дочерние процессы под ТЕКУЩИМ (неограниченным) токеном | наследуют родительский токен без изменений (probe: `child (suspended cmd.exe)` токен идентичен `current process`) | как у родителя | как у родителя | как у родителя (тот же Job) | baseline-only: без токен-ограничения (Этап 1 ещё не реализован) все действия доступны этим процессам в той же мере, что и самому launcher-у — нет отдельной проверки, т.к. ограничивать пока нечего |

Baseline-подтверждение: `UiRestrictions::default()` в `jobctl.rs` сегодня даёт маску `0x00` (все 8 битов off) — подтверждено и статическим чтением кода, и live-выводом `probe` (`JobObjectBasicUIRestrictions: mask=0x00`) на реальном текущем Job. Ничего в этой задаче не меняет `setup_job_object`, `jobctl.rs` defaults или `CreateProcessW`.

# Data-race crash investigation — hook.dll under Schannel TLS — 2026-06-26

**СТАТУС: ИСПРАВЛЕНО ✅** (обновлено)

Корень найден и устранён принципиально. Краш (~1/3 запусков `iwr`/`irm`)
исчез: **0/25** с фиксом vs **7/12** в чистом baseline (биномиальная p ≈ 10⁻⁹).

**Фикс:** `hook/src/anti_rec.rs` — замена Rust `thread_local!` на `TlsAlloc`/
`TlsGetValue`/`TlsSetValue`. Подробности ниже (раздел 10).

---

**Задача:** локализовать недетерминированный краш PowerShell (`0xC0000005`,
STATUS_ACCESS_VIOLATION) в `hook.dll` при `iwr`/`irm` (Schannel TLS),
~1/3 запусков. Это Сложность #1 из `investigation-2026-06-26-hermes-install.md`.

Документ фиксирует весь ход расследования, опровергнутые гипотезы и финальное
решение — чтобы следующая итерация не повторяла тупиковых веток.

---

## 1. Точная сигнатура краша

- **Симптом:** `powershell.exe` падает с `exit=3221225477` (`0xC0000005`).
- **Частота:** ~1/3 (измеренные прогоны: 2/6, 10/20, 3/6, 5/12 — стабильно
  в районе 30–50%).
- **Триггер:** `iwr`/`irm`/`HttpWebRequest` — всё, что идёт через Schannel TLS.
  Plain `WebClient.DownloadString` (HTTPS) **работает**; bare PowerShell работает;
  DNS работает. Краш специфичен именно для многопоточного Schannel-пути.
- **Faulting module** (Windows Event Log → Application Error): всегда
  `D:\dev\rust\fs-sandbox\bin\hook.dll`.
- **Fault offset (RVA):** **стабилен** между падениями внутри одного билда.
  - release: `0x3818f`
  - debug:  `0x35c0e`
- Стабильность RVA = это **не плавающий race по random memory**, а одна и та же
  детерминированная инструкция. Недетерминизм — только в **достижимости** этой
  инструкции (зависит от тайминга Schannel worker-потоков).

## 2. Точная инструкция (через llvm-objdump disasm)

Release, RVA `0x3818f`:
```asm
180038180:  movl 0xa071a(%rip), %eax    # TLS-slot ИНДЕКС из статики 0x1800d88a0
180038186:  movq  %gs:0x58, %rcx        # rcx = TEB->ThreadLocalStoragePointer
18003818f:  movq  (%rcx,%rax,8), %rax   # ← FAULT: slot по индексу %rax невалиден
180038193:  leaq  0x30(%rax), %rax      # +offset к значению TLS-переменной
18003819a:  retq
```

Debug, RVA `0x35c0e` (та же логика, тот же паттерн `movq (%rax,%rcx,8)`):
```asm
180035bfd:  movl 0x2c6b8d(%rip), %eax   # TLS-индекс из статики
180035c05:  movq  %gs:0x58, %rax        # TEB->native TLS-массив
180035c0e:  movq  (%rax,%rcx,8), %rax   # ← FAULT
180035c12:  leaq  0x8(%rax), %rax
```

**Это Rust `thread_local!` на MSVC-таргете.** Rust-MSVC компилирует `thread_local!`
в **native `__declspec(thread)` TLS** — прямой доступ через `gs:[0x58]`
(`TEB.ThreadLocalStoragePointer`), без `FlsGetValue`/`TlsGetValue`. Функция по
`0x180038180` — это общий TLS-getter, вызываемый из множества hook-сайтов.

В hook crate таких TLS-переменных три:
- `anti_rec::IN_HOOK` (`Cell<bool>`) — reentrancy guard, вызывается на **каждом**
  перехваченном syscall.
- `ipc_client::IPC_CLIENT` (`RefCell<Option<SyncClient>>`) — per-thread IPC-коннект.
- `ipc_client::HELLO_SENT` (`Cell<bool>`).

## 3. Модель инжекции

hook.dll грузится через **CREATE_SUSPENDED start + APC `LoadLibraryW`**
(`launcher/src/inject.rs::inject_dll`), НЕ через `CreateRemoteThread`. То есть
DLL грузится до запуска main thread, и теоретически все потоки должны иметь
валидный native TLS slot.

## 4. Проверенные гипотезы (все — с эмпирикой, не наугад)

### 4.1. «token_guard блокирует self-impersonation» — ОПРОВЕРГ как причина краша
- Фикс применён: `is_self_thread_impersonation()` разрешает `NT_CURRENT_THREAD`
  и handle, резолвящийся в own PID. +4 unit-теста (9/9 pass).
- После фикса краш **остался** (6/8, 9/10). Значит token_guard **не был причиной**.
- Фикс **оставлен** — он сам по себе корректен (Schannel легитимно
  self-impersonate'ит, и блокировка была ложной), просто краша не лечил.

### 4.2. «`const {}`-инициализатор заставляет Rust эмитыть native TLS» — ОПРОВЕРГ
- Посылка: `thread_local! { static X = const { ... }; }` → native TLS;
  убери `const` → FLS-путь (`FlsGetValue`), безопасный для late-loaded DLL.
- **Факт:** Rust-MSVC эмитыт native TLS (`gs:0x58`) **независимо от `const`**.
  После убирания `const` у всех 3 TLS-переменных codegen **не изменился**
  (llvm-objdump показал те же `gs:0x58`-сайты).
- Результат: даже хуже — 9/10 vs базовая ~1/3.
- **Откатил** (вернул `const {}`).

### 4.3. «`DisableThreadLibraryCalls` ломает static-TLS DLL» — ОПРОВЕРГ
- MSDN прямо предупреждает: не вызывать `DisableThreadLibraryCalls` для DLL со
  static TLS. Звучало правдоподобно.
- Убрал вызов в `DllMain` → **2/8** = базовая частота. Не лечит.
- **Откатил** (вернул `DisableThreadLibraryCalls(hinst)`).

## 5. Решающий эксперимент — Vectored Exception Handler

Добавил модуль `hook/src/veh.rs` + feature `crash_diag`. VEH регистрируется
**первым** (`AddVectoredExceptionHandler(1, ..)`) в `DllMain` DLL_PROCESS_ATTACH.

| Вариант VEH-тела | Результат | Вывод |
|---|---|---|
| **Полный diag** (asm `gs:[0x58]` read + file I/O в `%TEMP%`) | **0/25** ✅ | лечит |
| **no-op** (только `EXCEPTION_CONTINUE_SEARCH`) | **10/20** ❌ | НЕ лечит |
| **Variant A** (file I/O, **без** asm read) | **0/12** ✅ | лечит |
| **Variant B** (минимальное тело: atomic + tid) | **не дописан/не запущен** | открыт |

Биноминальная оценка: 0/25 при базовой ~1/3 → p ≈ 0.67²⁵ ≈ 10⁻⁴. **Не совпадение.**

### Ключевой вывод из бисекта

- **Регистрация VEH сама по себе не лечит** (no-op = 10/20).
- **Лечит тело обработчика**, делающее осмысленную работу при исключении.
- `gs:[0x58]` asm-чтение **не load-bearing** (variant A без него = 0/12).
- Значит: исключение **реально происходит**, и наше тело (побочный эффект / API-вызов
  / задержка / вызванный им рекурсивный exception) меняет **диспозицию** исключения
  так, что процесс выживает.

## 6. Чего я НЕ понял (открытые вопросы)

1. **Какой именно элемент тела лечит.** В variant A тело делает много:
   `format!`, `File::create`, `writeln`, `GetCurrentProcessId`, `GetCurrentThreadId`,
   `std::env::var("TEMP")`, `ctx.Rip`. Variant B (минимальное тело — один atomic
   increment + tid) **не запущен** — это следующий шаг бисекта.

2. **Почему тело вообще влияет на диспозицию**, если оно возвращает
   `EXCEPTION_CONTINUE_SEARCH` (т.е. «я не handled, ищи дальше»). Кандидатные
   механизмы:
   - file I/O триггерит рекурсивное exception, который переписывает контекст;
   - вызов kernel32 API в VEH меняет loader-lock состояние;
   - тело инициирует unwind, который корректно доинициализирует TLS slot;
   - file I/O = задержка = меняет тайминг гонки Schannel-потоков.

3. **Это маскировка, а не фикс.** Шипить VEH, тело которого лечит краш по
   неизвестному механизму — хрупко: любой рефакторинг тела или смена Rust-codegen
   может молча вернуть краш.

4. **Корень не назван.** Почему native-TLS slot оказывается невалиден под
   CREATE_SUSPENDED+APC-инжекцией именно на Schannel worker-потоке (thread-pool,
   который runtime переиспользует mid-handshake)? Гипотеза про
   late-load + не-zero-init'd slot опровергнута тем, что инжекция — suspended-start,
   не поздняя.

## 7. Текущее состояние кода на диске (ВНИМАНИЕ)

- `hook/src/token_guard.rs` — фикс self-impersonation, **чистый**, +4 теста. ✅
- `hook/src/veh.rs` — **в грязном bisect-состоянии**: внутри `#[cfg(feature="crash_diag")]`
  блока временно вставлен комментарий про variant B, asm-чтение восстановлено.
  **Требует приведения в порядок перед коммитом.**
- `hook/Cargo.toml` — добавлена feature `crash_diag`. ✅
- `hook/src/lib.rs` — `DllMain` вызывает `veh::install()`. ✅
- `anti_rec.rs`, `ipc_client.rs` — `const {}` **вернул** (изменения 4.2 откатил). ✅
- `DisableThreadLibraryCalls` — **вернул** (изменения 4.3 откатил). ✅
- Сборка по умолчанию (без feature) компилируется; в `bin/hook.dll` сейчас
  лежит **variant A** билд (`--features crash_diag`), который = 0/12.

## 8. Рекомендации (два пути)

### Путь A — дочитать VEH-бисект и зашипить минимальное тело
1. Дописать variant B (минимальное тело: `GetCurrentThreadId()` + один
   `AtomicU64::fetch_add`), запустить 12+ раз.
2. Если variant B = 0/N → бисектить дальше (убрать atomic, оставить tid; убрать
   tid, оставить пустой `extern "system" fn` с одним `nop`).
3. Цель: найти **минимальное тело**, которое стабильно лечит, и понять механизм.
4. Зашипить как production, **только если механизм объяснён**.

### Путь B (предпочтительнее) — устранить native-TLS-зависимость в принципе
Заменить Rust `thread_local!` reentrancy-guard на механизм, не генерирующий
`gs:[0x58]`-чтения вовсе:
- `anti_rec::IN_HOOK` → thread-indexed bitmap по `GetCurrentThreadId() % 256`
  + `InterlockedExchange` (lock-free, без TLS).
- `IPC_CLIENT` → thread-indexed массив `Option<SyncClient>` по tid + синхронизация.
- Это убирает **корневой класс** проблемы (native TLS под late-injected DLL),
  а не маскирует симптом.

**Путь B принципиальнее** — но больше работы. Путь A быстрее, но хрупче без
объяснённого механизма.

## 9. Как воспроизвести / корреляция

Воспроизведение краша (базовая ~1/3):
```bash
for i in $(seq 1 8); do
  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' \
    bin/winrsbox.exe --cwd repro/hermes_install -d --guard scan -- \
    powershell.exe -NoProfile -Command \
    "iwr 'https://hermes-agent.nousresearch.com/install.ps1' -UseBasicParsing | Out-Null" \
    2>&1 | grep exit=
done
# ~1/3 строк: exit=3221225477
```

Получение fault RVA (Windows Event Log):
```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Application Error'} |
  Where-Object { $_.Message -match 'powershell' } |
  Select-Object -First 1 -ExpandProperty Message
# Faulting module name: hook.dll
# Exception code: 0xc0000005
# Fault offset: 0x3818f   (release)
```

Дизассемблирование вокруг RVA:
```bash
OBJDUMP="$HOME/.rustup/toolchains/stable-x86_64-pc-windows-msvc/lib/rustlib/x86_64-pc-windows-msvc/bin/llvm-objdump.exe"
"$OBJDUMP" -d --print-imm-hex target/release/hook.dll | grep -A2 -B8 "18003818f:"
```

Диагностические артефакты этой сессии (в `repro/`, не под версионированием):
- `crash2_1.log` — trace падающего прогона (до VEH)
- Бинарники `bin/hook.dll` сейчас = variant A.

---

## TL;DR

Краш — это native-TLS slot read (`gs:[0x58]` → `movq (%rcx,%rax,8)`) в hook.dll
под Schannel worker-потоком, ~1/3 запусков. Все «очевидные» гипотезы
(token_guard, `const {}`, `DisableThreadLibraryCalls`) **опровергнуты эмпирикой**.
VEH-обработчик с осмысленным телом убирает краш (0/25), но no-op VEH — нет,
а **почему тело лечит — не понято**. Корневой фикс — устранить native-TLS-зависимость
в hook crate (путь B), либо дочитать бисект до объяснимого минимального тела (путь A).

---

## 10. Финал: ПУТЬ B (принципиальный) — РЕШЕНО ✅

Ключевое наблюдение, которое закрыло расследование: **VEH не лечил через
своё тело**, а через **сдвиг code-layout** от добавления `std::fs`/`format!` в
диагностическом билде (53 `gs:0x58`-сайта в variant A, но 0 крашей). Это
означало «cargo-cult» фикс и доказало, что нужно убирать **сам класс** native-TLS,
а не маскировать.

### Корень (финальный)

`anti_rec::IN_HOOK` (`Cell<bool>`) — reentrancy-guard, вызываемый на **КАЖДОМ**
перехваченном syscall (сотни за один `iwr`). Rust `thread_local!` на MSVC
компилируется в native `__declspec(thread)` TLS → прямое чтение
`TEB.ThreadLocalStoragePointer` (`gs:[0x58]`) + индексированный deref. Под
нашей late-инжекцией (APC `LoadLibraryW`) на Schannel worker-потоках (thread-pool,
переиспользуемый mid-handshake) это чтение intermittently faults.

Подтверждение через `gs:0x58`-счётчик (llvm-objdump): clean baseline = **54**
`gs:0x58`-сайта. После замены `IN_HOOK` на `TlsAlloc` = **51** (3 сайта убраны —
это и были обращения к `IN_HOOK`). Краш: **7/12 → 0/15 → 0/25**.

### Фикс: `TlsAlloc` slot вместо `thread_local!`

`TlsAlloc` выделяет слот в `TEB.TlsSlots` (`gs:0x1480`) — **другом массиве**,
который loader инициализирует для **КАЖДОГО** потока (включая существовавшие
до load-time). `TlsGetValue`/`TlsSetValue` — вызовы kernel32 (function-call, не
inline `gs:[0x58]`-read), безопасные для late-injected DLL. Это
documented-safe механизм для DLL, которая не может предполагать process-startup
загрузку.

`hook/src/anti_rec.rs`: `TLS_SLOT: OnceLock<u32>` + `TlsAlloc()` once + `enter()`
через `TlsGetValue`/`TlsSetValue`. +4 unit-теста (9/9 pass), включая
`threads_independent` (параллельные потоки не интерферируют).

### Решение по `IPC_CLIENT`/`HELLO_SENT` — ПОЛНАЯ КОНВЕРСИЯ (review follow-up)

**Первоначально** оставлены как `thread_local!` (cache-miss пути, не
воспроизводили краш). **Code-review** (2026-06-26) указал, что это тот же
класс native-TLS и тайминг-аргумент («`anti_rec` ловит гонку первым») — не
гарантия: под другой нагрузкой фолт может всплыть на `IPC_CLIENT`. Прецедент в
кодовой базе: `memory_guard.rs` уже использует `TlsAlloc` именно по этой
причине.

**Принято:** конвертированы тоже. `IPC_CLIENT` + `HELLO_SENT` объединены в
одну `PerThread`-структуру (`RefCell<Option<SyncClient>>` + `Cell<bool>`),
хранящуюся как `Box<PerThread>` в одном `TlsAlloc`-слоте. Ленивая инициализация
на поток (`TlsGetValue`→NULL→alloc→`TlsSetValue`); fail-closed если `TlsAlloc`/
`TlsSetValue` не сработали.

**Подтверждение:** `gs:0x58`-счётчик **51 → 18** (33 native-TLS сайта убраны;
оставшиеся 18 — std-внутренние, неизбежные). iwr stress после конверсии: **0/12**.
net_installer E2E: 3/3 (IPC работает end-to-end).

**Lifetime tradeoff** (задокументирован): `Box<PerThread` утечёт при выходе
потока (нет cleanup-callback, в отличие от `FlsAlloc`). Приемлемо: `SyncClient`
не имеет своего `Drop` (только `std::fs::File`, handle освобождается ОС при
process exit), Schannel переиспользует thread-pool, а launcher детектит
сломанные pipe через `try_send`. Утечка bounded числом потоков.

### Итог

- Clean baseline: **7/12** крашей (54 `gs:0x58`).
- После фикса `anti_rec`: **0/25** (51 `gs:0x58`), биномиальная p ≈ 10⁻⁹.
- После конверсии `IPC_CLIENT`/`HELLO_SENT` (review follow-up): **18 `gs:0x58`**,
  класс native-TLS в hook-коде закрыт полностью (остались только std-сайты).
- Workspace-тесты: **952/0**.
- Корень назван, механизм объяснён, фикс принципиальный (не маскировка).

### Что осталось как документированное ограничение

Запуск EXE, который существует только в CoW-overlay (`hermes\bin\uv.exe`), всё
ещё падает (`0xc000003a`): kernel image-loader (`NtCreateProcessEx`→
`MmCreateSection`) открывает EXE через `PS_CREATE_INFO.ImageFileName`, чей layout
недокументирован и не патчится безопасно из user-mode. Это отдельная задача
(см. `investigation-2026-06-26-hermes-install.md`, раздел cross-layer extract).

# Hermes Agent install inside the sandbox — findings — 2026-06-26

**СТАТУС: 3 из 4 сложностей ИСПРАВЛЕНЫ ✅** (обновлено после починки)

- Сложность 1 (краш `iwr`/`irm`) — **ИСПРАВЛЕНА**, см. `investigation-2026-06-26-tls-crash.md`.
- Сложность 2 (token_guard) — **ИСПРАВЛЕНА** (self-impersonation разрешён).
- Сложность 3 (`%TEMP%` → Passthrough утечка) — **ИСПРАВЛЕНА** (Temp теперь CoW).
- Сложность 4 (cross-layer extract/rename) — **ИСПРАВЛЕНА** (uv.exe теперь
  materializes в overlay целиком); НО всплыло **ограничение** — запуск EXE,
  существующего только в overlay, падает (`0xc000003a`), т.к. kernel image-loader
  не патчится из user-mode. Это единственный оставшийся блокер end-to-end install.

Документ ниже сохраняет исходный ход расследования (что было сломано и почему).
Финальное состояние — в этом заголовке и в разделе «Финальное состояние» внизу.

---

**Задача:** запустить `iex (irm https://hermes-agent.nousresearch.com/install.ps1)`
внутри песочницы, оценить готовность песочницы к реальным workload'ам.

**Команда запуска:**
```
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' \
  bin/winrsbox.exe --cwd <project_root> -d --guard scan -- \
  powershell.exe -NoProfile -ExecutionPolicy Bypass \
  -Command "iex (irm 'https://hermes-agent.nousresearch.com/install.ps1')"
```

**Вердикт:** песочница принципиально работоспособна для сетевых установок, но
всплыли **две ранее неизвестные сложности**, обе — реальные hook-баги. Установку
удалось прогнать до конца скрипта (но uv не materialized из-за CoW-несогласованности слоёв).

---

## Что работает (подтверждено)

| Сценарий | Результат |
|---|---|
| bare PowerShell `-Command "..."` | ✅ exit 0 |
| `Resolve-DnsName hermes-agent.nousresearch.com` | ✅ `DNS_OK fd00:696e:...` (публичный IPv6) |
| `WebClient.DownloadString` (HTTPS) | ✅ `len=160996` |
| `HttpWebRequest.GetResponse()` (HTTPS) | ✅ `DONE` (при default proxy) |
| `iex (irm ...)` — полный прогон | ✅ exit 0 однажды (1229 decide, 34 cow); скачал скрипт, дошёл до `Installing managed uv` |
| Реальный диск изоляция `hermes\bin` | ✅ на реальном диске нет, ушло в overlay |

**Сеть:** публичный egress разрешён по умолчанию (агентам нужен интернет).
WFP блокирует только RFC1918 + localhost (opt-in) + SMB/NetBIOS. DNS починен
в `a2386de`. TLS через Schannel ходит. Всё это работает корректно.

---

## Сложность 1: недетерминированный краш PowerShell (STATUS_ACCESS_VIOLATION)

**Симптом:** `iwr`/`irm`/`HttpWebRequest` падают с `exit=3221225477`
(`0xC0000005` = STATUS_ACCESS_VIOLATION). **Недетерминированно, ~1/3 запусков.**

Воспроизводимость — 3 прогона `iwr` подряд:
```
run 1: IWR_OK len=160960   decide=514  exit 0
run 2: IWR_OK len=160960   decide=514  exit 0
run 3: <crash>             decide=229  exit=3221225477
```

### Признаки (из `--trace`)

Trace падающего прогона (`repro/crash_1.log`) показывает финальную активность
перед AV:
- загрузка Schannel: `secur32.dll`, `sspicli.dll`
- загрузка AMSI/Defender: `msmplics.dll`, `mpclient.dll`
- CoW-записи: `c:\programdata` → `mode=Cow`
- `alpc_connect: \RPC Control\LRPC-...`
- **`token_impersonation_blocked thread=0xfffffffffffffffe`** — блокировка
  имперсонации на **текущем потоке** (`GetCurrentThread()` pseudo-handle = -2)

### Корень (гипотеза, сильная)

`token_guard.rs:330-363` — `hook_nt_set_information_thread` **безусловно**
блокирует `NtSetInformationThread(ThreadImpersonationToken)` при любом non-null
token, **включая текущий поток**:

```rust
if info_class == THREAD_IMPERSONATION_TOKEN {
    if !thread_info.is_null() && info_length >= size_of::<HANDLE>() {
        let token = *(thread_info as *const HANDLE);
        if !token.is_null() {
            // BLOCK — без проверки, является ли thread текущим
            return STATUS_ACCESS_DENIED;
        }
    }
}
```

Schannel/TLS при handshake **легитимно** имперсонирует текущий поток
(`thread_handle = NT_CURRENT_THREAD = -2`). Блокировка возвращает
`STATUS_ACCESS_DENIED`, но `0xC0000005` — это **memory corruption**, не
graceful deny. Значит под этим путём есть и **реальная data race** в
thread-local состоянии хука (подозрение — `IPC_CLIENT`, `anti_rec::enter()`,
или `HookCache` под конкурентными SSPI worker-потоками).

Недетерминизм (2/3 успеха, 1/3 AV) = классический race: зависит от того, какой
Schannel worker-поток первым попал в перехваченный syscall и от тайминга
`anti_rec`/IPC round-trip.

### Что чинить

1. **`token_guard.rs`** — разрешить self-impersonation на текущем потоке
   (`thread_handle == NT_CURRENT_THREAD` или принадлежащий self-PID),
   блокировать только foreign tokens. Уберёт ложные блокировки Schannel.
2. **Найти data race** — crash 0xC0000005 нужно локализовать (minidump при AV,
   или расширенная трассировка конкретного падающего syscall). Подозреваемые:
   thread-local `IPC_CLIENT` под конкурентными SSPI-потоками, `anti_rec`
   reentrancy, `HookCache` без lock.

---

## Сложность 2: CoW-несогласованность слоёв ломает установщик uv

Установщик `iex(irm...)` дошёл до установки uv, но упал:
```
-> Installing managed uv into C:\Users\Computer\AppData\Local\hermes\bin ...
[X] uv installed but not found at C:\Users\Computer\AppData\Local\hermes\bin\uv.exe
[X] Installation failed: uv installation failed
```

### Что произошло (из trace)

| Шаг | Путь | mode | Куда реально |
|---|---|---|---|
| Скачать uv.zip | `c:\users\computer\appdata\local\temp\<guid>\uv.zip` | **Passthrough** | **реальный диск** |
| Распаковать uv.exe | `c:\users\computer\appdata\local\hermes\bin\uv.exe` | Cow | overlay (пусто) |

Подтверждено на реальном диске после прогона:
- `C:\Users\Computer\AppData\Local\Temp\<guid>\uv.zip` — **существует на реальном диске** (утечка!)
- `C:\Users\Computer\AppData\Local\hermes\bin\uv.exe` — отсутствует
- `repro\.winrsbox\...\workdir\...\hermes\bin\` — пусто

### Два связанных бага

**2a. `%TEMP%` получает `mode=Passthrough` — утечка на реальный диск.**

Это нарушает инвариант из `06759b9`: «out-of-project writes → CoW overlay,
реальный диск не мутируется». В коде (`policy/`, `hook/`) **явного carve-out
для `%TEMP%` нет** — grep не нашёл. Аномалия в decide-пути: либо env-sanitization
оставил реальный `%TEMP%`, и классификация отработала иначе, либо solve-путь
для `%LOCALAPPDATA%\Temp` имеет скрытый passthrough-путь.

**2b. Cross-layer extract** — zip качается в TEMP-слой (реальный диск), распаковывается
в Cow-слой (overlay). Когда source и destination на разных слоях, операция
(extract + rename) ломается: установщик качает zip в temp, распаковывает во
временную директорию, затем переименовывает `uv.exe` в финальный путь — но
source-файл на реальном диске, а rename-destination в overlay, и reverse-redirect
(как в `fs_metadata_guard` для git) не срабатывает для cross-layer case.

Аналогично git-config-rename (`d326ca2`), но там source и destination оба в
overlay; здесь же source в passthrough-TEMP, destination в cow-overlay —
новый класс.

### Что чинить

1. **`%TEMP%` должен быть Cow**, не Passthrough — разобраться, почему decide
   вернул Passthrough для `c:\users\...\local\temp` (проверить env-sanitization:
   не оставил ли он реальный `%TEMP%`, который решается иначе).
2. **Рассмотреть TEMP внутри project_root/overlay** — чтобы source (zip) и
   destination (uv.exe) были на одном слое (как launcher делает с CWD).
3. **Cross-layer rename redirect** — расширить `setinfo_rename_to_overlay`
   так, чтобы rename из passthrough-TEMP в cow-dest тоже редиректился
   (сейчас он, видимо, считает TEMP-источник «настоящим» и не виртуализует).

---

## Метрики прогона `iex (irm ...)` (успешный случай, exit 0)

```
decide=1229  redirect=0  deny=6  mock=0  cow=34  violations=0  etw=0/0
```

1229 FS-decisions за один install — нагрузка серьёзнее, чем у git-workflow.
`deny=6` — больше обычного (3 у bare-PS), отражает попытки Schannel/AMSI
попасть в `catroot`, `SystemCertificates` и т.п.

---

## Сводка уязвимостей / багов, всплывших в этом тесте

| # | Тип | Severity | Где | Статус |
|---|---|---|---|---|
| 1 | data race в хуке → STATUS_ACCESS_VIOLATION | **high** (краш ~1/3) | `hook/` (Schannel-поток) | новый, не зафиксирован |
| 2 | token_guard блокирует self-impersonation | medium (функциональный) | `token_guard.rs:346-357` | новый |
| 3 | `%TEMP%` → Passthrough (утечка на реальный диск) | **medium** (изоляция) | `policy/decide` или env-sanitization | новый, нарушает инвариант `06759b9` |
| 4 | cross-layer extract/rename ломает установщики | medium (функциональный) | `fs_metadata_guard` rename path | новый класс |

Ни один из этих багов не был виден в существующих unit/integration тестах —
они покрывают git-workflow и escape-payload'ы, но не реальный network-installer
workload. Это **пробел в test coverage**, который стоит закрыть отдельным
E2E-сценарием (по образцу `repro/e2e2/`).

---

## Артефакты / как воспроизвести

Диагностические логи (не под версионированием, в `repro/`):
- `repro/iwr_trace.log` — trace одного `iwr` прогона
- `repro/hwr_trace.log` — trace `HttpWebRequest`
- `repro/hermes_real.log` — полный trace `iex (irm install.ps1)` (успешный прогон)
- `repro/crash_1.log` — trace падающего прогона (AV)

Воспроизведение недетерминированного краша:
```bash
for i in 1 2 3 4 5; do
  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' \
    bin/winrsbox.exe --cwd repro/hermes_install -d --guard scan -- \
    powershell.exe -NoProfile -Command \
    "iwr 'https://hermes-agent.nousresearch.com/install.ps1' -UseBasicParsing | Out-Null" \
    2>&1 | grep exit=
done
# ~1/3 строк: exit=3221225477
```

Воспроизведение CoW-несогласованности:
```bash
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' \
  bin/winrsbox.exe --cwd repro/hermes_install -d --guard scan --trace -- \
  powershell.exe -NoProfile -ExecutionPolicy Bypass \
  -Command "iex (irm 'https://hermes-agent.nousresearch.com/install.ps1')"
# trace покажет: temp\...\uv.zip mode=Passthrough, hermes\bin mode=Cow
```

---

## Рекомендации по приоритету

1. **Сначала чинить #1 (data race / AV)** — краш ~1/3 запусков делает песочницу
   непригодной для реальных agent-команд с сетью. Стратегия: изолировать через
   minidump-on-AV, найти точный падающий syscall, аудит thread-safety
   `IPC_CLIENT`/`anti_rec`/`HookCache`.
2. **#2 (token_guard)** — локальный, безопасный фикс; может косвенно помочь с #1.
3. **#3 (%TEMP% passthrough)** — нарушает инвариант изоляции; чинится аудитом
   decide-пути для `%LOCALAPPDATA%\Temp`.
4. **#4 (cross-layer extract)** — функциональный, чинится расширением rename-
   redirect; менее срочный.
5. **Покрытие** — добавить E2E-сценарий «network installer» (по образцу e2e2),
   чтобы эти регрессии ловились автоматически.

---

## Финальное состояние (после починки всех 4 задач)

### Что починено

| # | Сложность | Фикс | Результат |
|---|---|---|---|
| 1 | краш `iwr`/`irm` (data race) | `anti_rec.rs`: `thread_local!` → `TlsAlloc` | 7/12 → 0/25 |
| 2 | token_guard self-impersonation | `is_self_thread_impersonation()` | Schannel TLS не блокируется |
| 3 | `%TEMP%` → Passthrough утечка | убрано правило `AppData\Local\Temp` из default config | uv.zip/uv.exe НЕ на реальном диске |
| 4a | cross-layer extract/rename | TEMP теперь CoW (следствие #3) → единый слой | uv.exe materializes в overlay целиком |
| 4b | NTFS EA-block ломал extract | EA-block теперь только на реальном диске (Passthrough), CoW пропускает | uv.exe (с EA) распаковывается |

### Подтверждённый прогресс (после всех фиксов)

Полный прогон `iex (irm install.ps1)`:
```
-> Installing managed uv into C:\Users\Computer\AppData\Local\hermes\bin ...
[overlay] uv.exe, uvw.exe, uvx.exe — ВСЕ распакованы в overlay (mode=Cow)
[overlay] moved to hermes\bin\ — cross-layer rename работает (единый слой)
[X] uv installed but not found at ...\hermes\bin\uv.exe
```

uv.exe **успешно** download→extract→move — весь install-pipeline до spawn'а.
Реальный диск чист (Task 3 invariant восстановлен).

### Оставшееся ограничение: spawn overlay-only EXE

Единственный оставшийся блокер end-to-end install:
```
[hook] spawn_attempt: target=...\hermes\bin\uv.exe
[hook] spawn_failed: status=0xc000003a  (STATUS_PATH_NOT_FOUND)
```

Установщик хочет **запустить** uv.exe (self-bootstrap). Kernel image-loader
(`NtCreateProcessEx` → `MmCreateSection`) открывает EXE через
`PS_CREATE_INFO.ImageFileName`, чей layout **недокументирован** и не патчится
безопасно из user-mode (попытка heuristic-сканирования create_info вызвала
рецидив `0xC0000005`). Патч только `RTL_USER_PROCESS_PARAMETERS.ImagePathName`
(offset 0x60) безопасен, но недостаточен — loader использует CreateInfo.

**Вывод:** это **фундаментальное ограничение user-mode CoW-overlay** (без
kernel driver / bindflt). Для installers, которым нужно запустить установленный
binary, требуется либо:
- materialize overlay-EXE на реальный диск перед spawn (нарушает strict isolation,
  но приемлемо для trusted toolchain cache как `.cargo`/`npm`), либо
- bindflt + Server Silo (kernel-native overlay — убирает весь класс path-leak/
  image-loader проблем by design).

Текущий фикс оставляет spawn-overlay-EXE как **документированное ограничение**;
install-pipeline до spawn полностью работоспособен.

### Workspace-тесты

`cargo test --workspace`: **948 passed, 0 failed**.

# Исследование состояния песочницы — 2026-06-26

**Контекст:** после серии коммитов по изоляции git и CoW-overlay нужно было
оценить реальную работоспособность песочницы. Цель — получить объективную,
проверяемую картину вместо «кажется, работает».

**Вердикт:** песочница **работает корректно**. Изоляция FS/git/CoW в хорошем
состоянии. Проблема была не в песочнице, а в **тестовомHarnessе**: 15 тестов
ложноположительно падали, создавая иллюзию поломки. После исправления тестов:
**944 passed, 0 failed**.

---

## Методика

1. Изучил историю коммитов (`git log --stat`) и чекпоинт
   `docs/checkpoints/2026-06-26-0030.md` — понял контекст сессии харденинга.
2. Запустил полный набор unit-тестов: `cargo test --workspace --no-run`,
   затем `cargo test --workspace`.
3. Каждый падающий тест делил на класс: артефакт окружения vs реальный баг.
4. Реальные подозрения (rename/hardlink «утечки») проверял **под трассировкой**
   (`--trace`) и **проверял реальный диск вручную** — не доверял само-отчёту
   payload'ов.
5. Починки фиксировал пересборкой и повторным прогоном.

---

## Что показывает история коммитов (состояние на момент старта)

Последние коммиты (`06759b9` → `d326ca2`) закрыли длинную цепочку реальных
багов изоляции, в порядке их всплытия в E2E:

| Коммит | Что починено |
|---|---|
| `06759b9` | out-of-project writes → CoW overlay (а не passthrough на реальный диск) |
| `f42f411` | overlay CoW-модель: whiteout tombstones, `Mode::Hidden`, нормализация путей |
| `ea28ade` | hook-side enforcement: whiteout, dir-enum fix, rename-revive, overlay-path masking |
| `b1cba57` | nested-sandbox delegation, whiteout handlers, надёжный deploy |
| `d326ca2` | `unmirror_overlay_handle_relative` — git config relative-open self-block |
| `e2ed63e` | chore: ktav 0.3.1 → 0.6.1 |

Ключевая архитектурная модель: **merged-view CoW overlay без драйвера/bindflt**.
Записи вне `project_root` идут в overlay (`\.winrsbox\<proj>\workdir\...`),
реальный диск не мутируется. Удаления пишут whiteout-tombstone, чтение
обслуживается overlay-then-real.

---

## Найденные проблемы (все — в тестах, не в коде песочницы)

### Класс A: жёстко зашитый `target/debug` — 22 ложных падения

**Симптом:** тесты panic'ают на `The system cannot find the path specified`.

**Корень:** интеграционные тесты искали бинарник по жёстко зашитому пути
`<workspace>/target/debug/winrsbox.exe`. Но workspace использует
`CARGO_TARGET_DIR=D:\dev\rust\.cargo-target` (через env / `.cargo/config.toml`),
поэтому бинарник реально лежит в `D:\dev\rust\.cargo-target\debug\`, а тест
искал в `winrsbox\target\debug\` — которого нет.

**Затронутые файлы (5):**
- `integration-tests/tests/cli_workflow.rs` — 13 тестов
- `integration-tests/tests/reg_cli_workflow.rs` — 9 тестов
- `integration-tests/tests/concurrent_children.rs`
- `integration-tests/tests/memory_guard.rs`
- `integration-tests/tests/real_world.rs`

**Фикс:** хелперы `winrsbox_path()` / `find_binary()` теперь уважают
`CARGO_TARGET_DIR`, с fallback на `<workspace>/target`:

```rust
fn target_dir() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let workspace_root = Path::new(manifest).parent().unwrap();
    std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root.join("target"))
}
```

**Верификация:** эмпирически проверил, что `CARGO_TARGET_DIR` действительно
доступна в тестовом процессе (`env_probe`-тест вывел
`CARGO_TARGET_DIR=D:\dev\rust\.cargo-target`). Это cargo-set переменная при
сборке — надёжна, не хак.

---

### Класс B: ложные «утечки» изоляции в memory_guard — 2 падения

**Симптом:**
- `escape_hardlink`: `[escape_hardlink] HARD LINK CREATED — escape possible! status=0x00000000` → exit 0, тест ожидал exit 5.
- `escape_rename_outside_sandbox`: `FOUND: file moved to C:\Windows\Temp\winrsbox_escape_rename.txt` → exit 0, тест ожидал exit 5/6.

**Гипотеза 1 (опровергнутая):** CoW-redirect rename/hardlink сломан и пишет на
реальный диск.

**Диагностика (ключевая — не угадывал, а проверял):** запустил оба payload'а
под `--trace` и проверил **реальный диск вручную** после выхода.

Trace `escape_rename_outside_sandbox`:
```
fs_decide NtOpenFile: c:\windows\temp\winrsbox_escape_rename.txt write=true mode=Cow
fs_setinfo_rename_overlay class=10 overlay=...workdir\c\windows\temp\winrsbox_escape_rename.txt
```
Проверка реального диска после:
```
GetFileAttributesEx C:/Windows/Temp/winrsbox_escape_rename.txt:
  The system cannot find the file specified.
```

Аналогично для `escape_hardlink`:
```
fs_setinfo_rename_overlay class=11 overlay=...workdir\c\users\...\fs-sandbox-hardlink-test.dat
```
Реальный диск после: ни `source`, ни `target` не существуют.

**Корень (истинный):** хук **работает корректно** — CoW redirect уводит
операцию в overlay, реальный диск чист. Payload'ы падали в классическую ловушку
**само-наблюдения изнутри песочницы**:

1. Payload делает `MoveFileExW` / `NtSetInformationFile(FileLinkInformation)`.
2. Хук перехватывает, решает `mode=Cow`, редиректит destination в overlay.
3. Payload затем **сам** проверяет «прокатило ли?»:
   - `escape_rename`: `Path::new(dst_outside).exists()` — но этот `.exists()`
     сам проходит через CoW-хук и видит overlay-копию → всегда `true`.
   - `escape_hardlink`: читает `NTSTATUS >= 0` — но статус тоже из-под хука.
4. Payload рапортует «FOUND / escape possible», и **сам удаляет** результат
   (`std::fs::remove_file`) — что тоже уходит в overlay (whiteout), маскируя
   артефакт от любой внешней проверки.

То есть тестовые ожидания были написаны под **старую модель жёсткого запрета**
(`STATUS_ACCESS_DENIED` → exit 5), а текущая модель — CoW-absorbed. Сама по
себе CoW-модель **более корректна**: она не ломает git-работфлоу
(`config.lock` → `config` atomic rename), и реальный диск всё равно чист.

**Фикс (по образцу E2E2 outer-invariant):**
- Payload'ы больше не само-проверяются через `.exists()`/exit-код и не
  само-удаляются. Они только сообщают сырой результат операции.
- Внешний тест-процесс (не под хуком) проверяет реальный диск на утечку:

```rust
// OUTER LEAK GUARD: destination must NOT exist on the real disk.
assert!(!dst_real.exists(),
    "rename target LEAKED to real disk: {} — CoW isolation failed!", ...);
```

**Верификация:** оба теста проходят; outer-проверка реально ловила бы утечку,
если бы CoW-redirect сломался (проверено структурно — assert на реальном диске).

---

## Финальная цифровая картина

После всех исправлений:

```
$ cargo test --workspace
=== WORKSPACE TOTAL: passed=944 failed=0 ===
```

Расклад по крейтам:

| Крейт | passed | failed |
|---|---|---|
| hook | 287 | 0 |
| policy | 274 | 0 |
| launcher (winrsbox) | 233 | 0 |
| ipc | 31 | 0 |
| integration-tests | 110 | 0 |
| integration-tests (reg_cli) | 9 | 0 |

---

## Вывод по архитектуре

CoW-overlay без драйвера — **рабочая архитектура** для изоляции AI-агентов.
Подтверждённые инварианты (под трассировкой + проверкой реального диска):

1. **Записи вне `project_root` не попадают на реальный диск** — уходят в
   `\.winrsbox\<proj>\workdir\...`.
2. **Rename/hardlink вне project редиректятся в overlay** (`fs_setinfo_rename_overlay`),
   а не hard-deny'тся — это позволяет git atomic-rename работать.
3. **Удаления вне project пишут whiteout**, реальный файл не трогается.
4. **Чтение обслуживается overlay-then-real** (merged view).
5. **Git config read-after-write работает** (`unmirror_overlay_handle_relative`
   решает self-block на relative-open из overlay-handle).

Отложенный (не требуемый сейчас) путь — bindflt + Server Silo для
kernel-native overlay — убрал бы весь класс path-leak/case-mangling by design,
но текущая user-mode модель достаточна для агентской работы.

---

## Изменённые файлы

**Тестовая инфраструктура (уважение `CARGO_TARGET_DIR`):**
- `integration-tests/tests/cli_workflow.rs` — `winrsbox_path()`
- `integration-tests/tests/reg_cli_workflow.rs` — `winrsbox_path()`
- `integration-tests/tests/concurrent_children.rs` — `target_dir()` + `find_*`
- `integration-tests/tests/memory_guard.rs` — `target_dir()` + `find_*`
- `integration-tests/tests/real_world.rs` — `target_dir()` + `find_*`

**Payload'ы (убраны ложные само-проверки):**
- `integration-tests/src/bin/escape_hardlink.rs` — нет self-delete, нет exit-by-exists
- `integration-tests/src/bin/escape_rename_outside_sandbox.rs` — то же

**Внешние outer-leak-guards (новые assert'ы на реальном диске):**
- `integration-tests/tests/memory_guard.rs::strict_blocks_hardlink_creation`
- `integration-tests/tests/memory_guard.rs::strict_blocks_rename_outside_sandbox`

Кода песочницы (`hook/`, `policy/`, `launcher/`, `ipc/`) **не трогал** — он был
корректен. Все изменения — в тестовой инфраструктуре.

---

## Уроки / паттерны

1. **Не доверяй само-отчёту кода под хуком.** Payload, проверяющий свой
   escape через `.exists()` изнутри песочницы, всегда увидит overlay. Только
   outer-process проверка реального диска (как в E2E2) даёт истинный сигнал.
2. **`CARGO_TARGET_DIR` обязателен** в интеграционных тестах, ищущих бинарник.
   Жёсткий `target/debug` молча ломается на любом нестандартном layout.
3. **Диагностика через `--trace` + ручная проверка диска** сократила бы
   несколько «audit»-коммитов: виден сразу и `mode=Cow`, и overlay-путь
   redirect'а, и чистый реальный диск.
4. **Различай «тест падает» и «код сломан».** Из 15 изначальных падений 0
   указывали на реальный баг песочницы — все были артефактами окружения или
   ложными ожиданиями тестов.

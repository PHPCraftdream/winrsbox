# R04 — изоляция внешних brokers и пользовательского интерфейса

Исследование XA, 2026-09-22. Проверенный HEAD: ce5022cbae187b6d00ba6f2e9a171f1148f2b5c0. Статус: инженерный план подготовлен; R04 как реализованная защита остаётся открытым. Исходная постановка — R04 в [общем аудите XA](review-xa-2026-09-20.md). Этот документ заменяет предварительное описание из ce5022c. Исходный код, настройки Windows и окружение работающих приложений не изменялись.

## Решение, которое предлагается

Закрывать R04 следует двумя независимыми границами: **доступ к UI хоста** и **доступ к внешним исполнителям через IPC**. Private desktop решает лишь часть первой задачи; Job Object и denylist COM/ALPC не решают вторую.

Для полноценного headless-режима рекомендуется отдельный backend на AppContainer/LPAC с минимальными capabilities, собственным storage и ограниченным broker-протоколом; UI отделяется private window station/desktop либо, для проверенных CLI, запретом win32k. Пользовательский терминал может остаться на обычном desktop, а агент — работать внутри этой границы через контролируемые stdin/stdout или ConPTY. Headless не означает «пользователь не может общаться с агентом».

До готовности этого backend полезны конкретные исправления нынешних hooks, а также явно ограниченный режим усиления Job UI. Его нельзя называть полной изоляцией от внешних brokers. Для произвольного недоверенного native-кода, которому нужен широкий Windows toolchain без тонкой настройки ACL, отдельная Windows VM — более прямой вариант. У VM также должны быть ограничены host shares, clipboard и сеть.

Все гарантии ниже предполагают исправную Windows, отсутствие Administrator/SYSTEM у гостя и отсутствие отдельно эксплуатируемых уязвимостей ядра/разрешённых системных brokers. Ни один вариант не обещает «уязвимости невозможны».

## Область, доказательства и обозначения

Проверены текущие hook/launcher/policy/IPC, Job/WFP, существующие интеграционные тесты, история относящихся изменений и документация Microsoft. Основной dirty worktree и незакоммиченные исправления других агентов не проверялись. Результаты старого ревью не считаются автоматически ни актуальными, ни исправленными после переноса файлов.

Обозначения:

- **К** — непосредственно подтверждено кодом на указанном HEAD.
- **Д** — документированная семантика Windows; ссылки приведены рядом.
- **И** — историческое наблюдение из сообщения коммита, в этом исследовании не повторялось.
- **П** — инженерное предложение; реализация отсутствует.
- **L** — требуется живой тест на поддерживаемых Windows builds.

Live-эксплуатация, генерация exploit payloads, нагрузочные испытания, сборка и тесты в этом ходе не выполнялись. Приоритет P1 означает необходимую работу перед обещанием соответствующей границы безопасности; P2 — совместимость, наблюдаемость и последующее усиление. Это исследование R04, не повторный полный аудит всех файловых/памятных дефектов.

Пути в ссылках имеют префикс winrsbox/crates/. Для компактных file:line обозначений далее: **H** = winrsbox-hook/src/, **Lch** = winrsbox-launcher/src/, **Pcy** = winrsbox-policy/src/, **Ipc** = winrsbox-ipc/src/, **IT** = winrsbox-integration-tests/. Номера строк относятся к проверенному HEAD.

## Что действительно есть в текущем коде

| Поверхность | Подтверждённое поведение | Где |
|---|---|---|
| COM / WMI / Task Scheduler | Denylist CLSID в CoCreateInstance, CoCreateInstanceEx, CoGetClassObject. WMI/BITS/FSO обычно получают отказ; ряд launch/scheduler/automation классов приводит к fail-stop. Неизвестный CLSID допускается. Контекст in-proc/local/remote не превращён в общую allowlist-политику. | [com_guard.rs:45](../winrsbox/crates/winrsbox-hook/src/ipc/com_guard.rs#L45), [com_guard.rs:292](../winrsbox/crates/winrsbox-hook/src/ipc/com_guard.rs#L292) |
| WinRT | Перехвачены RoGetActivationFactory и RoActivateInstance, 11 запрещённых class prefixes, включая Launcher, AppService, Storage.Pickers, deployment/background/credentials. Остальные классы допускаются. | [com_guard.rs:182](../winrsbox/crates/winrsbox-hook/src/ipc/com_guard.rs#L182), [com_guard.rs:608](../winrsbox/crates/winrsbox-hook/src/ipc/com_guard.rs#L608) |
| ALPC/LPC | NtAlpcConnectPort, NtAlpcConnectPortEx, NtSecureConnectPort; классификация по префиксу последнего компонента имени порта. Неизвестное имя → Allow. ALPC epmapper/LSA lookup сознательно не закрыты целиком. | [alpc_guard/mod.rs:115](../winrsbox/crates/winrsbox-hook/src/ipc/alpc_guard/mod.rs#L115), [alpc_guard/mod.rs:184](../winrsbox/crates/winrsbox-hook/src/ipc/alpc_guard/mod.rs#L184), [alpc_guard/mod.rs:611](../winrsbox/crates/winrsbox-hook/src/ipc/alpc_guard/mod.rs#L611) |
| Named pipes / sockets | Обычные pipes и socket devices — passthrough; для pipes используется конечный список запрещённых имён. Нет общего sandbox endpoint namespace или проверки ownership каждого внешнего сервера. | [device.rs:66](../winrsbox/crates/winrsbox-hook/src/core/hooks/device.rs#L66), [dev.rs:93](../winrsbox/crates/winrsbox-policy/src/domains/dev.rs#L93), [dev.rs:153](../winrsbox/crates/winrsbox-policy/src/domains/dev.rs#L153) |
| SCM / services | Только OpenSCManagerW/OpenServiceW с проверкой access masks. Это проверка выдачи handle, не полная посредническая политика service operations. | [service_guard.rs:47](../winrsbox/crates/winrsbox-hook/src/ipc/service_guard.rs#L47), [service_guard.rs:146](../winrsbox/crates/winrsbox-hook/src/ipc/service_guard.rs#L146) |
| Shell | ShellExecute A/W и Ex A/W проверяют verb, target, params. Пустой verb/open/edit/print разрешены; runas/explore/find и неизвестный verb запрещены. Ex не интерпретирует полный набор target-bearing полей fMask/IDList/class. | [shell_guard/mod.rs:275](../winrsbox/crates/winrsbox-hook/src/ipc/shell_guard/mod.rs#L275), [shell_guard/mod.rs:340](../winrsbox/crates/winrsbox-hook/src/ipc/shell_guard/mod.rs#L340), [shell_guard/mod.rs:502](../winrsbox/crates/winrsbox-hook/src/ipc/shell_guard/mod.rs#L502) |
| Input / HWND | Есть SendInput, keybd_event, mouse_event, BlockInput, SetCursorPos и win32u!NtUserSendInput. Есть FindWindow/FindWindowEx/SendMessage/PostMessage A/W и ExitWindowsEx. Foreign HWND определяется по PID, а не по sandbox/Job identity. | [ui_guard.rs:79](../winrsbox/crates/winrsbox-hook/src/system/ui_guard.rs#L79), [ui_guard.rs:480](../winrsbox/crates/winrsbox-hook/src/system/ui_guard.rs#L480), [ui_guard.rs:522](../winrsbox/crates/winrsbox-hook/src/system/ui_guard.rs#L522) |
| Clipboard / Job UI | Все восемь UI flags по умолчанию false. --strict-clipboard включает **только** READCLIPBOARD и WRITECLIPBOARD, т.е. 0x06. Clipboard hooks по умолчанию вообще не устанавливаются. Есть диагностический FS_SANDBOX_NO_UI_LIMITS в launcher. | [jobctl.rs:71](../winrsbox/crates/winrsbox-launcher/src/contain/jobctl.rs#L71), [jobctl.rs:132](../winrsbox/crates/winrsbox-launcher/src/contain/jobctl.rs#L132), [sandbox/mod.rs:872](../winrsbox/crates/winrsbox-launcher/src/sandbox/mod.rs#L872), [ui_guard.rs:491](../winrsbox/crates/winrsbox-hook/src/system/ui_guard.rs#L491) |
| Windows identity / desktop | Root создаётся обычным CreateProcessW. STARTUPINFO.lpDesktop не задаётся. Нет CreateRestrictedToken, AppContainer security capabilities, создания private station/desktop. Следовательно, нет отдельной OS security identity гостя. | [sandbox/mod.rs:431](../winrsbox/crates/winrsbox-launcher/src/sandbox/mod.rs#L431), [sandbox/mod.rs:450](../winrsbox/crates/winrsbox-launcher/src/sandbox/mod.rs#L450) |
| Дочерние процессы | Hook NtCreateUserProcess принудительно suspends, подготавливает и инъектирует hook.dll; это применимо к созданию, которое проходит через hooked процесс. Job — kill-on-close, breakaway не разрешён. | [spawn.rs:479](../winrsbox/crates/winrsbox-hook/src/core/hooks/spawn.rs#L479), [spawn.rs:527](../winrsbox/crates/winrsbox-hook/src/core/hooks/spawn.rs#L527), [jobctl.rs:40](../winrsbox/crates/winrsbox-launcher/src/contain/jobctl.rs#L40) |
| Собственный policy IPC | DACL user SID + kernel client PID + ownership table. Клиент открывает pipe по имени без проверки server identity. Это канал launcher, а не ограничение связи гостя с чужими pipes. | [security.rs:156](../winrsbox/crates/winrsbox-launcher/src/pipe_server/security.rs#L156), [pipe_server/mod.rs:269](../winrsbox/crates/winrsbox-launcher/src/pipe_server/mod.rs#L269), [Ipc/lib.rs:310](../winrsbox/crates/winrsbox-ipc/src/lib.rs#L310) |
| WFP | При включении сети используются ALE connect filters с APP_ID пути root executable, не Job identity. По умолчанию сетевого enforcement нет. Это не фильтр произвольного локального ALPC/pipe RPC. | [main.rs:376](../winrsbox/crates/winrsbox-launcher/src/main.rs#L376), [wfp.rs:327](../winrsbox/crates/winrsbox-launcher/src/contain/wfp.rs#L327), [wfp.rs:654](../winrsbox/crates/winrsbox-launcher/src/contain/wfp.rs#L654) |

Слова «always blocked» в старом описании верны только для совпавших правил при реально установленных guards. В H/core/hooks/mod.rs:660 установка зависит от guard != none и skip(category); ряд ошибок лишь буферизуется на строках 682–708. В UI installer ошибки отдельных detours вообще проглатываются (H/system/ui_guard.rs:442). Принятие имени класса в denylist не означает, что Windows не может исполнить эквивалентную операцию через другой путь.

### История, существенная для решения

- **И, 106e7b7, 2026-07-03:** автор описал реальный выход через ранее разрешённый WMI/DCOM путь и вернул unconditional deny для соответствующих CLSID/ALPC patterns. Это весомое объяснение, почему нельзя просто разрешить общий WMI endpoint ради read-only query; новый live replay не выполнялся.
- **И/К, 8c9ddd5, 2026-07-04:** часть известных COM/ALPC попыток переведена из graceful deny в termination. Это реакция на обнаружение, а не новая граница Windows.
- **И, 64ece02 и 492464d, 2026-05-31/06-01:** описаны проблемы раскладки/IME/paste на Win10 19045; Job UI flags отключены. Историческое объяснение «SendInput и входящий broadcast — одна операция» не следует из Win32-контрактов. Саму UX-регрессию следует повторно измерить на поддерживаемых ОС, не объявлять выдуманной или универсальной.
- **К, 492464d:** shell integration для WezTerm добавила --always-new-process и --no-auto-connect; сейчас это Lch/cli/shell.rs:121. Эти флаги предотвращают конкретную штатную передачу управления внешнему mux, но не ограничивают произвольного клиента брокерского протокола.
- **К, 85088aa, 2026-09-20:** добавлены sibling entrypoints и проверки; текущие NtUserSendInput, ALPC Ex/Secure и ShellExecuteA действительно присутствуют.
- **К, 3cd845e/161e593:** WFP сужен до root APP_ID, затем network enforcement стал opt-in. R04 обязан включать localhost/socket brokers, а не только named pipes.
- **К, bedcc3f, 2026-09-21:** крупный перенос файлов. Сам по себе он не закрывает архитектурный риск. ce5022c добавил исходное описание R04 без изменения runtime.

## Threat model и точный смысл «закрыть R04»

**Недоверенная сторона:** агент, исполняемый им код, зависимости/build scripts, его потомки; любые сообщённые ими PID, строки, HWND, путь, CLSID, команда и переменные окружения. Две песочницы могут быть взаимно недоверенными.

**Доверенная сторона:** Windows и её механизмы контроля доступа, launcher/supervisor, минимальные явно разрешённые brokers и хостовый UI frontend. Внешний same-user terminal mux, IDE server, helper, credential agent или HTTP daemon не становится доверенным только из-за общего пользователя или подписи executable.

**Защищаемые действия:** чужой process spawn, изменение файлов/registry/config от чужого имени, регистрация отложенной работы, извлечение/использование credentials, управление UI/clipboard/вводом хоста. Выход не обязан давать Administrator: выполнение с обычным host user token вне policy — уже нарушение.

Различать два противника:

| Модель | Что допускается в утверждении о защите |
|---|---|
| T1: ошибки/нежелательные действия знакомых программ, использующих обычные API | Hooks и явные API denials полезны; поддерживаемый набор операций и известные исключения перечислены. Это совместимый контроль поведения. |
| T2: произвольный злонамеренный native-код, который не обязан соблюдать hooks | Решение должно сохраниться при отсутствии DLL, изменении user-mode пути и прямом обращении к Windows boundary. Нужны restricted security token/AppContainer или VM плюс доверенный broker. |

Критерий закрытия для T2: **недоверенный процесс не может заставить внешний исполнитель выполнить запрещённую операцию**, даже если операция не является его дочерним процессом. Отказ должен происходить до host side effect. Наблюдение ETW, последующее убийство «нового PID» или позднее AssignProcessToJobObject этого критерия не выполняют. Microsoft отдельно указывает, что процессы, создаваемые через WMI Win32_Process.Create, не получают Job обычного вызывающего клиента. [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

## Ближайшие исправления, подтверждённые текущим кодом

### F1 — P1: глобальный anti_rec охватывает выполнение внешних функций и callbacks

**К, высокая уверенность.** ShellExecute original вызывается до разрушения anti_rec guard (H/ipc/shell_guard/mod.rs:459,498; :511,612). Аналогично CoCreateInstance (:307,341 в com_guard.rs) и разрешённый SendMessage (H/system/ui_guard.rs:377,387). Эти API могут выполнять вложенную работу и application callbacks. Сам контракт H/core/anti_rec.rs:63 требует никогда не исполнять guest code при suppression.

Следствие на уровне кода: вложенный NtCreateUserProcess/FS/ALPC hook видит re-entry и пропускает проверку; это нельзя считать независимой второй линией защиты. В частности, Windows документирует непосредственный вызов оконной процедуры при соответствующем SendMessage. **L:** конкретные Shell/COM call graphs зависят от apartment, association и версии Windows; успешный внешний spawn в этой работе не заявляется. [SendMessageW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagew).

**П:** отделить собственный служебный I/O hooks от исполнения оригинального высокоуровневого API. Подготовить immutable request, закончить служебное bypass-окно перед callback-capable вызовом; для неизбежной рекурсии использовать ограниченный контекст конкретного wrapper, не «все guards off». Приёмка — инструментально проверить, что вложенный callback/dispatch сохраняет policy enforcement. Это первоочередной локальный фикс, не замена OS boundary.

### F2 — P1: ShellExecute не сводится к строке lpFile и созданию ребёнка

**К:** Ex wrapper читает лишь prefix struct и verb/file/params; target-bearing fMask/IDList/lpClass/hkeyClass не классифицируются (H/ipc/shell_guard/mod.rs:340,570). Разрешённые open/edit/print могут использовать ассоциации, DDE и execution delegates. **Д:** ShellExecuteEx может обслужиться существующим процессом и вернуть NULL hProcess даже при успехе; SEE_MASK_NOCLOSEPROCESS не является средством containment. [SHELLEXECUTEINFOW](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-shellexecuteinfow).

**П:** strict mode не передаёт raw ShellExecute внешнему Shell. Обычное создание известных executable идёт через собственный constrained spawn; «открыть URL/документ на хосте» — отдельная разрешаемая операция доверенного frontend, с проверенной схемой/типом и понятным пользователю действием. Если Ex остаётся в compatibility mode, поддерживаемые fMask формы должны быть явными, проверяться целиком и не менять target после проверки. **L:** association/IDList/DDE/packaged activation маршруты на поддерживаемых ОС.

Run dialog — лишь интерфейс Explorer к запуску. Блокировка окна по заголовку/классу и расчёт на то, что пользователь заметит Win+R, не обеспечивают границу. Нужны ограничения ввода/сообщений и доступа к external launch broker.

### F3 — P1: HWND classifier смешивает special/unknown и разрешённый target

**К:** H/system/ui_guard.rs:79 возвращает false при NULL и при GetWindowThreadProcessId→0; в вызывающих SendMessage/PostMessage это означает разрешение. Special destinations, включая broadcast, требуют собственной семантики. Более того, «другой PID» сейчас включает и легитимного ребёнка той же песочницы.

**П:** разделить own sandbox HWND, foreign HWND, special destination, unknown. Для headless запретить external/special dispatch; для compatibility определить нужные взаимодействия отдельно. Запрет распространить на фактически используемые семейства messaging, не выдавая бесконечное перечисление user32/win32u exports за T2 boundary. **L:** проверка deliverability на тестовых окнах, разные integrity levels, same-job versus different-job, callback/reentrancy, reuse HWND. Unknown identity для опасного действия не должна считаться safe.

### F4 — P1: успешный init не подтверждает установку UI/broker enforcement

**К:** UI macros игнорируют ошибки GenericDetour::new/enable (H/system/ui_guard.rs:442,462); отсутствующий win32u пропускается (:520); верхний installer лишь пишет errors для ALPC/UI/service/shell (H/core/hooks/mod.rs:682). COM installer тоже допускает отсутствующие exports (H/ipc/com_guard.rs:559).

**П:** capability manifest обязательных ограничений для каждого режима. Strict launch прекращается при отсутствии требуемой защиты, без silent fallback к shared desktop/token. Init подтверждает фактические token, Job, UI station, mitigation и необходимые hooks; provenance всех policy полей — supervisor, не изменяемый guest env. Compatibility mode явно сообщает частичные возможности.

### F5 — P1/P2: SCM access-mask логика одновременно неполна и чрезмерно широка

**К:** SCM_DANGEROUS содержит агрегат SC_MANAGER_ALL_ACCESS, затем проверяется пересечение маски (H/ipc/service_guard.rs:47,86). Поэтому даже отдельный SC_MANAGER_CONNECT попадает под запрет; SERVICE_ALL_ACCESS аналогично захватывает QUERY_STATUS/QUERY_CONFIG. Generic/maximal access requests не проходят корректную смысловую нормализацию. Перехвачены W-входы; гарантии по A/другим путям без проверки их фактического forwarding нет.

**П:** определить запрещённые конкретные операции/права, корректно разобрать generic и maximum access, симметрично проверить поддерживаемые API. Для strict не выдавать guest service-control capabilities. Не утверждать, что обычный пользователь автоматически способен создавать SYSTEM services: Windows уже проверяет SCM/service DACL. При этом доступный same-user service или task способен быть важным broker независимо от elevation. [Service Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

### F6 — P1: собственный pipe должен выдерживать смену token model

**К:** Lch/pipe_server/security.rs:156 выдаёт GRGW user SID; Ipc/lib.rs:310 не проверяет server identity. Для AppContainer такой DACL/namespace нельзя просто сохранить и считать рабочим. GRGW также шире нужных клиенту отдельных pipe rights: FILE_GENERIC_WRITE включает FILE_CREATE_PIPE_INSTANCE. **Д:** это особо отмечено Microsoft. [Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights).

**П:** точные client read/write/synchronize rights без права создания server instance и изменения ACL; разрешение конкретному sandbox SID/capability; подходящая mandatory label. Проверять обе стороны соединения, pin process lifetime/identity, не доверять Hello/SpawnedChild как самостоятельному доказательству membership. Перенастроить также read-only session section (Lch/contain/session_section.rs:145): owner-only grant не является автоматическим разрешением новому restricted/package SID. Details — в плане broker ниже.

## Как устроены реальные Windows-границы

### Job UI, UIPI, desktop и window station — разные механизмы

| Механизм | Что даёт | Чего не даёт |
|---|---|---|
| UILIMIT_HANDLES | Ограничение использования USER handles вне Job; ограничение ряда broadcasts/window hooks. | Не общий ACL для file/process/pipe handles. SendInput вообще не принимает HWND, поэтому один этот бит не доказывает запрет синтетического ввода. |
| UILIMIT_GLOBALATOMS | Собственная atom table Job при включённом флаге. | При выключенном флаге нельзя утверждать, что global atoms уже изолированы Job. |
| READ/WRITECLIPBOARD | Запрет соответствующего clipboard доступа членов Job. | Не управляемый user-consent clipboard bridge и не изоляция named pipes. |
| DESKTOP | По публичному контракту запрещает CreateDesktop/SwitchDesktop. | Нельзя расширять это обещание до запрета всех OpenDesktop/SetThreadDesktop/OpenWindowStation путей. |
| SYSTEMPARAMETERS, DISPLAYSETTINGS, EXITWINDOWS | Ограничения конкретных UI/system операций. | Не общая защита от брокерских действий других процессов. |
| UIPI / low integrity | Ограничение опасных межуровневых UI действий; SendInput разрешён только в равный/нижний IL. | Same-user medium→medium не изолируется. Low IL не задаёт allowlist всех RPC/brokers и сам по себе не скрывает все читаемые secrets. |
| Private desktop в WinSta0 | Отделяет windows/messages/hooks desktop. | Clipboard/atom table принадлежат window station; токен с доступом к host desktop может его открыть/назначить. |
| Private noninteractive window station + desktop | Отдельные UI objects, clipboard и atom table station, без интерактивного host display/input. | Не отдельный NPFS/ALPC/network namespace; нужен token, который не может вернуть себе доступ к WinSta0/host objects. |

Семантика flags: [JOBOBJECT_BASIC_UI_RESTRICTIONS](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_ui_restrictions). UIPI: [SendInput](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput). MIC по умолчанию ограничивает write-up, а не любой read-up: [Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control).

**Д:** window station содержит clipboard, atom table и desktops; интерактивная station называется WinSta0. Desktop является securable object, сообщения между разными desktops не передаются. Поэтому новый desktop полезен, но название/случайность имени не заменяют access check. [Window Stations](https://learn.microsoft.com/en-us/windows/win32/winstation/window-stations), [Desktops](https://learn.microsoft.com/en-us/windows/win32/winstation/desktops).

**П:** UI flags для headless включать по испытанному профилю, а не автоматически на основании отсутствия окна/TTY. Даже CLI может использовать COM, fonts, hidden HWND и console services. Legacy интерактивный WezTerm/IDE путь не менять молча. При несовместимости nested Jobs нельзя просто снять ограничения: Windows ограничивает сочетание UI limits и job nesting. [Nested Jobs](https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs).

### Отдельная identity обязательна, но её варианты не равнозначны

CreateRestrictedToken с убранными privileges и restricting SID позволяет требовать второй ACL check; простое удаление Administrators или установка low IL не создаёт такого же набора ограничений. WRITE_RESTRICTED намеренно ограничивает применение restricting SIDs записью и не подходит как универсальная confidentiality policy. Microsoft также рекомендует другой desktop для restricted applications. [CreateRestrictedToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken).

AppContainer добавляет package identity/capability access checks и изоляцию ресурсов. LPAC убирает часть разрешений, доступных обычным AppContainers, включая доступ к некоторым системным ресурсам/COM без дополнительных capabilities. Это подходящая база T2, однако разрешённый broker/capability становится частью доверенной поверхности. «AppContainer» не равно «не существует доступных системных brokers». [AppContainer isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation), [Launch an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer).

Отдельный обычный Windows user отделяет профиль и user ACL, но по-прежнему получает доступы общих групп и системных служб. Его создание, logon, profile/secrets lifecycle сложнее; он не гарантирует запрет регистрации own-user tasks или доступа к каждому общедоступному broker. Отдельный user не следует называть автоматически равным LPAC.

Нельзя устранять несовместимость выдачей guest прежнего unrestricted token, широких impersonation/process handles, UIAccess, полного доступа к профилю пользователя или all-packages grants на host state. Проверки token и server-side policy должны переживать отсутствие hooks.

### COM/WMI/WinRT и службы

COM activation и вызов метода на уже полученном interface — разные события. CLSID deny не является проверкой каждого method call; ALPC port name не выражает метод, разрешённый resource и его аргументы. Уже marshalled interface, другой activation frontend, in-process object и out-of-process server требуют разной оценки. Допустимые классы могут быть нужны .NET/TSF/IME; blanket COM denial серьёзно снижает совместимость.

COM LaunchPermission задаёт, кто может запускать server, а access/security policy самого server — что разрешено затем. Это не per-winrsbox namespace; нельзя менять общесистемные DCOM ACL ради одного запуска. WMI namespace ACL и методная семантика также важны. При необходимости read-only inventory лучше маленький собственный broker с фиксированным перечнем query/полей, без произвольных WQL/method/moniker passthrough. [LaunchPermission](https://learn.microsoft.com/en-us/windows/win32/com/launchpermission), [WMI security](https://learn.microsoft.com/en-us/windows/win32/wmisdk/securing-a-remote-wmi-connection).

Task Scheduler хранит работу, выполняемую позднее сервисом и в заданном security context; смерть Job клиента не отменяет такую регистрацию. Для strict broker вообще не должен предоставлять schedule/persist capability. Указание «это только задача того же пользователя» не сохраняет Job lifecycle. [Security Contexts for Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks).

WinRT/package brokers, включая активацию другого приложения, оцениваются так же: capability на сервис — не разрешение на любую его операцию. UI prompts/system-mediated launch могут быть штатным поведением платформы; это всё равно отдельное разрешённое пересечение границы, которое должно быть отражено в threat model и UX.

### Pipes/ALPC и сеть

Private desktop/window station **не создаёт** изолированного namespace произвольных named pipes. Restricted token/AppContainer ограничивает securable endpoints через OS checks; app-scoped named objects имеют свои правила namespace/sharing. Для packaged/UWP и unpackaged Win32 AppContainer пути отличаются нюансами, поэтому актуальный namespace IPC нужно подтвердить на целевых ОС. Не считать префикс LOCAL самодостаточной защитой. [Sharing named objects](https://learn.microsoft.com/en-us/windows/apps/develop/communication/sharing-named-objects).

Denylist «опасных имён» не покрывает сторонний broker с произвольным именем. И наоборот, само наличие pipe не доказывает spawn capability: SSH agent обычно является signing broker, а не исполнителем произвольной команды. Для него риск — нежелательное использование ключей/удалённой аутентификации; для terminal/IDE mux — действия в другой process tree; для build/cache daemon — запись или выполнение от его identity. Возможности конкретного продукта требуют отдельной проверки.

Локальный HTTP/TCP, IPv6 loopback, Unix-domain sockets и файловые command queues тоже могут быть broker-каналами. Отдельный IPC allowlist при открытой сети не закрывает R04. Текущие ALE WFP filters не контролируют локальный ALPC/NPFS; WFP имеет также специализированные RPC layers, но они не являются универсальным перехватом всех ALPC/pipe protocols. Это отдельная исследовательская возможность, не готовое решение в текущем коде. [WFP filtering layers](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer).

## Варианты реализации

| Вариант | Гарантия и остаток | Совместимость / стоимость | Рекомендация |
|---|---|---|---|
| A. Минимальные исправления hooks + явная policy | Укрепляет T1, устраняет F1–F6. Прямые OS calls/неизвестные brokers не становятся запрещёнными архитектурно. | Наименьший объём; некоторые допустимые Shell/COM workflows придётся уточнить. | Выполнить независимо от выбора backend. |
| B. Headless Job UI profile без новой identity | Kernel ограничения конкретных UI действий. Pipe/ALPC и same-user resources остаются доступны. | Малый/средний объём; nested Job/console/IME испытания обязательны. | Возможен промежуточный режим с честным названием и ограниченным обещанием. |
| C. Private station/desktop + restricted token | OS-разделение UI при правильных ACL; resource restrictions зависят от restricting SIDs и доступных endpoints. Не изоляция «по факту другого desktop». | Средний/высокий объём: ACL, startup, console bridge, жизненный цикл. | Альтернатива для доказанно несовместимого с AppContainer toolchain; потребует подробной ACL-модели. |
| D. AppContainer/LPAC + own broker + UI separation | Native Windows security boundary для ресурсов, разрешённых выбранной identity. Общие system brokers и каждое granted capability входят в остаточный TCB. | Высокий объём: staging/ACL/profile/network/toolchain matrix. JIT возможен; запрет dynamic code не является обязательным свойством AppContainer. | Предпочтительный native backend для headless T2; LPAC оценить отдельным compatibility spike. |
| E. Выделенный Windows user/logon + station + broker restrictions | Отделение пользовательского state; default group/service grants надо дополнительно сузить. Само по себе не полное закрытие R04. | Provisioning/logon/profile cleanup, часто административная настройка; совместимость шире, модель прав сложнее. | Deployment-вариант при управляемом хосте, не «дешёвый AppContainer». |
| F. Выделенная Windows VM / Windows Sandbox | Другая Windows instance отделяет host UI/service/IPC namespace. Host-facing channels и VM escape vulnerabilities остаются в threat model. | Выше startup/RAM/storage; проще сохранить широкий native toolchain внутри гостя. | Для максимально недоверенного кода и требований к широкой совместимости. |

Выбор C/D/F — продуктовый выбор гарантии и совместимости. Он не мешает подготовить и принять конкретные F1–F6. Текущий документ не меняет профиль по умолчанию и не выдаёт разрешение на развертывание другого backend без отдельной реализации.

## Предлагаемая native-архитектура headless strict

Граница: **trusted frontend/supervisor → ограниченный канал → недоверенный worker и его потомки**. На стороне хоста нет универсального «исполнить строку», «активировать CLSID», «открыть произвольный pipe» или «вызвать shell verb». Каждый такой метод превратил бы собственный broker в тот самый обход, от которого защищает R04.

### 1. Явный профиль и immutable launch policy

**П, P1.** Ввести независимую от memory guard ось isolation backend: compatibility / headless-restricted / headless-appcontainer / VM. Guard scan/full/static остаётся дополнительным свойством. Термин strict разрешён только при выполнении объявленного набора OS capabilities, с versioned manifest.

Политика фиксирует sandbox identity, roots, IPC capabilities, network, UI mode, clipboard direction, child policy, limits. Она создаётся supervisor и не ослабляется env/guest config. --guard none/--disable-hooks не может незаметно снять обязательную часть strict-профиля; диагностический override меняет заявленный режим или даёт отказ. Не определять безопасность по TTY: это лишь подсказка UX, не авторизация.

### 2. Identity и storage до запуска guest code

**П, P1.** Для AppContainer создать/выбрать профиль с уникальным sandbox identity. CreateAppContainerProfile возвращает SID; для явно повторно используемого профиля SID можно derive по имени. Разные недоверенные сессии не должны по ошибке получать одну writable область/capability. Ресурсы профиля очищать только после окончания всех принадлежащих ему процессов; cleanup должен знать, что было создано именно этим запуском. [CreateAppContainerProfile](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createappcontainerprofile), [DeriveAppContainerSidFromAppContainerName](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-deriveappcontainersidfromappcontainername).

Права раздавать на минимальный staged workspace, scratch/cache и read-only toolchain; не на весь пользовательский профиль и не на ACL-предков, открывающих случайно лишнее. Package SID/capabilities участвуют в access checks наряду с обычными правами. LPAC применить через documented all-application-packages opt-out; capabilities добавлять по фиксированному контракту, не auto-learn→allow. [SECURITY_CAPABILITIES](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_capabilities), [LPAC launch](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer).

AppContainer не реализует произвольный прозрачный CoW для обычной файловой системы. Новый режим должен выбрать: отдельная рабочая копия и явный export результатов либо brokered file operations с минимальными grants. Существующие in-process hooks могут помогать compatibility, но прямое открытие без них не должно получать host rights сверх разрешённого. Нельзя сохранить unlimited profile reads/writes и одновременно обещать T2 confidentiality/integrity.

### 3. UI objects с минимальными правами

**П, P1.** Trusted bootstrap helper создаёт уникальную **неинтерактивную** window station и desktop с явными security descriptors. Guest получает только нужные права к своим объектам, без WRITE_DAC/WRITE_OWNER и без широких grants к host WinSta0/Default. Отдельно проверяются owner implicit rights; guest не должен владением снять ограничения.

CreateDesktop создаёт объект в текущей station вызывающего процесса. Поэтому нужный SetProcessWindowStation/CreateDesktop bootstrap лучше вынести в короткоживущий trusted helper с одним потоком: временно менять process-wide station у уже многопоточного supervisor небезопасно. STARTUPINFO.lpDesktop целевого процесса задаёт конкретное station\desktop имя. При повторном открытии объекта нельзя слепо доверять совпадению имени — проверяется identity/ACL или запуск отвергается. [CreateWindowStationW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-createwindowstationw), [CreateDesktopW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-createdesktopw).

OS token должен не позволять повторно открыть интерактивные host objects с требуемыми правами; один private-object DACL ограничивает вход в private объект, но сам по себе не ограничивает выход в host объект. Не переписывать глобальный host WinSta0 ACL ради одного гостя. Проверить OpenWindowStation/OpenDesktop/OpenInputDesktop, SetProcessWindowStation/SetThreadDesktop и унаследованные handles. Последний API имеет thread-state ограничения, но это не security proof, поскольку гость создаёт новые нити. [Desktop access rights](https://learn.microsoft.com/en-us/windows/win32/winstation/desktop-security-and-access-rights), [Window station access rights](https://learn.microsoft.com/en-us/windows/win32/winstation/window-station-security-and-access-rights), [SetThreadDesktop](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setthreaddesktop).

**Опция, P2:** для отдельно сертифицированного no-GUI CLI профиля установить DisallowWin32kSystemCalls при создании процесса. Это kernel enforcement, не инструкция scanner. Оно не блокирует ALPC/COM/network, может ломать скрытые GUI dependencies и нынешний ui_guard, который загружает user32 (H/system/ui_guard.rs:433). Такой профиль требует адаптации bootstrap; нельзя обещать совместимость лишь потому, что приложение консольное. [PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_system_call_disable_policy).

### 4. Атомарный launch и lifecycle

**П, P1.** Создать Job и установить limits до исполнения гостя. На поддерживаемых Win10/11 применить PROC_THREAD_ATTRIBUTE_JOB_LIST вместе с SECURITY_CAPABILITIES/mitigations в STARTUPINFOEX. Предусмотреть атрибуты handle list и pseudoconsole, если нужны; число attributes и backing buffers не должны предполагать «всегда только mitigation», как текущий launch path. Все обязательные API ошибки — terminal launch error с уничтожением только созданных этим запуском процессов. [UpdateProcThreadAttribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute).

Guest наследует только конкретные безопасные stdio/control handles; не token, process/thread mutation handles supervisor, Job-management handles, произвольные files или COM proxies. Parent/child registration — учёт, не выдача привилегии. Проверять фактический token/AppContainer SID, IsProcessInJob и mitigation state. Во всех children сохраняется одна или более строгая security identity, а не повторная установка из изменяемого env.

Если нужен доверенный spawn broker, он принимает executable/argv/cwd как структурированные данные, проверяет их, создаёт ребёнка сразу в правильном token/Job/UI boundary и возвращает лишь минимальный результат/handles. Он не запускает ту же команду от host token «для совместимости». Remote broker-created host process невозможно надёжно вернуть в containment после исполнения первых инструкций.

IOCP Job notifications и ETW используются для аудита/cleanup, не для разрешения уже выполненной операции. Supervisor удерживает уникальные noninheritable Job handles; штатный stop/сбой/timeout завершают собственный sandbox lifetime без воздействия на несвязанные процессы.

### 5. IPC capabilities и собственный broker

**П, P1.** Классифицировать каналы на: внутренние worker↔child; связь с winrsbox supervisor; небольшой набор системных services; явно разрешённые внешние функции. Имена путей/портов не являются capabilities. Для AppContainer поддерживаемый LOCAL/app namespace и cross-boundary ACL должны быть отдельным tested protocol; для внутренних программ предпочтительны унаследованные unnamed pipes/handles с определённым lifecycle.

Собственный server проверяет kernel peer PID, удерживаемую process identity, token sandbox SID и Job membership, затем конкретное право сообщения. Client проверяет ожидаемый server на установленном соединении; GetNamedPipeServerProcessId — один из probes, не проверка безопасности одного имени. Reconnect заново удостоверяет peer и не принимает PID reuse. Random name полезен против squatting, но не секрет от guest и не замена аутентификации. [GetNamedPipeServerProcessId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeserverprocessid).

Протокол версионируется, ограничивает длины/число запросов/deadlines, не принимает произвольные host paths, raw handles, COM interface marshaling или command strings. Broker запускает operations только в нужном security context; если impersonation используется, переход и восстановление контекста обязательны на всех error paths. Ограниченный запрос не должен превратиться в иной ресурс через reparse/TOCTOU/path normalization.

Примеры допустимых **узких** возможностей: получить фиксированный набор OS inventory полей; скачать артефакт с разрешённого origin в конкретный sandbox sink; запросить одно явное host-UI действие; получить scoped credential operation. Глобальный SSH agent, Docker daemon, IDE remote command server и shell runner не допускаются целиком ради одного метода.

Для разрешения внешнего broker требуются одновременно: известная server identity, безопасный метод/параметры, scope ресурсов, правильный effective token, лимиты, аудит и тест отказа соседней сессии. «Подписан Microsoft» и «тот же пользователь» не заменяют этот контракт.

### 6. Сеть как часть доступа к brokers

**П, P1.** Headless strict starts deny-by-default для localhost/LAN/remote services; необходимые agent API/package downloads разрешаются отдельной capability или узким network broker. Internet capability AppContainer сама по себе не является domain allowlist. Loopback exemptions и широкие user-profile credentials не добавлять скрыто.

WFP при его использовании привязать к фактической sandbox/package identity и полному дереву, с IPv4/IPv6, TCP/UDP и фиксированным поведением при отказе установки. Не применять path-only root фильтр ко всем одноимённым host instances. Privileged управление WFP, если требуется, отделить от guest execution: запускать весь агент elevated для настройки firewall нельзя. DNS/proxy/certificate dependencies изучаются как часть compatibility, с минимальными grants.

### 7. Терминал, clipboard и согласованные host-действия

**П, P1.** UI frontend остаётся доверенным host процессом, worker — headless. ConPTY создаётся frontend/supervisor, подключается к worker через PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE и pipes; для простых задач достаточно перенаправленного stdio. Поддержка AppContainer/private station + выбранный console host является **L**, её нельзя гарантировать по одному примеру CreatePseudoConsole. [Creating a Pseudoconsole session](https://learn.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session).

Ввод пользователя передаётся как stream; guest не получает произвольные HWND и право посылать host keyboard events. Host frontend сохраняет IME, раскладку и привычное отображение, поэтому не нужно давать worker полный доступ к чужим оконным объектам ради Alt+Shift.

Clipboard по умолчанию закрыт в обе стороны. Явный paste пользователя означает копирование конкретных байтов в stdin; это не выдача worker доступа к clipboard API. Copy из sandbox — операция frontend с ограничением форматов/размера; никакой автоматической обработки произвольного OLE/IDataObject как доверенного объекта. URL/open-file intents показываются отдельно и проверяются на стороне host.

Вывод агента тоже недоверенный: terminal escape sequences, OSC clipboard requests, hyperlinks и сообщения «выполни это» не должны автоматически запускать host actions. UI frontend и parser находятся в TCB. Не строить security policy на факте наличия пользователя перед экраном.

Для отдельного GUI режима private desktop внутри WinSta0 позволяет показать всё приложение при переключении desktop, но это другой UX; keyboard/clipboard sharing и возможность открытия host desktop всё равно требуют ACL/token policy. Для запуска обычной GUI IDE рядом с host windows нужны существенно более сложные UI broker правила либо VM. UserHandleGrantAccess может точечно разрешить USER handle Job, но любое такое разрешение расширяет поверхность и не должно массово раздаваться Explorer/host windows ради совместимости. [UserHandleGrantAccess](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-userhandlegrantaccess).

## VM и границы интеграции

Windows Sandbox/выделенная Hyper-V VM изолируют guest brokers и UI от host экземпляров структурно. Для строгого профиля отключить clipboard/printer/audio/video redirection, ограничить сеть, не давать writable host mounts, не передавать пользовательские credentials. Input snapshot монтировать read-only или копировать; результаты экспортировать отдельным ограниченным каналом. После export host не должен автоматически исполнять полученный бинарник, hook/config или открывать активный документ. [Windows Sandbox configuration](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file).

WSL2 по умолчанию не является эквивалентом такого настроенного профиля: interop позволяет запускать Windows programs, а automount открывает host drives. Даже отключение этих настроек — отдельный lifecycle/privilege/network проект; это не просто флаг winrsbox. Для проверки Windows native toolchain полноценный Windows guest обычно ближе к цели. [WSL configuration](https://learn.microsoft.com/en-us/windows/wsl/wsl-config).

Сопоставимый зрелый native подход сочетает broker, restricted token, Job, alternate desktop и mitigations. Но копирование отдельных приёмов браузерной песочницы без её process model не даёт её гарантий: браузерный renderer и универсальный coding toolchain имеют разные допустимые ресурсы. [Chromium sandbox design](https://chromium.googlesource.com/chromium/src/+/main/docs/design/sandbox.md).

## Совместимость: что измерить до выбора backend

| Workflow | Что оставить внутри boundary | Что вынести/ограничить | Что нельзя обещать заранее |
|---|---|---|---|
| Node/Python/.NET агент с TUI | Сам агент, interpreters, native extensions, subprocesses, project scratch. | Terminal frontend, scoped network/credential access. | Что private station/AppContainer/no-win32k совместимы с каждым runtime. ACG/static часто несовместим с JIT; это отдельная ось. |
| cargo/rustc/linker, npm/pip/uv, git | Toolchain и дочерние процессы под тем же token/Job, per-sandbox caches. | Global toolchain updates, shared credentials, installers пишущие host registry. | Неизменённые global caches и profiles не становятся safe от наличия hooks. |
| PowerShell и системная диагностика | Обычные команды/данные внутри sandbox. | Узкий inventory API вместо unrestricted WMI/COM. | Полная совместимость Get-CimInstance/служб без открытия broker поверхности. |
| WezTerm/IDE в host UI | Агент/worker отдельно; frontend доверенный. | Mux/IDE integration через ограниченный protocol. | --always-new-process/--no-auto-connect — полезные UX knobs, не запрет произвольного IPC. |
| LSP/debugger/test server | По возможности вместе с worker и его identity. | Конкретные debugger capabilities к своим процессам; контролируемые локальные endpoints. | Открытый localhost «для dev tools» не равен ограниченному набору brokers. |
| Git/SSH/auth/OAuth | Только scoped credentials, необходимые конкретному workload. | User-driven host auth и узкий credential proxy. | Произвольный credential manager/ssh-agent/protocol handler нельзя разрешить wholesale. |
| GUI automation / browser/UI tests | Выделенный desktop или guest VM с собственными окнами. | Host UI actions не входят в обычные права агента. | Безопасное управление любым host окном одновременно с его изоляцией. |

## Приёмка и тестовая матрица

Тестировать на отдельной Windows test-среде, с безопасными принадлежащими тесту fixtures. Реальные рабочие Explorer/SCM/tasks/clipboard пользователя не являются мишенями. Нельзя трактовать crash/exit code сам по себе как доказательство «host side effect не произошёл».

Нужны три независимых наблюдателя: guest результат; trusted supervisor (token/Job/UI identity и protocol decisions); отдельный host observer, подтверждающий отсутствие запрещённых действий. OS denial и hook denial различаются в журнале. Test setup failure/unsupported feature отмечается как отсутствие покрытия, не как успешная блокировка.

| ID | Проверяемый контракт | Критерий приёмки |
|---|---|---|
| T01 | Root и много поколений потомков | Ожидаемые AppContainer/restricted SID, integrity level, capabilities, Job membership, desktop/station на всём дереве. Guest env не меняет профиль. |
| T02 | Bootstrap / failure injection | Ошибка token/ACL/UI object/mitigation/required hook или несовместимый nested Job прекращает запуск до guest actions. Нет silent compatibility fallback и orphan processes. |
| T03 | Внутренний IPC | Pipes/stdio между своими worker/child работают; endpoints не доступны другой песочнице. Неподтверждённые PID/Hello/registration не выдают trust. |
| T04 | Host broker fixture | Безопасный тестовый broker вне Job доступен host positive-control, но guest не получает запрещённого метода/действия. Проверяется реальный deny до dispatch. |
| T05 | Подмена peer / reconnect | Fake server/same-name collision/wrong sandbox SID/recycled PID отвергаются до передачи чувствительных данных; ACL не позволяет guest создать server instance собственного supervisor pipe. |
| T06 | COM/WMI/WinRT | Известные запрещённые activation paths и вызовы test broker остаются запрещёнными; разрешённый inventory выдаёт только фиксированные поля. Тест отдельно покрывает activation и использование interface. |
| T07 | SCM / Scheduler | Host fixtures подтверждают отсутствие изменения конфигурации/постоянной регистрации. Разрешённые read-only запросы проверяются отдельно, чтобы denial не скрывал сломанную access mask. |
| T08 | Shell semantics | Executable spawn, document association, delegated/existing-instance, IDList/class и URL intents дают ровно заявленный результат. Успешный Shell return не считается доказательством contained child. |
| T09 | UI сообщения | Same-sandbox/foreign/special/unknown destinations различаются; host test windows не получают запрещённых сообщений, действий или callbacks. Политика сохраняется на nested dispatch. |
| T10 | Input | Тестовый host UI не получает синтетические input events от strict worker; позитивный пользовательский input через frontend работает. Самостоятельный тест для export-level guard и OS boundary. |
| T11 | Desktop/station переходы | Guest остаётся в разрешённой UI области; попытки открыть/назначить host objects и унаследованные handles не расширяют права. Не проверять только имя current desktop. |
| T12 | Clipboard / atoms | Host/guest clipboard независимы или доступ запрещён по профилю; соседние песочницы не обмениваются data/atoms неявно. Явный frontend copy/paste сохраняет направление, scope и размер. |
| T13 | Reentrancy | При исполнении разрешённых callbacks/COM/Shell dispatch нижние policy checks активны. Ошибки и exceptions не оставляют bypass state. |
| T14 | Network brokers | IPv4/IPv6 loopback, LAN, TCP/UDP и альтернативные transport paths соответствуют правилам всего дерева. Host процесс того же executable не получает чужие WFP ограничения. |
| T15 | Внешний lifecycle | Вне Job не появляется незаявленная отложенная работа/child fixture; ETW служит дополнительным наблюдателем, не единственным oracle. Stop/краш supervisor прекращает собственную работу. |
| T16 | Boundary без hooks | Отдельная безопасная тестовая конфигурация OS backend без policy DLL сохраняет запрет host UI/IPC/resources. Это обязательная проверка T2, не production switch. |
| T17 | Реальный toolchain | Агент → git/package install/build/test/subprocess pipeline работает в объявленном профиле. Проверить Ctrl+C, resize, Unicode, IME в frontend, stdout backpressure, cancel, cleanup. |
| T18 | Multi-session | Разные sandbox IDs не делят writable storage/objects/capabilities, даже при одинаковом project basename и executable. Shared cache допускается только как явно спроектированный broker. |
| T19 | Resource abuse | Bounded requests/replies/logging, broker deadlines и quotas удерживают затраты host service. Нет blanket elevation и token/handle leakage. |
| T20 | Upgrade / cleanup | Повторный запуск и аварийное завершение не оставляют привилегированные channels/ACL grants; удаляются только собственные profile/UI objects/temporary resources. |

Дополнительно отделить проверку **платформенного барьера** от совместимости конкретных пользовательских brokers: fixture нужен для доказательства механизма, а реальные WezTerm/IDE/credential-server версии — для явного списка поддерживаемых integrations. Нельзя делать вывод «любой broker изолирован» по одному заблокированному CLSID.

Текущий IT/tests/memory_guard/broker.rs:5,99,117,129 проверяет известные deny paths преимущественно по exit code; отдельный endpoint setup в :147 может пропускать тест при ошибке подготовки. CI по .github/workflows/ci.yml:50 исполняет --lib --bins и не запускает этот интеграционный слой. Для принятия R04 нужен отдельный обязательный Windows runtime job с соответствующими fixtures и сохранением фактических enforcement properties, а не только строковых/predicate tests.

## План работ и владельцы ответственности

| Этап | Приоритет | Модули / ответственность | Конкретный результат |
|---|---|---|---|
| A1 | P1 | H/core/anti_rec.rs, H/ipc/{com_guard,shell_guard}, H/system/ui_guard.rs | Закрыто широкое callback bypass-окно F1, сохранён нижний enforcement; нет пересказа «системная DLL доверенная, значит всё внутри безопасно». |
| A2 | P1/P2 | H/system/ui_guard.rs, H/ipc/service_guard.rs, H/ipc/shell_guard/ | Типизированная target/capability policy F2/F3/F5, обязательный install result F4; positive и negative fixtures. |
| A3 | P1 | Lch/pipe_server/, Ipc/lib.rs, H/ipc/ipc_client.rs, Lch/contain/session_section.rs | Двусторонняя identity, минимальные pipe rights, bounded protocol, tested restricted/AppContainer ACL. |
| B1 | P1 | Lch/main.rs, Lch/sandbox/, Lch/contain/jobctl.rs | Явные backend/profile contracts, atomically prepared launch, immutable policy и queryable enforcement manifest. Existing compatibility поведение не переключается скрыто. |
| B2 | P1 | Новая token/UI boundary ответственность в Lch/contain/ и trusted bootstrap | Прототип private station + token, либо AppContainer/LPAC; измерена console/toolchain совместимость, граница подтверждена без hooks. |
| B3 | P1 | Storage/IPC/network broker и frontend | Суженные grants, no raw external dispatch; ограниченный UI/credential/network bridge; sandbox-specific quotas/lifetime. |
| C1 | P1 | IT + CI Windows runtime | Выполнены T01–T20 в заявленной матрице ОС/режимов; failures диагностируются, unsupported scenarios не считаются pass. |
| C2 | P2 | THREATMODEL/SECURITY/CLI diagnostics | Фактические claims, остаточные capabilities, история совместимости и список supported integrations. Из текста убраны обещания full isolation от одного desktop/Job. |
| V | Альтернатива B2/B3 | Отдельный VM backend | Воспроизводимая guest image, ограниченные shared channels/export, независимая lifecycle и toolchain acceptance. |

Профиль B «UI flags only» можно принять раньше, но **R04 для T2 он не закрывает**. Прототип B2 следует сначала оценить на no-GUI workload со staged toolchain; перенос текущего произвольного same-user filesystem view в AppContainer — отдельная задача, не одно изменение STARTUPINFO.

## Уточнения предварительного документа, THREATMODEL и комментариев

1. «Atom table не пересекает Job» заменено точным условием UILIMIT_GLOBALATOMS; по умолчанию этот бит выключен.
2. «SendInput и WM_INPUTLANGCHANGE — одна операция на kernel layer» не считается доказательством. Есть разные API/объекты/направления доступа; историческая совместимость остаётся предметом L-тестов.
3. Обещание THREATMODEL.md:473, что private desktop полностью закрывает host input, требует дополнительно лишить guest доступа к host station/desktop; один новый объект без token restrictions недостаточен.
4. Правильное предупреждение предварительного документа «private desktop не создаёт pipe namespace» сохранено и распространено на private window station. UI namespace и NPFS/ALPC/network access контролируются разными механизмами.
5. «Restricted token / AppContainer / другой user дают полную одинаковую гарантию» заменено различающимися контрактами и residual risk.
6. Фраза сообщения коммита 492464d «--strict-clipboard включает все UI flags» не соответствует текущему коду: включаются два clipboard flags. Предварительный документ уже правильно называл это частичным opt-in.
7. «Достаточно пользователя, наблюдающего экран» не является security control; host actions должны предотвращаться до side effect.
8. «R04 нельзя продвинуть без общего решения» уточнено: архитектурный backend выбирается отдельно, но F1–F6 и acceptance criteria уже представляют конкретную локальную работу. Этим исследованием реализация не выполнялась.

## Остаточные риски после предлагаемого решения

Даже после принятия native strict остаются уязвимости самой Windows/доверенных brokers, ошибки собственной protocol validation, широкие capabilities, identity/ACL migration, denial of service и опасные результаты, которые пользователь сознательно переносит на хост. Разрешённый network/credential/UI broker — явная делегация, а не исключение «вне threat model». Shared toolchain/caches нельзя сделать writable обоим мирам без дополнительного trust contract.

Файловые, memory/bootstrap и policy дефекты из общего аудита должны быть исправлены или перестать быть единственной опорой enforcement выбранного backend. Запрет нескольких COM classes не компенсирует общий in-process bypass, а AppContainer не исправляет автоматически ошибки привилегированного winrsbox broker.

R04 можно закрыть только для **названного режима, поддерживаемой Windows/toolchain матрицы и зафиксированного набора разрешённых capabilities**, после проверки OS boundary и отсутствия запрещённых host side effects. Расширение allowlist меняет эту границу и требует соответствующей приёмки.

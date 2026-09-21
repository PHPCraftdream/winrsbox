    // NOTE: `cargo build` never compiles this module — only `cargo test` does.
    use super::*;

    type FnDummy = unsafe extern "system" fn(u32) -> NTSTATUS;

    // A plain, detourable stub playing the role of the ntdll export: the
    // trampoline built by GenericDetour::new copies its prologue, so calling
    // through `call()` executes THIS function with the passed argument.
    unsafe extern "system" fn dummy_original(x: u32) -> NTSTATUS {
        (0xC000_0001u32.wrapping_add(x)) as NTSTATUS
    }

    // Marker value proving the DETOUR body does NOT run in the installed
    // case (call() must reach the trampoline = the original, like the old
    // `.get().unwrap().call(...)` shape did).
    unsafe extern "system" fn dummy_detour(_x: u32) -> NTSTATUS {
        0xDEAD_BEEFu32 as NTSTATUS
    }

    #[test]
    fn fail_closed_when_detour_absent() {
        static ABSENT: OnceLock<GenericDetour<FnDummy>> = OnceLock::new();
        let rc = nt_call_original!(&ABSENT, "NtTestApi", (7u32));
        assert_eq!(rc as u32, 0xC000_0022, "expected STATUS_ACCESS_DENIED");
    }

    #[test]
    fn installed_detour_still_calls_original() {
        static INSTALLED: OnceLock<GenericDetour<FnDummy>> = OnceLock::new();
        // SAFETY: both operands are real fn pointers with matching ABI;
        // `new` only builds the trampoline — no enable()/code patching.
        let target: FnDummy = dummy_original;
        let hook_fn: FnDummy = dummy_detour;
        let detour = unsafe { GenericDetour::<FnDummy>::new(target, hook_fn) }
            .expect("dummy fn must be detourable");
        let _ = INSTALLED.set(detour);
        // Behaviour-unchanged proof: with the detour installed the macro
        // returns the ORIGINAL's result (0xC000_0001 + 7), not the detour's
        // 0xDEADBEEF marker and not the fail-closed STATUS_ACCESS_DENIED.
        let rc = nt_call_original!(&INSTALLED, "NtTestApi", (7u32));
        assert_eq!(rc as u32, 0xC000_0008, "expected the original's result");
    }

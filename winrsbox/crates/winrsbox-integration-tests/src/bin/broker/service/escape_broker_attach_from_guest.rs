// MP-10 §B3: a GUEST process (running inside a session's job, injected and
// containment-checked like any other sandboxed target) connects directly to
// the broker's pipe and sends the broker-only `Attach`/`PolicyMutate`
// requests. Job membership alone must not authorize them —
// `pipe_server::mod.rs::handle_connection`'s guest-facing dispatch must
// reject both with `Resp::Err`, never `Resp::Attached`/`Resp::PolicyMutated`,
// and never a silently dropped connection either.
//
// The pipe name is supplied as args[1] by the test (read from `broker.json`
// beforehand) — this guest cannot read `.winrsbox`/`broker.json` itself
// under the sandbox's own containment, so this is the test handing it a
// value a real attacker would have to discover some other way.
//
// Exit codes:
//   0 = both Attach and PolicyMutate were correctly rejected (Resp::Err)
//   2 = missing args[1] (pipe name)
//   3 = connect to the broker pipe failed
//   4 = Attach was NOT rejected — security failure
//   5 = PolicyMutate was NOT rejected — security failure

fn main() -> std::process::ExitCode {
    let pipe_name = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: escape_broker_attach_from_guest <pipe_name>");
            return std::process::ExitCode::from(2);
        }
    };

    let mut attach_client = match ipc::SyncClient::connect(&pipe_name) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("connect (attach) failed: {e}");
            return std::process::ExitCode::from(3);
        }
    };
    match attach_client.send(&ipc::Req::Attach { launcher_pid: std::process::id(), launcher_create_time: 0 }) {
        Ok(ipc::Resp::Err(msg)) => println!("attach: rejected as expected: {msg}"),
        other => {
            eprintln!("attach: NOT rejected — security failure: {other:?}");
            return std::process::ExitCode::from(4);
        }
    }
    drop(attach_client);

    let mut mutate_client = match ipc::SyncClient::connect(&pipe_name) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("connect (policy mutate) failed: {e}");
            return std::process::ExitCode::from(3);
        }
    };
    let op = policy::db::PolicyOp::RuleList;
    match mutate_client.send(&ipc::Req::PolicyMutate { op }) {
        Ok(ipc::Resp::Err(msg)) => println!("policy_mutate: rejected as expected: {msg}"),
        other => {
            eprintln!("policy_mutate: NOT rejected — security failure: {other:?}");
            return std::process::ExitCode::from(5);
        }
    }

    println!("escape_broker_attach_from_guest ok");
    std::process::ExitCode::from(0)
}

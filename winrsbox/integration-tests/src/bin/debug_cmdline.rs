// debug_cmdline — prints GetCommandLineW for diagnostic purposes

fn main() {
    unsafe {
        let cmd = winapi::um::processenv::GetCommandLineW();
        if !cmd.is_null() {
            let mut len = 0;
            let mut p = cmd;
            while *p != 0 { len += 1; p = p.add(1); }
            let slice = std::slice::from_raw_parts(cmd, len);
            let s = String::from_utf16_lossy(slice);
            println!("CMDLINE={s}");
        } else {
            println!("CMDLINE=<null>");
        }
    }
}

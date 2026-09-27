use ntapi::ntioapi::{NtCreateFile, IO_STATUS_BLOCK};
use ntapi::ntobapi::{NtQueryObject, ObjectNameInformation};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use winapi::shared::ntdef::{HANDLE, OBJECT_ATTRIBUTES, UNICODE_STRING};

fn create_native(root: HANDLE, mut name: Vec<u16>, label: &str) {
    let mut unicode = UNICODE_STRING {
        Length: u16::try_from(name.len() * 2).unwrap(),
        MaximumLength: u16::try_from(name.len() * 2).unwrap(),
        Buffer: name.as_mut_ptr(),
    };
    let mut attrs = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root,
        ObjectName: &mut unicode,
        Attributes: 0x40,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };
    // SAFETY: IO_STATUS_BLOCK is a POD output record.
    let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let mut handle: HANDLE = std::ptr::null_mut();
    // SAFETY: attributes and UTF-16 storage outlive the call; root is null or a live directory.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            0x40000000 | 0x100000,
            &mut attrs,
            &mut iosb,
            std::ptr::null_mut(),
            0x80,
            7,
            5,
            0x60,
            std::ptr::null_mut(),
            0,
        )
    };
    println!("{label}: status={status:#x}");
    assert!(
        status >= 0 && !handle.is_null(),
        "{label}: NtCreateFile failed"
    );
    // SAFETY: successful NtCreateFile transferred ownership of this writable handle.
    let mut file = unsafe { File::from_raw_handle(handle as *mut _) };
    file.write_all(b"sandbox-relative-io").unwrap();
}

fn main() {
    report_token_owner();
    let cwd = std::env::current_dir().unwrap();
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(0x02000000)
        .open(&cwd)
        .unwrap();
    let mut info = vec![0usize; 8192];
    let mut returned = 0;
    // SAFETY: aligned initialized output storage, live directory handle, writable returned length.
    let status = unsafe {
        NtQueryObject(
            root.as_raw_handle() as *mut _,
            ObjectNameInformation,
            info.as_mut_ptr() as *mut _,
            (info.len() * std::mem::size_of::<usize>()) as u32,
            &mut returned,
        )
    };
    // SAFETY: initialized usize storage is aligned and large enough for UNICODE_STRING.
    let name_len = unsafe { (*(info.as_ptr() as *const UNICODE_STRING)).Length };
    println!("root query: status={status:#x} returned={returned} name_length={name_len}");
    let mut final_name = vec![0u16; 32768];
    // SAFETY: root is live and final_name is a writable buffer; 2 requests the NT volume name.
    let len = unsafe {
        winapi::um::fileapi::GetFinalPathNameByHandleW(
            root.as_raw_handle() as *mut _,
            final_name.as_mut_ptr(),
            final_name.len() as u32,
            2,
        )
    } as usize;
    println!(
        "root final: {}",
        String::from_utf16_lossy(&final_name[..len.min(final_name.len())])
    );
    let mut absolute: Vec<u16> = r"\??\".encode_utf16().collect();
    absolute.extend(cwd.join("probe_absolute.exe").as_os_str().encode_wide());
    create_native(std::ptr::null_mut(), absolute, "absolute create");
    create_native(
        root.as_raw_handle() as *mut _,
        "probe_root.exe".encode_utf16().collect(),
        "relative root create",
    );
    std::fs::write("hello.exe", b"sandbox-relative-io").expect("Win32 relative create");
    std::fs::write("hello.exe", b"sandbox-relative-io-overwrite")
        .expect("Win32 relative overwrite");
    println!("sandbox-relative-io-ok");
}

fn report_token_owner() {
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
    use winapi::um::securitybaseapi::{EqualSid, GetTokenInformation};
    use winapi::um::winnt::{TokenOwner, TokenUser, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER};
    let mut token = std::ptr::null_mut();
    // SAFETY: current-process pseudo handle is valid; token is writable.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        println!("token owner: query unavailable");
        return;
    }
    // SAFETY: OpenProcessToken transferred ownership of this live handle.
    let token = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(token as *mut _) };
    let mut user = vec![0usize; 64];
    let mut owner = vec![0usize; 64];
    let mut returned = 0;
    // SAFETY: aligned initialized buffers, live TOKEN_QUERY handle and writable length.
    unsafe {
        let handle = token.as_raw_handle() as *mut _;
        if GetTokenInformation(
            handle,
            TokenUser,
            user.as_mut_ptr() as *mut _,
            512,
            &mut returned,
        ) == 0
            || GetTokenInformation(
                handle,
                TokenOwner,
                owner.as_mut_ptr() as *mut _,
                512,
                &mut returned,
            ) == 0
        {
            println!("token owner: information unavailable");
            return;
        }
        let user_sid = (*(user.as_ptr() as *const TOKEN_USER)).User.Sid;
        let owner_sid = (*(owner.as_ptr() as *const TOKEN_OWNER)).Owner;
        if user_sid.is_null() || owner_sid.is_null() {
            println!("token owner: empty SID");
            return;
        }
        println!(
            "token owner matches user: {}",
            EqualSid(user_sid, owner_sid) != 0
        );
    }
}

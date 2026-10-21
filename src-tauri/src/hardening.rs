//! Process hardening at startup (Windows), the same measures KeePassXC and browsers use.
//! Nothing here touches system settings or the registry; every step only affects this process.
//! - DLLs only from the app folder and System32 (no current directory / PATH → no DLL planting)
//! - process DACL: other programs of the same user may not read our memory or inject code
//!   (only "query basic info", "wait for exit" and "terminate" stay allowed)
//! - crash reports without heap memory, no crash dialog
//!
//! Escape hatch for troubleshooting: environment variable AKP_NO_HARDENING=1.

#[cfg(windows)]
pub fn apply() {
    if std::env::var_os("AKP_NO_HARDENING").is_some() {
        return;
    }
    dll_search_order();
    if let Err(e) = restrict_process_access() {
        log::warn!("process hardening: {e}");
    }
    crash_reports_without_memory();
}

#[cfg(not(windows))]
pub fn apply() {}

#[cfg(windows)]
fn dll_search_order() {
    use windows_sys::Win32::System::LibraryLoader::{SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS};
    unsafe {
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    }
}

/// Security descriptor from SDDL; caller frees with LocalFree.
#[cfg(windows)]
pub fn security_descriptor(sddl: &str) -> Result<windows_sys::Win32::Security::PSECURITY_DESCRIPTOR, String> {
    use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
    let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut sd = std::ptr::null_mut();
    let ok = unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(wide.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) };
    if ok == 0 { Err("sddl".into()) } else { Ok(sd) }
}

#[cfg(windows)]
fn restrict_process_access() -> Result<(), String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{SetSecurityInfo, SE_KERNEL_OBJECT};
    use windows_sys::Win32::Security::{GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    // our user: SYNCHRONIZE | PROCESS_QUERY_(LIMITED_)INFORMATION | PROCESS_TERMINATE (taskkill needs both); SYSTEM: everything.
    // The user's SID, not OW: the process owner can be the Administrators group, and then
    // nobody could end the process (Task Manager, taskkill).
    let mut user = user_sid_of(unsafe { GetCurrentProcess() }).ok_or("token")?;
    let sid = unsafe {
        let mut p = std::ptr::null_mut();
        if ConvertSidToStringSidW(user.as_mut_ptr() as _, &mut p) == 0 {
            return Err("sid".into());
        }
        let n = (0..).take_while(|&i| *p.add(i) != 0).count();
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, n));
        LocalFree(p as _);
        s
    };
    let sd = security_descriptor(&format!("D:P(A;;0x101401;;;{sid})(A;;GA;;;SY)"))?;
    let (mut present, mut defaulted, mut dacl) = (0, 0, std::ptr::null_mut());
    let result = unsafe {
        if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) == 0 {
            Err("dacl".to_string())
        } else {
            let r = SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(), std::ptr::null_mut(), dacl, std::ptr::null());
            if r == 0 { Ok(()) } else { Err(format!("SetSecurityInfo {r}")) }
        }
    };
    unsafe { LocalFree(sd as _) };
    result
}

#[cfg(windows)]
fn crash_reports_without_memory() {
    use windows_sys::Win32::System::Diagnostics::Debug::{SetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX};
    use windows_sys::Win32::System::ErrorReporting::{WerSetFlags, WER_FAULT_REPORTING_FLAG_NOHEAP};
    unsafe {
        WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP);
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    }
}

/// SID of the user this process runs as (copied out of the token).
#[cfg(windows)]
fn user_sid_of(process: windows_sys::Win32::Foundation::HANDLE) -> Option<Vec<u8>> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{GetLengthSid, GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::OpenProcessToken;
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
            return None;
        }
        let mut buf = vec![0u8; 256];
        let mut len = 0u32;
        let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr() as _, buf.len() as u32, &mut len);
        CloseHandle(token);
        if ok == 0 {
            return None;
        }
        let sid = (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid;
        Some(std::slice::from_raw_parts(sid as *const u8, GetLengthSid(sid) as usize).to_vec())
    }
}

/// The process serving a named pipe runs as the current user (our own browser server).
#[cfg(windows)]
pub fn pipe_server_is_me(pipe: windows_sys::Win32::Foundation::HANDLE) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    unsafe {
        let mut pid = 0u32;
        if GetNamedPipeServerProcessId(pipe, &mut pid) == 0 {
            return false;
        }
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return false;
        }
        let theirs = user_sid_of(h);
        CloseHandle(h);
        theirs.is_some() && theirs == user_sid_of(GetCurrentProcess())
    }
}

/// Owner of a pipe (needs READ_CONTROL on the handle) is SYSTEM, Administrators or the
/// current user: a pipe another user squatted is refused.
#[cfg(windows)]
pub fn pipe_owner_trusted(pipe: windows_sys::Win32::Foundation::HANDLE) -> bool {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows_sys::Win32::Security::{IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid, OWNER_SECURITY_INFORMATION};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    unsafe {
        let (mut owner, mut sd) = (std::ptr::null_mut(), std::ptr::null_mut());
        if GetSecurityInfo(pipe, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, &mut owner, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), &mut sd) != 0 {
            return false;
        }
        let me = user_sid_of(GetCurrentProcess());
        let len = windows_sys::Win32::Security::GetLengthSid(owner) as usize;
        let owner_bytes = std::slice::from_raw_parts(owner as *const u8, len).to_vec();
        let ok = IsWellKnownSid(owner, WinLocalSystemSid) != 0 || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0 || me.as_deref() == Some(&owner_bytes[..]);
        LocalFree(sd as _);
        ok
    }
}

/// Encrypt for the current Windows user (DPAPI). Prefixed so plain old files still load.
#[cfg(windows)]
pub fn protect(data: &[u8]) -> Option<Vec<u8>> {
    use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB};
    let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    unsafe {
        if CryptProtectData(&input, std::ptr::null(), std::ptr::null(), std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out) == 0 {
            return None;
        }
        let mut v = b"DPAPI1".to_vec();
        v.extend_from_slice(std::slice::from_raw_parts(out.pbData, out.cbData as usize));
        windows_sys::Win32::Foundation::LocalFree(out.pbData as _);
        Some(v)
    }
}

#[cfg(windows)]
pub fn unprotect(data: &[u8]) -> Option<Vec<u8>> {
    use windows_sys::Win32::Security::Cryptography::{CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB};
    let body = data.strip_prefix(b"DPAPI1")?;
    let input = CRYPT_INTEGER_BLOB { cbData: body.len() as u32, pbData: body.as_ptr() as *mut u8 };
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    unsafe {
        if CryptUnprotectData(&input, std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out) == 0 {
            return None;
        }
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        windows_sys::Win32::Foundation::LocalFree(out.pbData as _);
        Some(v)
    }
}

#[cfg(not(windows))]
pub fn protect(_data: &[u8]) -> Option<Vec<u8>> { None }
#[cfg(not(windows))]
pub fn unprotect(_data: &[u8]) -> Option<Vec<u8>> { None }

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn dpapi_roundtrip() {
        let enc = super::protect(b"remember-token").unwrap();
        assert!(enc.starts_with(b"DPAPI1") && !enc.windows(8).any(|w| w == b"remember"));
        assert_eq!(super::unprotect(&enc).unwrap(), b"remember-token");
        assert!(super::unprotect(b"{\"plain\":1}").is_none());
    }

    #[test]
    fn sddl_parses() {
        let sd = super::security_descriptor("D:P(A;;0x101001;;;OW)(A;;GA;;;SY)").unwrap();
        assert!(!sd.is_null());
        unsafe { windows_sys::Win32::Foundation::LocalFree(sd as _) };
    }

    /// own process, opened by pid like another program would: memory read denied, terminate allowed
    /// (ignored: it locks down the whole test process; run with --ignored --test-threads=1)
    #[test]
    #[ignore]
    fn process_memory_is_closed() {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, PROCESS_VM_READ};
        super::restrict_process_access().unwrap();
        let pid = std::process::id();
        unsafe {
            let read = OpenProcess(PROCESS_VM_READ, 0, pid);
            assert!(read.is_null(), "memory read must be denied");
            let term = OpenProcess(PROCESS_TERMINATE, 0, pid);
            assert!(!term.is_null(), "terminate stays allowed (Task Manager)");
            CloseHandle(term);
        }
    }
}

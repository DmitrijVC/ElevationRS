#![cfg(windows)]

// ToDo [Reminder] remove from the release
// #![allow(warnings)]

mod process_handler;
// use process_handler::ProcessHandler;

use std::mem;
use std::ptr::null_mut;

use libc;
use winapi::um::securitybaseapi::{CheckTokenMembership, AllocateAndInitializeSid, FreeSid};
use winapi::um::winnt::{SECURITY_NT_AUTHORITY, SID_IDENTIFIER_AUTHORITY, PSID, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, PROCESS_ALL_ACCESS};
use winapi::um::winnt::HANDLE;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::{FALSE, TRUE, DWORD};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;


#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ErrorType {
    None,
    Unknown,

    NotRenewed,
    OpenProcessFailed,
}

#[derive(Debug)]
pub struct Error {
    code: DWORD,
    pub message: &'static str,
    pub tip: &'static str,
    etype: ErrorType,
}

impl Error {
    fn new(code: DWORD, message: &'static str, tip: &'static str, etype: ErrorType) -> Self {
        Self {
            code,
            message,
            tip,
            etype,
        }
    }

    pub fn get_code(&self) -> Option<DWORD> {
        if self.code == 0 {
            return None
        }

        Some(self.code)
    }

    pub fn get_type(&self) -> Option<ErrorType> {
        if &self.etype == &ErrorType::None {
            return None
        }

        Some(self.etype)
    }

    pub unsafe fn last_sys_error() -> u32 {
        GetLastError()
    }
}


/// `sid_result: i32` - return value of the AllocateAndInitializeSid() function <br>
/// `admins_group: PSID` - security identifier of admins group <br>
/// `mem: *mut c_void` - <br>
/// `cleaned: bool` - true/false to note if the Elevation::cleanup() method has been executed <br>
pub struct Elevation {
    sid_result: i32,
    admins_group: PSID,

    mem: *mut c_void,
    cleaned: bool,
}

impl Elevation {
    /// Returns an Elevation structure instance
    pub unsafe fn new() -> Self {
        let (sid_result, admins_group, mem) = Elevation::alloc();

        Self {
            sid_result,
            admins_group,
            mem,
            cleaned: false,
        }
    }

    /// Similar to Elevation::new() but overwrites the old instance with new attributes
    pub unsafe fn renew(&mut self) {
        let alloc = Elevation::alloc();

        self.sid_result = alloc.0;
        self.admins_group = alloc.1;
        self.mem = alloc.2;
        self.cleaned = false;
    }

    /// Cleans up the allocated memory
    pub unsafe fn cleanup(&mut self) {
        FreeSid(self.admins_group);
        self.mem.drop_in_place();
        self.cleaned = true;
    }

    /// Allocates what is necessary <br>
    /// Used in Elevation::new() and Elevation::renew() <br>
    /// It has been detached from Elevation::is_elevated() to prevent from crashes and unnecessary operations <br>
    unsafe fn alloc() -> (i32, PSID, *mut c_void) {
        let mut authority: SID_IDENTIFIER_AUTHORITY = Default::default();
        authority.Value = SECURITY_NT_AUTHORITY;

        let mem = libc::malloc(mem::size_of::<PSID>()) as *mut c_void;
        let mut admins_group: PSID = *(mem as *mut PSID);

        let sid_result = AllocateAndInitializeSid(
            &mut authority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &mut admins_group
        );

        (sid_result, admins_group, mem)
    }

    /// Checks if certain process is elevated or not
    /// If `pid` is equal to `None`, is_elevated uses the impersonation token of the calling thread.
    /// If the thread is not impersonating, the function duplicates the thread's primary token to create an impersonation token.
    ///
    /// ## Example
    /// ```rust
    /// let mut el = Elevation::new();
    /// match el.is_elevated(None) {
    ///     Ok(result) => println!("Elevated: {}", result),
    ///     Err(error) => println!("Error: {:#?}", error),
    /// }
    /// el.cleanup();
    /// ```
    pub unsafe fn is_elevated(&mut self, pid: Option<u32>) -> Result<bool, Error> {
        if self.cleaned {
            return Err(
                Error::new(
                    0,
                    "Checking elevation after cleanup!",
                    "Create new Elevation object or use renew() method after cleanup.",
                    ErrorType::NotRenewed,
                )
            )
        }

        // ToDo fix checking elevation for other processes
        let mut handle: HANDLE = null_mut();
        if pid.is_some() {
            handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid.unwrap());

            if handle == null_mut() {
                return Err(
                    Error::new(
                        GetLastError(),
                        "OpenProcess has failed!",
                        "Check the error code for more details.",
                        ErrorType::OpenProcessFailed,
                    )
                )
            }
        }

        if self.sid_result == TRUE {
            if CheckTokenMembership(handle, self.admins_group, &mut self.sid_result) == FALSE {
                self.sid_result = FALSE
            }
        }

        if handle != null_mut() {
            CloseHandle(handle);
        }

        return if self.sid_result == TRUE {
            Ok(true)
        } else {
            Ok(false)
        }

    }

    /// Checks if the allocated memory has been cleaned
    pub fn is_cleaned(&self) -> bool {
        self.cleaned
    }

}

#[cfg(test)]
mod tests {

    use crate::Elevation;

    #[test]
    fn self_elevation_check() { unsafe {
        let mut el = Elevation::new();

        // If it's elevated, both functions should return true
        let ch_1 = el.is_elevated(None);
        let ch_2 = el.is_elevated(Some( std::process::id() ));

        el.cleanup();

        println!("Check0: {:?}", &ch_1);
        println!("Check1: {:?}", &ch_2);

        assert_eq!(
            ch_1.expect("ch_1 failed!"),
            ch_2.expect("ch_2 failed!")
        )
    } }
}

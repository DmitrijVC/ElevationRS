// Yet unused
#![allow(dead_code)]

use std::process;
use sysinfo::{
    System,
    SystemExt,
    ProcessExt,
    Signal
};


pub struct ProcessHandler;

impl ProcessHandler {
    pub fn kill_self() {
        let pid_self = process::id() as usize;
        let mut sys = System::new();
        sys.refresh_processes();

        if let Some(v) = sys.get_process(pid_self) {
            v.kill(Signal::Term);
        };
    }
}

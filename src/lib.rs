mod proc_service;
mod thread_db;

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

pub use thread_db::{TdErr, TdTaStats, TdThrInfo};
use thread_db::{TdThrAgent, TdThrHandle, TdThrState};
use proc_service::ProcHandle;

use dlopen::wrapper::Container;

/// Runs a libthread_db function, returning on error.
macro_rules! td_try {
    ($e: expr) => {
        match $e {
            TdErr::Ok => (),
            err => return Err(err),
        }
    }
}

pub struct Library {
    api: Container<thread_db::ThreadDb>,
}

impl Library {
    pub fn new() -> Library {
        Library {
            api: thread_db::open_lib(),
        }
    }

    pub fn attach(&self, pid: i32) -> Result<Process, TdErr> {
        let symbols = match get_symbols(pid) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("get_symbols: {:?}", e);
                return Err(TdErr::Err);
            }
        };
        let mut handle = match ProcHandle::new(pid) {
            Ok(h) => Box::new(h),
            Err(e) => {
                eprintln!("could not attach to process: {:?}", e);
                return Err(TdErr::Err);
            }
        };
        handle.symbols = symbols;
        let mut ta: *mut TdThrAgent = std::ptr::null_mut();
        unsafe {
            // Initialize libthread_db.
            td_try!(self.api.td_ta_new(handle.as_mut(), &mut ta));
        }
        Ok(Process { lib: &self, handle, ta })
    }
}

/// Returns a map of mapped symbols in the process with the given pid.
fn get_symbols(pid: i32) -> Result<HashMap<String, usize>, Box<std::error::Error>> {
    // Result map.
    let mut symbols = HashMap::new();

    // The mappings for libpthread look like this:
    //
    // 7ffff7f78000-7ffff7f7e000 r--p 00000000 fd:01 10893944 /usr/lib64/libpthread-2.28.so
    // 7ffff7f7e000-7ffff7f8e000 r-xp 00006000 fd:01 10893944 /usr/lib64/libpthread-2.28.so
    // 7ffff7f8e000-7ffff7f94000 r--p 00016000 fd:01 10893944 /usr/lib64/libpthread-2.28.so
    // 7ffff7f94000-7ffff7f95000 r--p 0001b000 fd:01 10893944 /usr/lib64/libpthread-2.28.so
    // 7ffff7f95000-7ffff7f96000 rw-p 0001c000 fd:01 10893944 /usr/lib64/libpthread-2.28.so
    // 7ffff7f96000-7ffff7f9a000 rw-p 00000000 00:00 0
    //
    // Some symbols (like __nptl_nthreads at 0x1d2e0 in the ELF file) end up in the last anonymous
    // mapping region, even if they're in the .data section (in the example, __nptl_nthreads ends
    // up at 0x77ffff7f952e0). To account for these symbols, the following code doesn't try to
    // understand any mappings other than the first (with offset 0).
    //
    // See also this Stackoverflow question: https://stackoverflow.com/questions/25274569/
    for map in proc_maps::get_process_maps(pid)? {
        // We're only interested in the first entry for each library.
        if map.offset > 0 || map.filename().is_none() {
            continue;
        }
        let filename = map.filename().as_ref().unwrap();
        // We can only read files, skip mappings to [stack] etc.
        if !filename.starts_with("/") {
            continue;
        }

        for (symbol, offset) in get_symbols_for_library(&filename)? {
            symbols.insert(symbol.to_string(), offset + map.start());
        }
    }
    Ok(symbols)
}

/// Returns a map with all symbols defined in the given library.
fn get_symbols_for_library(filename: &str) -> Result<HashMap<String, usize>, Box<std::error::Error>> {
    let mut symbols = HashMap::new();
    eprintln!("reading library {}", filename);

    let mut f = match File::open(filename) {
        Ok(f) => f,
        // 
        Err(e) => {
            use std::error::Error;
            eprintln!("get_symbols_for_library: couldn't read {}: {}", filename, e.description());
            return Ok(symbols);
        }
    };
    let mut buf: Vec<u8> = Vec::new();
    f.read_to_end(&mut buf)?;

    let binary = goblin::elf::Elf::parse(&buf)?;
    for sym in binary.syms.iter() {
        if let Some(name) = binary.strtab.get_unsafe(sym.st_name) {
            // Only keep symbols that start with a letter to keep the symbol hashmap small.
            let first_char = name.chars().next().unwrap_or('\0');
            if first_char.is_alphabetic() || first_char == '_' {
                symbols.insert(name.to_string(), sym.st_value as usize);
            }
        }
    }
    Ok(symbols)
}

pub struct Process<'a> {
    lib: &'a Library,
    // handle needs to be boxed so that the pointer that libthread_db keeps stays valid even if
    // Process is moved on the Rust side.
    handle: Box<ProcHandle>,
    ta: *mut TdThrAgent,
}

impl Process<'_> {
    /// Get number of currently running threads in process associated with TA.
    pub fn get_nthreads(&self) -> Result<i32, TdErr> {
        let mut result: i32 = 42;
        unsafe {
            td_try!(self.lib.api.td_ta_get_nthreads(self.ta, &mut result));
        }
        Ok(result)
    }

    /// Enable collecting statistics for process associated with TA.
    /// *Note*: Not implemented in glibc.
    pub fn enable_stats(&mut self, enable: bool) -> Result<(), TdErr> {
        unsafe {
            td_try!(self.lib.api.td_ta_enable_stats(self.ta, enable as i32));
        }
        Ok(())
    }

    /// Reset statistics.
    /// *Note*: Not implemented in glibc.
    pub fn reset_stats(&mut self) -> Result<(), TdErr> {
        unsafe {
            td_try!(self.lib.api.td_ta_reset_stats(self.ta));
        }
        Ok(())
    }

    /// Retrieve statistics from process associated with TA.
    /// *Note*: Not implemented in glibc.
    pub fn get_stats(&self) -> Result<TdTaStats, TdErr> {
        let mut result: TdTaStats = Default::default();
        unsafe {
            td_try!(self.lib.api.td_ta_get_stats(self.ta, &mut result));
        }
        Ok(result)
    }

    /// Get all threads.
    pub fn threads(&self) -> Result<Vec<Thread>, TdErr> {
        // The td_ta_thr_iter function will call the callback function for each thread. Save the
        // results in a Vec so that we can iterate over it.
        let mut handles: Vec<TdThrHandle> = Vec::new();
        unsafe {
            let sigmask = nix::sys::signal::SigSet::empty();
            let mut c_sigmask = sigmask.as_ref().clone();
            td_try!(self.lib.api.td_ta_thr_iter(self.ta, thr_iter_callback, &mut handles as *mut _ as *mut libc::c_void, TdThrState::AnyState, 0, &mut c_sigmask, 0));
        }
        Ok(handles.iter().map(|handle| Thread { lib: self.lib, handle: *handle }).collect())
    }

}

/// Appends the thread handle to the Vec<Process> in cbdata.
unsafe extern "C" fn thr_iter_callback(handle: *const TdThrHandle, cbdata: *mut libc::c_void) -> i32 {
    let threads = cbdata as *mut Vec<TdThrHandle>;
    (*threads).push(*handle);
    0
}

impl Drop for Process<'_> {
    fn drop(&mut self) {
        unsafe {
            match self.lib.api.td_ta_delete(self.ta) {
                TdErr::Ok => (),
                err => panic!("Deleting Process with pid {} failed: {:?}", self.handle.pid, err),
            }
        }
    }
}

pub struct Thread<'a> {
    lib: &'a Library,
    handle: TdThrHandle,
}

impl Thread<'_> {
    /// Validate that this is a thread handle.
    pub fn validate(&self) -> Result<(), TdErr> {
        unsafe {
            td_try!(self.lib.api.td_thr_validate(&self.handle));
        }
        Ok(())
    }

    /// Return information about the thread.
    pub fn info(&self) -> Result<TdThrInfo, TdErr> {
        unsafe {
            let mut info: TdThrInfo = std::mem::zeroed();
            td_try!(self.lib.api.td_thr_get_info(&self.handle, &mut info));
            Ok(info)
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::io::{BufRead, BufReader};

    /// Read symbols from the test process and compare to the symbols gdb reads.
    #[test]
    fn test_get_symbols() {
        use nix::unistd::{fork, ForkResult};

        // We need to fork because gdb will stop the process while reading the symbols, preventing
        // us from capturing its output.
        match fork().unwrap() {
            ForkResult::Child => {
                std::thread::sleep(std::time::Duration::from_millis(2000));
                std::process::exit(0);
            },
            ForkResult::Parent { child, .. } => {
                let pid = child.as_raw();
                let symbols = get_symbols(pid as i32).expect("could not get symbols");
                let gdb_symbols = get_symbols_gdb(pid as i32).expect("could not get gdb symbols");
                println!("#symbols = {}, #gdb_symbols = {}", symbols.len(), gdb_symbols.len());
                let mut checked_symbols = 0;
                for (symbol, offset) in gdb_symbols {
                    if symbol.contains("nptl") || symbol.contains("_thread_db") {
                        assert_eq!(symbols[&symbol], offset, "symbol {} does not match: {:x} != {:x}", symbol, symbols[&symbol], offset);
                        checked_symbols += 1;
                    }
                }
                dbg!(checked_symbols);
            }
        }
    }

    fn get_symbols_gdb(pid: i32) -> Result<HashMap<String, usize>, Box<std::error::Error>> {
        let mut result = HashMap::new();
        eprintln!("starting gdb");
        let child = Command::new("gdb")
            .arg(format!("--pid={}", pid))
            .arg("--batch")
            .arg("-ex").arg("info variables")
            .stdout(Stdio::piped())
            .spawn()?;

        let reader = BufReader::new(child.stdout.unwrap());

        for line in reader.lines().filter_map(|line| line.ok()) {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            // Filter unrelated gdb output by searching for lines with a number and some other
            // word.
            if tokens.len() == 2 && tokens[0].starts_with("0x") {
                result.insert(tokens[1].to_string(), usize::from_str_radix(&tokens[0][2..], 16)?);
            }
        }
        Ok(result)
    }
}

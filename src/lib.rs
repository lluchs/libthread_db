mod proc_service;
mod thread_db;

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

pub use thread_db::TdErr;
use thread_db::TdThrAgent;
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
            Ok(h) => h,
            Err(e) => {
                eprintln!("could not attach to process: {:?}", e);
                return Err(TdErr::Err);
            }
        };
        handle.symbols = symbols;
        let mut ta: *mut TdThrAgent = std::ptr::null_mut();
        unsafe {
            // Initialize libthread_db.
            td_try!(self.api.td_ta_new(&mut handle, &mut ta));
        }
        Ok(Process { lib: &self, handle, ta })
    }
}

/// Returns a map of mapped symbols in the process with the given pid.
fn get_symbols(pid: i32) -> Result<HashMap<String, usize>, Box<std::error::Error>> {
    // Result map.
    let mut symbols = HashMap::new();
    // Cache to avoid opening libraries multiple times.
    let mut process_symbols: HashMap<String, HashMap<String, usize>> = HashMap::new();
    for map in proc_maps::get_process_maps(pid)? {
        if let Some(filename) = map.filename() {
            if filename.chars().next() == Some('/') {
                let syms = if process_symbols.contains_key(filename) {
                    &process_symbols[filename]
                } else {
                    &*process_symbols.entry(filename.to_string())
                        .or_insert(get_symbols_for_library(filename)?)
                };
                for (symbol, offset) in syms {
                    // Is the symbol in the current map range? A library usually has multiple
                    // ranges (code/data).
                    if *offset >= map.offset && *offset < map.offset + map.size() {
                        symbols.insert(symbol.to_string(), *offset - map.offset + map.start());
                    }
                }
            }
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
            if name.chars().next().unwrap_or('\0').is_alphabetic() {
                symbols.insert(name.to_string(), sym.st_value as usize);
            }
        }
    }
    Ok(symbols)
}

pub struct Process<'a> {
    lib: &'a Library,
    handle: ProcHandle,
    ta: *mut TdThrAgent,
}

impl Process<'_> {
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

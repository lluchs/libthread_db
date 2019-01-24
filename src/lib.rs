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
    // Cache to avoid opening libraries multiple times.
    let mut process_symbols: HashMap<String, HashMap<String, usize>> = HashMap::new();

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
    // up at 0x77ffff7f952e0). To account for these symbols, the following code treats anonymous
    // sections as extensions of the previous shared library.
    //
    // See also this Stackoverflow question: https://stackoverflow.com/questions/25274569/
    let mut last_map: Option<proc_maps::MapRange> = None;
    for map in proc_maps::get_process_maps(pid)? {
        let (filename, map_offset) = if let Some(filename) = map.filename() {
            if filename.chars().next() == Some('/') {
                last_map = Some(map.clone());
                (filename.clone(), map.offset)
            } else {
                continue
            }
        } else if let Some(ref last_map) = last_map {
            // The current mapping is anonymous. Consider it part of the previous library if it
            // continues without a gap.
            // TODO: This won't work if the library has multiple anonymous mappings.
            if last_map.start() + last_map.size() == map.start() {
                if let Some(filename) = last_map.filename() {
                    (filename.clone(), last_map.offset + last_map.size())
                } else {
                    continue
                }
            } else {
                continue
            }
        } else {
            continue
        };

        let syms = if process_symbols.contains_key(&filename) {
            &process_symbols[&filename]
        } else {
            &*process_symbols.entry(filename.clone())
                .or_insert(get_symbols_for_library(&filename)?)
        };
        for (symbol, offset) in syms {
            // Is the symbol in the current map range? A library usually has multiple
            // ranges (code/data).
            if *offset >= map_offset && *offset < map_offset + map.size() {
                symbols.insert(symbol.to_string(), *offset - map_offset + map.start());
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
    pub fn get_nthreads(&self) -> Result<i32, TdErr> {
        let mut result: i32 = 42;
        unsafe {
            td_try!(self.lib.api.td_ta_get_nthreads(self.ta, &mut result));
        }
        Ok(result)
    }
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

/// Callback interface for libthread_db.
///
/// See /usr/include/proc_service.h

use std::ffi::CStr;
use std::collections::HashMap;
use errno::{errno, set_errno, Errno};

pub type PsAddr = libc::c_void;

const TRACE_CALLS: bool = true;

macro_rules! ps_trace {
    ($($arg:tt)*) => (
        if TRACE_CALLS {
            eprintln!($($arg)*);
        }
    )
}

#[allow(dead_code)]
#[derive(Debug, PartialEq)]
#[repr(C)]
pub enum PsErr {
  /// Generic "call succeeded".
  Ok,
  /// Generic error.
  Err,
  /// Bad process handle.
  BadPID,
  /// Bad LWP identifier.
  BadLID,
  /// Bad address.
  BadAddr,
  /// Could not find given symbol.
  NoSym,
  /// FPU register set not available for given LWP.
  NoFRegs,
}

pub struct ProcHandle {
    pub pid: i32,
    pub symbols: HashMap<String, usize>,
}

impl ProcHandle {
    pub fn new(pid: i32) -> Result<ProcHandle, Box<dyn std::error::Error>> {
        let handle = ProcHandle { pid, symbols: HashMap::new() };
        unsafe {
            // Attach to the process with ptrace, but don't stop it. We need this later on to read
            // and write data from the process.
            match libc::ptrace(libc::PTRACE_SEIZE, pid, std::ptr::null() as *const libc::c_void, std::ptr::null() as *const libc::c_void) {
                -1 => return Err(Box::new(std::io::Error::from(errno::errno()))),
                _  => () // ok
            }
        }

        Ok(handle)
    }
}

impl Drop for ProcHandle {
    fn drop(&mut self) {
        unsafe {
            match libc::ptrace(libc::PTRACE_DETACH, self.pid, std::ptr::null() as *const libc::c_void, std::ptr::null() as *const libc::c_void) {
                -1 => eprintln!("Detaching process with pid {} failed: {:?}", self.pid, errno::errno()),
                _ => (),
            }
        }
    }
}

impl std::fmt::Debug for ProcHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "ProcHandle {{ pid: {}, symbols: [{} syms] }}", self.pid, self.symbols.len())
    }
}

/// Automatically resumes the ptrace-stopped process on drop.
struct Stopper {
    pid: i32,
}

impl Stopper {
    /// Stops the process.
    fn new(pid: i32) -> Result<Stopper, Box<dyn std::error::Error>> {
        unsafe {
            if libc::ptrace(libc::PTRACE_INTERRUPT, pid, std::ptr::null() as *const libc::c_void, std::ptr::null() as *const libc::c_void) == -1 {
                return Err(Box::new(std::io::Error::from(errno::errno())));
            }
        }
        match nix::sys::wait::waitpid(Some(nix::unistd::Pid::from_raw(pid)), Some(nix::sys::wait::WaitPidFlag::__WALL)) {
            Err(e) => return Err(Box::new(e)),
            Ok(_) => (), // TODO: Not all non-error states indicate a stopped process.
        }
        Ok(Stopper { pid })
    }
}

impl Drop for Stopper {
    fn drop(&mut self) {
        unsafe {
            libc::ptrace(libc::PTRACE_CONT, self.pid, std::ptr::null() as *const libc::c_void, std::ptr::null() as *const libc::c_void);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn ps_getpid(handle: *mut ProcHandle) -> i32 {
    ps_trace!("ps_getpid({:?})", *handle);
    (*handle).pid
}

/// Reads one word at addr from pid.
/// Assumes that the process is already stopped.
unsafe fn read_data(pid: libc::pid_t, addr: *mut PsAddr) -> Result<usize, PsErr> {
    set_errno(Errno(0));
    let result = libc::ptrace(libc::PTRACE_PEEKDATA, pid, addr, std::ptr::null_mut() as *mut libc::c_void);
    match (result, errno()) {
        (-1, Errno(0)) => Ok(result as usize),
        (-1, e) => {
            eprintln!("read_data({:?}, {:?}): {:?}", pid, addr, e);
            Err(PsErr::Err)
        },
        _ => Ok(result as usize),
    }
}

/// Writes one word at addr in process <pid>'s address space.
/// Assumes that the process is already stopped.
unsafe fn write_data(pid: libc::pid_t, addr: *mut PsAddr, data: libc::uintptr_t) -> Result<(), PsErr> {
    match libc::ptrace(libc::PTRACE_POKEDATA, pid, addr, data) {
        -1 => Err(PsErr::Err),
        _ => Ok(()),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ps_pdread(handle: *mut ProcHandle, ps_addr: *mut PsAddr, addr: *mut libc::c_void, size: usize) -> PsErr {
    ps_trace!("ps_pdread({:?}, {:?}, {:?}, {})", *handle, ps_addr, addr, size);
    let pid = (*handle).pid;
    let _stopper = Stopper::new(pid).expect("could not stop process");
    let mut source_ptr = ps_addr as *mut usize;
    let mut target_ptr = addr as *mut usize;
    let step = std::mem::size_of::<usize>();
    let mut size = size;
    loop {
        match read_data(pid, source_ptr as *mut PsAddr) {
            Err(e) => { return e; },
            Ok(data) => {
                if size > step {
                    *target_ptr = data;
                } else {
                    // Last partial read
                    std::ptr::copy_nonoverlapping(&data as *const _ as *const u8, target_ptr as *mut u8, size);
                    break;
                }
            },
        }
        target_ptr = target_ptr.add(1);
        source_ptr = source_ptr.add(1);
        size -= step;
    }
    PsErr::Ok
}

#[no_mangle]
pub unsafe extern "C" fn ps_pdwrite(handle: *mut ProcHandle, ps_addr: *mut PsAddr, addr: *const libc::c_void, size: usize) -> PsErr {
    ps_trace!("ps_pdwrite({:?}, {:?}, {:?}, {})", *handle, ps_addr, addr, size);
    let pid = (*handle).pid;
    let _stopper = Stopper::new(pid).expect("could not stop process");
    let mut target_ptr = ps_addr as *mut usize;
    let mut source_ptr = addr as *mut usize;
    let step = std::mem::size_of::<usize>();
    let mut size = size;
    loop {
        if size >= step {
            if let Err(e) = write_data(pid, target_ptr as *mut PsAddr, *source_ptr) {
                return e;
            }
            if size == step {
                break;
            }
        } else {
            // read-modify-write necessary to write the remaining bytes.
            match read_data(pid, target_ptr as *mut PsAddr) {
                Err(e) => { return e; }
                Ok(word) => {
                    let mut new_word = word;
                    std::ptr::copy_nonoverlapping(source_ptr as *const u8, &mut new_word as *mut _ as *mut u8, size);
                    if let Err(e) = write_data(pid, target_ptr as *mut PsAddr, new_word) {
                        return e;
                    }
                },
            }
            break;
        }
        target_ptr = target_ptr.add(1);
        source_ptr = source_ptr.add(1);
        size -= step;
    }
    PsErr::Ok
}

#[no_mangle]
pub unsafe extern "C" fn ps_lgetregs(handle: *mut ProcHandle, lwpid: libc::pid_t, registers: *mut libc::c_void) -> PsErr {
    ps_trace!("ps_lgetregs({:?}, {}, {:?})", *handle, lwpid, registers);
    match libc::ptrace(libc::PTRACE_GETREGS, lwpid, 0, registers) {
        -1 => PsErr::Err,
        _ => PsErr::Ok,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ps_lsetregs(handle: *mut ProcHandle, lwpid: libc::pid_t, registers: *mut libc::c_void) -> PsErr {
    ps_trace!("ps_lsetregs({:?}, {}, {:?})", *handle, lwpid, registers);
    match libc::ptrace(libc::PTRACE_SETREGS, lwpid, 0, registers) {
        -1 => PsErr::Err,
        _ => PsErr::Ok,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ps_lgetfpregs(handle: *mut ProcHandle, lwpid: libc::pid_t, registers: *mut libc::c_void) -> PsErr {
    ps_trace!("ps_lgetfpregs({:?}, {}, {:?})", *handle, lwpid, registers);
    match libc::ptrace(libc::PTRACE_GETFPREGS, lwpid, 0, registers) {
        -1 => PsErr::Err,
        _ => PsErr::Ok,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ps_lsetfpregs(handle: *mut ProcHandle, lwpid: libc::pid_t, registers: *mut libc::c_void) -> PsErr {
    ps_trace!("ps_lsetfpregs({:?}, {}, {:?})", *handle, lwpid, registers);
    match libc::ptrace(libc::PTRACE_SETFPREGS, lwpid, 0, registers) {
        -1 => PsErr::Err,
        _ => PsErr::Ok,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ps_pglobal_lookup(handle: *mut ProcHandle, object_name: *const libc::c_char, sym_name: *const libc::c_char, sym_addr: *mut *mut PsAddr) -> PsErr {
    let object_name = CStr::from_ptr(object_name).to_str().unwrap();
    let sym_name = CStr::from_ptr(sym_name).to_str().unwrap();
    ps_trace!("ps_pglobal_lookup({:?}, {:?}, {:?}, {:?})", *handle, object_name, sym_name, sym_addr);

    if (*handle).symbols.contains_key(sym_name) {
        *sym_addr = (*handle).symbols[sym_name] as *mut PsAddr;
        ps_trace!(" -> {} :: {} = {:?}", object_name, sym_name, *sym_addr);
        PsErr::Ok
    } else {
        PsErr::NoSym
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;
    use libc::c_void;

    #[test]
    fn ps_pdread_works() {
        let mut u64_value = 0x1122334455667788u64;
        let mut u32_value = 0x11223344;
        let mut string = "abcdefghijklmnopqrstuvwxyz123456879".to_string();

        match unsafe { libc::fork() } {
            -1 => panic!("fork failed: {:?}", errno::errno()),
            0 => { // child
                std::thread::sleep(std::time::Duration::from_millis(2000));
                println!("child exiting");
                std::process::exit(0);
            },
            pid => { // parent
                unsafe {
                    let mut handle = ProcHandle::new(pid)
                        .expect("creating ProcHandle failed");
                    let mut result: u64 = 0;
                    assert_eq!(
                        ps_pdread(&mut handle, &mut u64_value as *mut _ as *mut c_void, &mut result as *mut _ as *mut c_void, size_of::<u64>()),
                        PsErr::Ok);
                    assert_eq!(result, 0x1122334455667788u64);

                    result = 0;
                    assert_eq!(
                        ps_pdread(&mut handle, &mut u32_value as *mut _ as *mut c_void, &mut result as *mut _ as *mut c_void, size_of::<u32>()),
                        PsErr::Ok);
                    assert_eq!(result, 0x11223344);

                    let mut strresult = vec![0u8; string.len()];
                    assert_eq!(
                        ps_pdread(&mut handle, string.as_bytes_mut() as *mut _ as *mut c_void, strresult.as_mut_slice().as_mut_ptr() as *mut c_void, string.len()),
                        PsErr::Ok);
                    assert_eq!(String::from_utf8_lossy(&strresult), "abcdefghijklmnopqrstuvwxyz123456879");
                }
                // done, kill child after detaching
                unsafe { libc::kill(pid, libc::SIGTERM); }
            }
        }
    }

    #[test]
    fn ps_pdwrite_works() {
        let copy_str = "abcdefghijklmnopqrstuvwxyz123456879";
        let mut u64_result = 0;
        let mut u32_result = 0;
        let mut str_result = vec![0u8; copy_str.len()];
        let str_result_ptr = str_result.as_mut_slice().as_mut_ptr();

        let parent_pid = std::process::id();

        match unsafe { libc::fork() } {
            -1 => panic!("fork failed: {:?}", errno::errno()),
            0 => { // child
                eprintln!("child startup");
                let mut handle = ProcHandle::new(parent_pid as i32)
                    .expect("creating ProcHandle failed");

                unsafe {
                    let mut u64_value = 0x1122334455667788u64;
                    let mut u32_value = 0x11223344;
                    assert_eq!(
                        ps_pdwrite(&mut handle, &mut u64_result as *mut _ as *mut c_void, &mut u64_value as *mut _ as *mut c_void, size_of::<u64>()),          
                        PsErr::Ok);
                    assert_eq!(
                        ps_pdwrite(&mut handle, &mut u32_result as *mut _ as *mut c_void, &mut u32_value as *mut _ as *mut c_void, size_of::<u32>()),          
                        PsErr::Ok);
                    assert_eq!(
                        ps_pdwrite(&mut handle, str_result_ptr as *mut c_void, copy_str as *const _ as *const c_void, copy_str.len()),          
                        PsErr::Ok);
                }

                std::process::exit(0);
            },
            pid => { // parent
                // The child will modify our variables. Wait for it to exit.
                if let nix::sys::wait::WaitStatus::Exited(_pid, status) = nix::sys::wait::waitpid(Some(nix::unistd::Pid::from_raw(pid)), None).unwrap() {
                    assert_eq!(status, 0);
                } else {
                    panic!("child did not exit correctly");
                }
                assert_eq!(u64_result, 0x1122334455667788u64);
                assert_eq!(u32_result, 0x11223344);
                assert_eq!(String::from_utf8_lossy(&str_result), copy_str);
            }
        }
    }
}

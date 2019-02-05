/// Interface to libthread_db.so
///
/// See /usr/include/thread_db.h

use dlopen_derive::WrapperApi;
use dlopen::wrapper::{Container, WrapperApi};

use crate::proc_service::{ProcHandle, PsAddr};

#[derive(Debug)]
#[repr(C)]
pub enum TdErr {
    /// No error.
    Ok,
    /// No further specified error.
    Err,
    /// No matching thread found.
    NoThr,
    /// No matching synchronization handle found.
    NoSv,
    /// No matching light-weighted process found.
    NoLWP,
    /// Invalid process handle.
    BadPH,
    /// Invalid thread handle.
    BadTH,
    /// Invalid synchronization handle.
    BadSH,
    /// Invalid thread agent.
    BadTA,
    /// Invalid key.
    BadKEY,
    /// No event available.
    NoMsg,
    /// No floating-point register content available.
    NoFPRegs,
    /// Application not linked with thread library.
    NoLibthread,
    /// Requested event is not supported.
    NoEvent,
    /// Capability not available.
    NoCapab,
    /// Internal debug library error.
    DbErr,
    /// Operation is not applicable.
    NoAplic,
    /// No thread-specific data available.
    NoTSD,
    /// Out of memory.
    Malloc,
    /// Not entire register set was read or written.
    PartialReg,
    /// X register set not available for given thread.
    NoXregs,
    /// Thread has not yet allocated TLS for given module.
    TLSDefer,
    NoTalloc,
    /// Version if libpthread and libthread_db do not match.
    Version,
    /// There is no TLS segment in the given module.
    NoTLS,
}

/// Handle for a process. Opaque type.
pub type TdThrAgent = libc::c_void;

/// The actual thread handle type `td_thrhandle_t`. Opaque (but copyable) type.
#[derive(Copy, Clone)]
pub struct TdThrHandle {
    _th_ta_p: *mut TdThrAgent,
    _th_unique: *mut PsAddr,
}

/// Possible thread states.  AnyState is a pseudo-state used to
/// select threads regardless of state in td_ta_thr_iter().
#[allow(dead_code)]
#[derive(Debug)]
#[repr(C)]
pub enum TdThrState {
    AnyState,
    Unknown,
    Stopped,
    Run,
    Active,
    Zombie,
    Sleep,
    StoppedAsleep,
}

/// Thread type: user or system.  TD_THR_ANY_TYPE is a pseudo-type used
/// to select threads regardless of type in td_ta_thr_iter().
#[allow(dead_code)]
#[derive(Debug)]
#[repr(C)]
pub enum TdThrType {
  AnyType,
  User,
  System
}

///Bitmask of enabled events.
#[derive(Debug)]
#[repr(C)]
pub struct TdThrEvents {
    event_bits: [u32; 2],
}

/// Gathered statistics about the process.
#[derive(Default,Debug)]
#[repr(C)]
pub struct TdTaStats {
    /// Total number of threads in use.
    pub nthreads: i32,
    /// Concurrency level requested by user.
    pub r_concurrency: i32,
    /// Average runnable threads, numerator.
    pub nrunnable_num: i32,
    /// Average runnable threads, denominator.
    pub nrunnable_den: i32,
    /// Achieved concurrency level, numerator.
    pub a_concurrency_num: i32,
    /// Achieved concurrency level, denominator.
    pub a_concurrency_den: i32,
    /// Average number of processes in use, numerator.
    pub nlwps_num: i32,
    /// Average number of processes in use, denominator.
    pub nlwps_den: i32,
    /// Average number of idling processes, numerator.
    pub nidle_num: i32,
    /// Average number of idling processes, denominator.
    pub nidle_den: i32,
}

/// Information about the thread.
#[repr(C)]
pub struct TdThrInfo {
    /// Process handle.
    ti_ta_p: *mut TdThrAgent,
    /// Unused.
    ti_user_flags: libc::c_uint,
    /// Thread ID returned by pthread_create().
    pub ti_tid: libc::pthread_t,
    /// Pointer to thread-local data.
    pub ti_tls: *mut u8,
    /// Start function passed to pthread_create().
    pub ti_startfunc: *mut PsAddr,
    /// Base of thread's stack.
    pub ti_stkbase: *mut PsAddr,
    /// Size of thread's stack.
    pub ti_stksize: libc::c_long,
    /// Unused.
    ti_ro_area: *mut PsAddr,
    /// Unused.
    ti_ro_size: libc::c_int,
    /// Thread state.
    pub ti_state: TdThrState,
    /// Nonzero if suspended by debugger
    pub ti_db_suspended: libc::c_uchar,
    /// Type of the thread (system vs user thread).
    pub ti_type: TdThrType,
    /// Unused.
    ti_pc: libc::intptr_t,
    /// Unused.
    ti_sp: libc::intptr_t,
    /// Unused.
    ti_flags: libc::c_ushort,
    /// Thread priority.
    pub ti_pri: libc::c_int,
    /// Kernel PID for this thread.
    pub ti_lid: libc::pid_t,
    /// Signal mask.
    pub ti_sigmask: libc::sigset_t,
    /// Nonzero if event reporting enabled.
    pub ti_traceme: libc::c_uchar,
    /// Unused.
    ti_preemptflag: libc::c_uchar,
    /// Unused.
    ti_pirecflag: libc::c_uchar,
    /// Set of pending signals.
    pub ti_pending: libc::sigset_t,
    /// Set of enabled events.
    pub ti_events: TdThrEvents,
}

impl std::fmt::Debug for TdThrInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "TdThrInfo {{ ti_tid: {}, ti_type: {:?}, ti_pri: {}, ti_lid: {} }}",
               self.ti_tid, self.ti_type, self.ti_pri, self.ti_lid)
    }
}

#[derive(WrapperApi)]
pub struct ThreadDb {
    /// Initialize the thread debug support library.
    td_init: unsafe extern "C" fn() -> TdErr,
    /// Generate new thread debug library handle for process PS.
    td_ta_new: unsafe extern "C" fn(ps: *mut ProcHandle, ta: *mut *mut TdThrAgent) -> TdErr,
    /// Free resources allocated for TA.
    td_ta_delete: unsafe extern "C" fn(ta: *mut TdThrAgent) -> TdErr,

    /// Get number of currently running threads in process associated with TA.
    td_ta_get_nthreads: unsafe extern "C" fn(ta: *const TdThrAgent, np: *mut i32) -> TdErr,

    /// Enable collecting statistics for process associated with TA.
    td_ta_enable_stats: unsafe extern "C" fn(ta: *mut TdThrAgent, enable: i32) -> TdErr,
    /// Reset statistics.
    td_ta_reset_stats: unsafe extern "C" fn(ta: *mut TdThrAgent) -> TdErr,
    /// Retrieve statistics from process associated with TA.
    td_ta_get_stats: unsafe extern "C" fn(ta: *const TdThrAgent, stats: *mut TdTaStats) -> TdErr,

    /// Call for each thread in a process associated with TA the callback function CALLBACK.
    /// From looking at the glibc implementation:
    ///  - Return value of `callback`: 0 => ok, _ => error
    ///  - `state`: must be `TdThrState::AnyState`
    ///  - `ti_prio`: minimum priority (probably 0 for all)
    ///  - `ti_sigmask` and `ti_user_flags` are unused
    td_ta_thr_iter: unsafe extern "C" fn(ta: *mut TdThrAgent, callback: unsafe extern "C" fn(handle: *const TdThrHandle, cbdata: *mut libc::c_void) -> i32, cbdata: *mut libc::c_void, state: TdThrState, pri: i32, ti_sigmask: *mut libc::sigset_t, ti_user_flags: u32) -> TdErr,


    /// Validate that TH is a thread handle.
    td_thr_validate: unsafe extern "C" fn(handle: *const TdThrHandle) -> TdErr,

    /// Return information about thread TH.
    td_thr_get_info: unsafe extern "C" fn(handle: *const TdThrHandle, info: *mut TdThrInfo) -> TdErr,
}

pub fn open_lib() -> Container<ThreadDb> {
    dummy();
    eprintln!("open_lib");
    let container: Container<ThreadDb> = unsafe { Container::load("libthread_db.so") }.unwrap();
    let res = unsafe { container.td_init() };
    eprintln!("td_init -> {:?}", res);
    container
}

/// Dummy function to fool dead code elimination.
fn dummy() {
    unsafe { 
        use crate::proc_service::*;
        let mut handle = ProcHandle { pid: 0, symbols: std::collections::HashMap::new() };
        ps_getpid(&mut handle);
    }
}

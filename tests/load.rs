use libthread_db::{Library};

/// Tries to load the libthread_db library. This is already fairly complex because it requires
/// several functions to be defined.
#[test]
fn open_lib_works() {
    let _lib = Library::new();
}

/// Attaches to itself (via a forked child).
#[test]
fn self_attach_works() {
    use nix::unistd::{fork, ForkResult};

    let lib = Library::new();

    match fork().unwrap() {
        ForkResult::Child => {
            std::thread::sleep(std::time::Duration::from_millis(2000));
        },
        ForkResult::Parent { child, .. } => {
            let process = lib.attach(child.as_raw()).unwrap();
            // TODO: Looks like it always reports 0.
            assert_eq!(process.get_nthreads().unwrap(), 0);
        },
    }
}

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
            let thread = std::thread::spawn(|| std::thread::sleep(std::time::Duration::from_millis(2000)));
            thread.join().unwrap();
            std::process::exit(0);
        },
        ForkResult::Parent { child, .. } => {
            let mut process = lib.attach(child.as_raw()).unwrap();
            assert_eq!(process.get_nthreads().unwrap(), 2);

            // Note: These functions are not actually implemented in glibc.
            process.enable_stats(true).expect("enable_stats failed");
            let stats = process.get_stats().expect("get_stats failed");
            process.reset_stats().expect("reset_stats failed");

            let threads = process.threads().expect("getting threads failed");
            assert_eq!(threads.len(), 2);

            threads.iter().for_each(|t|t.validate().expect("thread is valid"));
            let info = threads[0].info().expect("getting thread info failed");
            println!("thread 0 info: {:?}", info);
        },
    }
}

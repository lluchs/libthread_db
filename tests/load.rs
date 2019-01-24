use libthread_db::{Library};

/// Tries to load the libthread_db library. This is already fairly complex because it requires
/// several functions to be defined.
#[test]
fn open_lib_works() {
    let _lib = Library::new();
}

#[test]
fn self_attach_works() {
    let lib = Library::new();
    let _process = lib.attach(std::process::id() as i32).unwrap();
    //println!("have {} threads", process.get_nthreads().unwrap());
}

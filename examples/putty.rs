// Set the windows subsystem to "windows" if the target OS is Windows and debug assertions are not enabled
#![cfg_attr(
    all(target_os = "windows", not(debug_assertions),),
    windows_subsystem = "windows"
)]

use rust_pe::reflective_loader_with_args;

// Main function
fn main() {
    // Read the file to load into a buffer
    #[cfg(target_arch = "x86_64")]
    let data = include_bytes!(r#"putty_x64.exe"#);
    #[cfg(target_arch = "x86")]
    let data = include_bytes!(r#"putty_x86.exe"#);

    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    unsafe {
        let _ = reflective_loader_with_args(data, &arg_refs);
    }
}

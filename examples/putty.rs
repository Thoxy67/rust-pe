// Set the windows subsystem to "windows" if the target OS is Windows and debug assertions are not enabled
#![cfg_attr(
    all(target_os = "windows", not(debug_assertions),),
    windows_subsystem = "windows"
)]

use rust_pe::{reflective_loader, utils::check_dotnet};

// Main function
fn main() {
    // Read the file to load into a buffer
    #[cfg(target_arch = "x86_64")]
    let data = include_bytes!(r#"putty_x64.exe"#);
    #[cfg(target_arch = "x86")]
    let data = include_bytes!(r#"putty_x86.exe"#);

    // Check if the file is a .NET assembly (no cloning needed — uses &[u8])
    if !check_dotnet(data) {
        // If it is not, use the reflective loader (no cloning needed — uses &[u8])
        unsafe {
            reflective_loader(data);
        };
    }
}

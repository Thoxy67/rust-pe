#![no_std]
#![no_main]

extern crate alloc;
pub mod dotnet;
pub mod pelib;
pub mod test;
pub mod utils;
pub mod windows;

use pelib::{
    change_memory_protection, fix_base_relocations, get_dos_header, get_entry_point_rva,
    get_headers_size, get_image_size, get_nt_header, process_tls_callbacks,
    register_exception_table, unregister_exception_table, write_delayed_import_table,
    write_import_table, write_sections,
};
use windows::{
    CloseHandle, CreateThread, VirtualAlloc, VirtualFree, WaitForSingleObject, INFINITE,
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};

use core::ffi::c_void;

/// Loads a Portable Executable (PE) file into memory using reflective loading.
///
/// Correctly parses both PE32 (32-bit) and PE32+ (64-bit) binaries at runtime,
/// but the PE bitness must match the host process architecture (a 64-bit loader
/// can only execute 64-bit PEs and vice versa).
///
/// This is the main entry point. It:
/// 1. Checks for .NET assemblies (unsupported)
/// 2. Validates PE architecture matches the host process
/// 3. Allocates memory with `MEM_COMMIT | MEM_RESERVE` and `PAGE_READWRITE`
/// 4. Copies headers and sections
/// 5. Resolves imports (including ordinal imports, with correct thunk sizes)
/// 6. Applies base relocations (HIGHLOW for 32-bit, DIR64 for 64-bit)
/// 7. Sets per-section memory protections
/// 8. Executes via CreateThread + WaitForSingleObject
/// 9. Cleans up with VirtualFree
///
/// # Arguments
///
/// * `buffer` - A byte slice of the PE file (borrowed, no cloning needed).
///
/// # Safety
///
/// This function is unsafe because it directly interacts with the Windows API,
/// allocates executable memory, and runs arbitrary PE code.
pub unsafe fn reflective_loader(buffer: &[u8]) {
    reflective_loader_with_args(buffer, &[]);
}

/// Loads a PE file into memory using reflective loading, with argument support
/// for .NET assemblies.
///
/// For native PEs, `args` is ignored. For .NET assemblies, `args` is passed
/// to `Main(string[] args)`.
///
/// # Safety
///
/// Same as `reflective_loader`.
pub unsafe fn reflective_loader_with_args(buffer: &[u8], args: &[&str]) {
    // Check for .NET assembly — use CLR hosting pipeline
    if utils::check_dotnet(buffer) {
        dotnet::execute_dotnet_assembly(buffer, args);
        return;
    }

    // Validate PE architecture matches the host process
    match utils::detect_platform(buffer) {
        Some(32) => {
            if core::mem::size_of::<usize>() != 4 {
                panic!("Cannot load 32-bit PE in a 64-bit process");
            }
        }
        Some(64) => {
            if core::mem::size_of::<usize>() != 8 {
                panic!("Cannot load 64-bit PE in a 32-bit process");
            }
        }
        _ => panic!("Unsupported or invalid PE architecture"),
    }

    // Get the size of the headers and the image
    let headerssize = get_headers_size(buffer);
    let imagesize = get_image_size(buffer);

    // Allocate memory with MEM_COMMIT | MEM_RESERVE and PAGE_READWRITE (not RWX)
    let baseptr = VirtualAlloc(
        core::ptr::null_mut(),
        imagesize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );

    if baseptr.is_null() {
        panic!("VirtualAlloc failed");
    }

    // Write the headers to the allocated memory
    core::ptr::copy_nonoverlapping(buffer.as_ptr() as *const c_void, baseptr, headerssize);

    // Get the DOS and NT headers from the ALLOCATED memory
    let dosheader = get_dos_header(baseptr as *const c_void);
    let ntheader = get_nt_header(baseptr as *const c_void, dosheader);

    if ntheader.is_null() {
        VirtualFree(baseptr, 0, MEM_RELEASE);
        panic!("Invalid NT header signature");
    }

    // Write each section to the allocated memory
    write_sections(baseptr, buffer, ntheader, dosheader);

    // Resolve imports (handles PE32 4-byte thunks and PE32+ 8-byte thunks)
    write_import_table(baseptr, ntheader);

    // Apply base relocations (handles HIGHLOW, DIR64, ARM_MOV32, THUMB_MOV32)
    fix_base_relocations(baseptr, ntheader);

    // Resolve delayed imports
    write_delayed_import_table(baseptr, ntheader);

    // Register exception handlers (x64/ARM64 only)
    let exception_table_ptr = register_exception_table(baseptr, ntheader);

    // Apply per-section memory protections
    change_memory_protection(baseptr, ntheader, dosheader);

    // Process TLS callbacks
    process_tls_callbacks(baseptr, ntheader);

    // Get entry point address — runtime detected from PE format
    let ep_rva = get_entry_point_rva(ntheader);
    let entrypoint = baseptr as usize + ep_rva as usize;

    // Execute via CreateThread + WaitForSingleObject
    execute_image(entrypoint);

    // Clean up exception table before freeing memory
    unregister_exception_table(exception_table_ptr);

    // Clean up allocated memory
    VirtualFree(baseptr, 0, MEM_RELEASE);
}

/// Executes the PE image by creating a new thread at the entry point
/// and waiting for it to complete.
unsafe fn execute_image(entrypoint: usize) {
    let start_routine: windows::LPTHREAD_START_ROUTINE = core::mem::transmute(entrypoint);

    let thread_handle = CreateThread(
        core::ptr::null(),
        0,
        start_routine,
        core::ptr::null_mut(),
        0,
        core::ptr::null_mut(),
    );

    if thread_handle.is_null() {
        return;
    }

    WaitForSingleObject(thread_handle, INFINITE);
    CloseHandle(thread_handle);
}

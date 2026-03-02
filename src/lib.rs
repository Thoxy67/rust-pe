#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

extern crate alloc;
#[cfg(feature = "dotnet")]
pub mod dotnet;
pub mod pelib;
pub mod test;
pub mod utils;
pub mod windows;

use alloc::vec::Vec;
use pelib::{
    change_memory_protection, fix_base_relocations, get_dos_header, get_entry_point_rva,
    get_headers_size, get_image_size, get_nt_header, initialize_security_cookie, process_tls_callbacks,
    register_exception_table, setup_cfg, unregister_exception_table, write_delayed_import_table,
    write_import_table, write_sections, zero_bound_import_directory,
};
use windows::{
    CloseHandle, CreateThread, VirtualAlloc, VirtualFree, WaitForSingleObject, INFINITE,
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};

use core::ffi::c_void;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum PeError {
    InvalidPe,
    FileTooSmall,
    ArchMismatch,
    AllocFailed,
    InvalidNtHeader,
    ImportResolveFailed,
    SectionOutOfBounds,
    UnsupportedRelocationType,
    ThreadCreationFailed,
    VirtualProtectFailed,
    DotNetError(&'static str),
}

// ---------------------------------------------------------------------------
// Debug logging (compiles to nothing in release builds)
// ---------------------------------------------------------------------------

#[cfg(debug_assertions)]
macro_rules! debug_log {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let mut buf = alloc::string::String::new();
        let _ = core::write!(buf, $($arg)*);
        buf.push('\0');
        unsafe { crate::windows::OutputDebugStringA(buf.as_ptr()); }
    }};
}

#[cfg(not(debug_assertions))]
macro_rules! debug_log {
    ($($arg:tt)*) => {};
}

pub(crate) use debug_log;

// ---------------------------------------------------------------------------
// PEB command line patching (native PE argument passing)
// ---------------------------------------------------------------------------

/// UNICODE_STRING from the PEB.
#[repr(C)]
struct PebUnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

/// Saved PEB CommandLine state for restoration.
struct SavedCommandLine {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

/// Returns a pointer to PEB->ProcessParameters->CommandLine.
unsafe fn peb_command_line() -> *mut PebUnicodeString {
    let peb: *mut u8;
    #[cfg(target_arch = "x86_64")]
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
    #[cfg(target_arch = "x86")]
    core::arch::asm!("mov {}, fs:[0x30]", out(reg) peb, options(nostack, preserves_flags));
    #[cfg(target_arch = "aarch64")]
    core::arch::asm!("ldr {}, [x18, #0x60]", out(reg) peb, options(nostack, preserves_flags));

    let pp_off: usize = if core::mem::size_of::<usize>() == 8 { 0x20 } else { 0x10 };
    let cl_off: usize = if core::mem::size_of::<usize>() == 8 { 0x70 } else { 0x40 };
    let proc_params = *(peb.add(pp_off) as *const *mut u8);
    proc_params.add(cl_off) as *mut PebUnicodeString
}

/// Builds a quoted UTF-16 command line: `"arg1" "arg2" ...`
fn build_wide_command_line(args: &[&str]) -> Vec<u16> {
    let mut v: Vec<u16> = Vec::new();
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            v.push(b' ' as u16);
        }
        v.push(b'"' as u16);
        for &b in arg.as_bytes() {
            v.push(b as u16);
        }
        v.push(b'"' as u16);
    }
    v.push(0);
    v
}

/// Patches PEB CommandLine with the given wide string, returns saved state.
unsafe fn patch_peb_command_line(wide: &[u16]) -> SavedCommandLine {
    let cl = peb_command_line();
    let saved = SavedCommandLine {
        length: (*cl).length,
        maximum_length: (*cl).maximum_length,
        buffer: (*cl).buffer,
    };
    let byte_len = ((wide.len() - 1) * 2) as u16; // exclude null terminator
    (*cl).length = byte_len;
    (*cl).maximum_length = (wide.len() * 2) as u16;
    (*cl).buffer = wide.as_ptr() as *mut u16;
    saved
}

/// Restores PEB CommandLine from saved state.
unsafe fn restore_peb_command_line(saved: SavedCommandLine) {
    let cl = peb_command_line();
    (*cl).length = saved.length;
    (*cl).maximum_length = saved.maximum_length;
    (*cl).buffer = saved.buffer;
}

/// Loads a Portable Executable (PE) file into memory using reflective loading.
///
/// Correctly parses both PE32 (32-bit) and PE32+ (64-bit) binaries at runtime,
/// but the PE bitness must match the host process architecture (a 64-bit loader
/// can only execute 64-bit PEs and vice versa).
///
/// # Safety
///
/// This function is unsafe because it directly interacts with the Windows API,
/// allocates executable memory, and runs arbitrary PE code.
pub unsafe fn reflective_loader(buffer: &[u8]) -> Result<(), PeError> {
    reflective_loader_with_args(buffer, &[])
}

/// Loads a PE file into memory using reflective loading, with argument support.
///
/// For native PEs, `args` are passed by patching the PEB CommandLine
/// (visible to `GetCommandLineW()`). For .NET assemblies, `args` is passed
/// to `Main(string[] args)`.
///
/// # Safety
///
/// Same as `reflective_loader`.
pub unsafe fn reflective_loader_with_args(buffer: &[u8], args: &[&str]) -> Result<(), PeError> {
    // Check for .NET assembly — use CLR hosting pipeline
    #[cfg(feature = "dotnet")]
    if utils::check_dotnet(buffer) {
        debug_log!("[runpe] Detected .NET assembly, using CLR pipeline\n");
        dotnet::execute_dotnet_assembly(buffer, args)?;
        return Ok(());
    }

    // Validate PE architecture matches the host process
    debug_log!("[runpe] Validating PE architecture\n");
    match utils::detect_platform(buffer) {
        Some(32) => {
            if core::mem::size_of::<usize>() != 4 {
                return Err(PeError::ArchMismatch);
            }
        }
        Some(64) => {
            if core::mem::size_of::<usize>() != 8 {
                return Err(PeError::ArchMismatch);
            }
        }
        _ => return Err(PeError::InvalidPe),
    }

    // Get the size of the headers and the image
    let headerssize = get_headers_size(buffer)?;
    let imagesize = get_image_size(buffer)?;

    // Allocate memory with MEM_COMMIT | MEM_RESERVE and PAGE_READWRITE (not RWX)
    debug_log!("[runpe] Allocating {} bytes\n", imagesize);
    let baseptr = VirtualAlloc(
        core::ptr::null_mut(),
        imagesize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );

    if baseptr.is_null() {
        return Err(PeError::AllocFailed);
    }

    // Write the headers to the allocated memory
    core::ptr::copy_nonoverlapping(buffer.as_ptr() as *const c_void, baseptr, headerssize);

    // Get the DOS and NT headers from the ALLOCATED memory
    let dosheader = get_dos_header(baseptr as *const c_void);
    let ntheader = get_nt_header(baseptr as *const c_void, dosheader);

    if ntheader.is_null() {
        VirtualFree(baseptr, 0, MEM_RELEASE);
        return Err(PeError::InvalidNtHeader);
    }

    // Zero bound imports directory to prevent stale pre-resolved addresses
    debug_log!("[runpe] Zeroing bound imports directory\n");
    zero_bound_import_directory(baseptr, ntheader);

    // Write each section to the allocated memory
    debug_log!("[runpe] Writing sections\n");
    write_sections(baseptr, buffer, ntheader, dosheader)?;

    // Resolve imports (handles PE32 4-byte thunks and PE32+ 8-byte thunks)
    debug_log!("[runpe] Resolving imports\n");
    write_import_table(baseptr, ntheader)?;

    // Apply base relocations (handles HIGHLOW, DIR64, ARM_MOV32, THUMB_MOV32)
    debug_log!("[runpe] Applying base relocations\n");
    fix_base_relocations(baseptr, ntheader)?;

    // Resolve delayed imports
    debug_log!("[runpe] Resolving delayed imports\n");
    write_delayed_import_table(baseptr, ntheader)?;

    // Register exception handlers (x64/ARM64 only)
    debug_log!("[runpe] Registering exception table\n");
    let exception_table_ptr = register_exception_table(baseptr, ntheader);

    // Initialize security cookie (__security_cookie for /GS)
    debug_log!("[runpe] Initializing security cookie\n");
    initialize_security_cookie(baseptr, ntheader);

    // Setup CFG (Control Flow Guard)
    debug_log!("[runpe] Setting up CFG\n");
    setup_cfg(baseptr, ntheader);

    // Apply per-section memory protections
    debug_log!("[runpe] Applying memory protections\n");
    change_memory_protection(baseptr, ntheader, dosheader)?;

    // Activate SxS context for GUI PEs with manifests
    debug_log!("[runpe] Activating SxS context\n");
    let sxs_guard = activate_sxs_context(baseptr, ntheader);

    // Process TLS callbacks
    debug_log!("[runpe] Processing TLS callbacks\n");
    process_tls_callbacks(baseptr, ntheader);

    // Get entry point address — runtime detected from PE format
    let ep_rva = get_entry_point_rva(ntheader);
    let entrypoint = baseptr as usize + ep_rva as usize;

    // Patch PEB command line so GetCommandLineW() returns our args
    let wide_cmd = if !args.is_empty() {
        Some(build_wide_command_line(args))
    } else {
        None
    };
    let saved_cmd = wide_cmd.as_ref().map(|w| patch_peb_command_line(w));

    // Execute via CreateThread + WaitForSingleObject
    debug_log!("[runpe] Executing PE at entry point 0x{:X}\n", entrypoint);
    execute_image(entrypoint);

    // Restore original PEB command line
    if let Some(saved) = saved_cmd {
        restore_peb_command_line(saved);
    }

    // Deactivate SxS context
    if let Some(guard) = sxs_guard {
        debug_log!("[runpe] Deactivating SxS context\n");
        deactivate_sxs_context(guard);
    }

    // Clean up exception table before freeing memory
    unregister_exception_table(exception_table_ptr);

    // Clean up allocated memory
    VirtualFree(baseptr, 0, MEM_RELEASE);

    Ok(())
}

// ---------------------------------------------------------------------------
// SxS / Activation Context
// ---------------------------------------------------------------------------

struct SxsGuard {
    handle: *mut c_void,
    cookie: usize,
}

/// Activates an SxS context from the PE's embedded manifest (resource ID 1).
unsafe fn activate_sxs_context(
    baseptr: *const c_void,
    ntheader: *const c_void,
) -> Option<SxsGuard> {
    let resource_dir = pelib::data_directory_pub(ntheader, windows::IMAGE_DIRECTORY_ENTRY_RESOURCE);
    if resource_dir.Size == 0 {
        return None;
    }

    // Use a null-terminated empty wide string as source (not used with HMODULE flag)
    let empty_source: [u16; 1] = [0];
    let mut actctx = windows::ACTCTXW {
        cbSize: core::mem::size_of::<windows::ACTCTXW>() as u32,
        dwFlags: windows::ACTCTX_FLAG_RESOURCE_NAME_VALID | windows::ACTCTX_FLAG_HMODULE_VALID,
        lpSource: empty_source.as_ptr(),
        wProcessorArchitecture: 0,
        wLangId: 0,
        lpAssemblyDirectory: core::ptr::null(),
        lpResourceName: 1usize as *const u16, // MAKEINTRESOURCE(1)
        lpApplicationName: core::ptr::null(),
        hModule: baseptr as *mut c_void,
    };

    let handle = windows::CreateActCtxW(&mut actctx);
    if handle == windows::INVALID_HANDLE_VALUE || handle.is_null() {
        return None;
    }

    let mut cookie: usize = 0;
    if windows::ActivateActCtx(handle, &mut cookie) == 0 {
        windows::ReleaseActCtx(handle);
        return None;
    }

    Some(SxsGuard { handle, cookie })
}

/// Deactivates and releases an SxS context.
unsafe fn deactivate_sxs_context(guard: SxsGuard) {
    windows::DeactivateActCtx(0, guard.cookie);
    windows::ReleaseActCtx(guard.handle);
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

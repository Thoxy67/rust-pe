use core::ffi::c_void;

use crate::debug_log;
use crate::PeError;
use crate::windows::{
    GetProcAddress, LoadLibraryA, RtlAddFunctionTable, RtlDeleteFunctionTable, VirtualProtect,
    DLL_PROCESS_ATTACH, IMAGE_BASE_RELOCATION, IMAGE_DELAYLOAD_DESCRIPTOR,
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, IMAGE_DIRECTORY_ENTRY_EXCEPTION,
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
    IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR,
    IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR32_MAGIC,
    IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_NT_SIGNATURE, IMAGE_ORDINAL_FLAG32, IMAGE_ORDINAL_FLAG64,
    IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_ARM_MOV32, IMAGE_REL_BASED_DIR64,
    IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_THUMB_MOV32, IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_WRITE, IMAGE_SECTION_HEADER, IMAGE_TLS_DIRECTORY32, IMAGE_TLS_DIRECTORY64,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READONLY,
    PAGE_READWRITE, PIMAGE_TLS_CALLBACK, RUNTIME_FUNCTION,
};

// ---------------------------------------------------------------------------
// Runtime PE format detection
// ---------------------------------------------------------------------------

/// Detects whether the PE loaded at `ntheader` is PE32 (true) or PE32+ (false).
/// Reads the Magic field from the OptionalHeader to decide at runtime.
unsafe fn is_pe32(ntheader: *const c_void) -> bool {
    // The Signature (u32) + FileHeader (IMAGE_FILE_HEADER = 20 bytes) precede
    // the OptionalHeader. The first field of OptionalHeader is Magic (u16).
    let magic_ptr = (ntheader as *const u8).add(4 + 20) as *const u16;
    let magic = core::ptr::read_unaligned(magic_ptr);
    magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC
}

/// Returns the offset from the start of the NT headers to the first section header.
/// Uses FileHeader.SizeOfOptionalHeader for robustness (handles non-standard sizes).
unsafe fn section_headers_offset(ntheader: *const c_void) -> usize {
    // SizeOfOptionalHeader is at FileHeader + 16, and FileHeader starts at offset 4
    let size_of_opt_hdr_ptr = (ntheader as *const u8).add(4 + 16) as *const u16;
    let size_of_opt_hdr = core::ptr::read_unaligned(size_of_opt_hdr_ptr) as usize;
    // Signature(4) + FileHeader(20) + SizeOfOptionalHeader
    4 + 20 + size_of_opt_hdr
}

/// Returns the number of sections from the FileHeader.
/// FileHeader.NumberOfSections is at the same offset for both PE32 and PE32+.
unsafe fn number_of_sections(ntheader: *const c_void) -> u16 {
    // FileHeader starts at offset 4 (after Signature).
    // NumberOfSections is at FileHeader + 2 (offset 6 from ntheader start).
    let ptr = (ntheader as *const u8).add(4 + 2) as *const u16;
    core::ptr::read_unaligned(ptr)
}

/// Returns AddressOfEntryPoint from the OptionalHeader.
/// This field is at the same byte offset (+40) in both PE32 and PE32+.
unsafe fn entry_point_rva(ntheader: *const c_void) -> u32 {
    let ptr = (ntheader as *const u8).add(4 + 20 + 16) as *const u32;
    core::ptr::read_unaligned(ptr)
}

/// Returns ImageBase. For PE32 it's a u32, for PE32+ it's a u64.
/// Always returned as usize for pointer arithmetic.
unsafe fn image_base(ntheader: *const c_void) -> usize {
    if is_pe32(ntheader) {
        (*(ntheader as *const IMAGE_NT_HEADERS32))
            .OptionalHeader
            .ImageBase as usize
    } else {
        (*(ntheader as *const IMAGE_NT_HEADERS64))
            .OptionalHeader
            .ImageBase as usize
    }
}

/// Returns a DataDirectory entry by index, handling both PE32 and PE32+.
unsafe fn data_directory(
    ntheader: *const c_void,
    index: usize,
) -> crate::windows::IMAGE_DATA_DIRECTORY {
    if is_pe32(ntheader) {
        (*(ntheader as *const IMAGE_NT_HEADERS32))
            .OptionalHeader
            .DataDirectory[index]
    } else {
        (*(ntheader as *const IMAGE_NT_HEADERS64))
            .OptionalHeader
            .DataDirectory[index]
    }
}

// ---------------------------------------------------------------------------
// Public API: header parsing from raw buffer
// ---------------------------------------------------------------------------

/// Returns the size of the PE headers from the raw buffer.
pub fn get_headers_size(buffer: &[u8]) -> Result<usize, PeError> {
    if buffer.len() < 2 || buffer[0] != b'M' || buffer[1] != b'Z' {
        return Err(PeError::InvalidPe);
    }
    if buffer.len() < 0x40 {
        return Err(PeError::FileTooSmall);
    }

    let offset = u32::from_le_bytes([buffer[60], buffer[61], buffer[62], buffer[63]]) as usize;

    if buffer.len() < offset + 4 + 20 + 2 {
        return Err(PeError::FileTooSmall);
    }

    let magic = u16::from_le_bytes([buffer[offset + 4 + 20], buffer[offset + 4 + 20 + 1]]);
    match magic {
        IMAGE_NT_OPTIONAL_HDR64_MAGIC | IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
            // SizeOfHeaders is at OptionalHeader + 60 for both PE32 and PE32+
            let idx = offset + 24 + 60;
            if buffer.len() < idx + 4 {
                return Err(PeError::FileTooSmall);
            }
            Ok(u32::from_le_bytes([
                buffer[idx],
                buffer[idx + 1],
                buffer[idx + 2],
                buffer[idx + 3],
            ]) as usize)
        }
        _ => Err(PeError::InvalidPe),
    }
}

/// Returns the size of the PE image (SizeOfImage) from the raw buffer.
pub fn get_image_size(buffer: &[u8]) -> Result<usize, PeError> {
    if buffer.len() < 2 || buffer[0] != b'M' || buffer[1] != b'Z' {
        return Err(PeError::InvalidPe);
    }
    if buffer.len() < 0x40 {
        return Err(PeError::FileTooSmall);
    }

    let offset = u32::from_le_bytes([buffer[60], buffer[61], buffer[62], buffer[63]]) as usize;

    if buffer.len() < offset + 4 + 20 + 2 {
        return Err(PeError::FileTooSmall);
    }

    let magic = u16::from_le_bytes([buffer[offset + 4 + 20], buffer[offset + 4 + 20 + 1]]);
    match magic {
        IMAGE_NT_OPTIONAL_HDR64_MAGIC | IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
            // SizeOfImage is at OptionalHeader + 56 for both PE32 and PE32+
            let idx = offset + 24 + 56;
            if buffer.len() < idx + 4 {
                return Err(PeError::FileTooSmall);
            }
            Ok(u32::from_le_bytes([
                buffer[idx],
                buffer[idx + 1],
                buffer[idx + 2],
                buffer[idx + 3],
            ]) as usize)
        }
        _ => Err(PeError::InvalidPe),
    }
}

/// Casts `lp_image` to an `IMAGE_DOS_HEADER` pointer.
pub fn get_dos_header(lp_image: *const c_void) -> *const IMAGE_DOS_HEADER {
    lp_image as *const IMAGE_DOS_HEADER
}

/// Returns a pointer to the NT header, validated against the PE signature.
/// Works for both PE32 and PE32+ — the Signature and FileHeader are at the
/// same offsets regardless of optional header format.
pub fn get_nt_header(
    lp_image: *const c_void,
    lp_dos_header: *const IMAGE_DOS_HEADER,
) -> *const c_void {
    let nt_addr = unsafe { lp_image as usize + (*lp_dos_header).e_lfanew as usize };
    // Signature is always the first u32 in both NT_HEADERS32 and NT_HEADERS64
    let sig = unsafe { core::ptr::read_unaligned(nt_addr as *const u32) };
    if sig != IMAGE_NT_SIGNATURE {
        return core::ptr::null();
    }
    nt_addr as *const c_void
}

// ---------------------------------------------------------------------------
// Section writing
// ---------------------------------------------------------------------------

/// Writes each section of the PE file to the allocated memory.
pub fn write_sections(
    baseptr: *const c_void,
    buffer: &[u8],
    ntheader: *const c_void,
    dosheader: *const IMAGE_DOS_HEADER,
) -> Result<(), PeError> {
    let num_sections = unsafe { number_of_sections(ntheader) };
    let sec_offset = unsafe { section_headers_offset(ntheader) };
    let e_lfanew = (unsafe { *dosheader }).e_lfanew as usize;

    let mut section_ptr = (baseptr as usize + e_lfanew + sec_offset) as *const IMAGE_SECTION_HEADER;

    for _i in 0..num_sections {
        let raw_offset = unsafe { (*section_ptr).PointerToRawData } as usize;
        let raw_size = unsafe { (*section_ptr).SizeOfRawData } as usize;
        let virtual_addr = unsafe { (*section_ptr).VirtualAddress } as usize;

        if raw_offset == 0 || raw_size == 0 {
            section_ptr = unsafe { section_ptr.add(1) };
            continue;
        }
        if raw_offset + raw_size > buffer.len() {
            return Err(PeError::SectionOutOfBounds);
        }

        let section_data = &buffer[raw_offset..raw_offset + raw_size];
        unsafe {
            core::ptr::copy_nonoverlapping(
                section_data.as_ptr() as *const c_void,
                (baseptr as usize + virtual_addr) as *mut c_void,
                raw_size,
            )
        };

        section_ptr = unsafe { section_ptr.add(1) };
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Base relocations
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ARM relocation helpers
// ---------------------------------------------------------------------------

/// Extracts a 32-bit value from an ARM MOVW+MOVT instruction pair.
/// MOVW/MOVT encoding: imm4 in bits[19:16], imm12 in bits[11:0].
unsafe fn arm_mov32_extract(addr: *const u8) -> u32 {
    let movw = core::ptr::read_unaligned(addr as *const u32);
    let movt = core::ptr::read_unaligned(addr.add(4) as *const u32);
    let low = ((movw >> 4) & 0xF000) | (movw & 0xFFF);
    let high = ((movt >> 4) & 0xF000) | (movt & 0xFFF);
    (high << 16) | low
}

/// Encodes a 32-bit value back into an ARM MOVW+MOVT instruction pair.
unsafe fn arm_mov32_encode(addr: *mut u8, value: u32) {
    let low = value & 0xFFFF;
    let high = value >> 16;

    let movw = core::ptr::read_unaligned(addr as *const u32);
    let movw = (movw & 0xFFF0_F000) | ((low & 0xF000) << 4) | (low & 0xFFF);
    core::ptr::write_unaligned(addr as *mut u32, movw);

    let movt = core::ptr::read_unaligned(addr.add(4) as *const u32);
    let movt = (movt & 0xFFF0_F000) | ((high & 0xF000) << 4) | (high & 0xFFF);
    core::ptr::write_unaligned(addr.add(4) as *mut u32, movt);
}

/// Extracts a 32-bit value from a Thumb-2 MOVW+MOVT instruction pair.
/// Thumb-2 encoding: imm4 in hw0[3:0], i in hw0[10], imm3 in hw1[14:12], imm8 in hw1[7:0].
unsafe fn thumb_mov32_extract(addr: *const u8) -> u32 {
    let hw0 = core::ptr::read_unaligned(addr as *const u16) as u32;
    let hw1 = core::ptr::read_unaligned(addr.add(2) as *const u16) as u32;
    let hw2 = core::ptr::read_unaligned(addr.add(4) as *const u16) as u32;
    let hw3 = core::ptr::read_unaligned(addr.add(6) as *const u16) as u32;

    let low =
        ((hw0 & 0xF) << 12) | (((hw0 >> 10) & 1) << 11) | (((hw1 >> 12) & 0x7) << 8) | (hw1 & 0xFF);

    let high =
        ((hw2 & 0xF) << 12) | (((hw2 >> 10) & 1) << 11) | (((hw3 >> 12) & 0x7) << 8) | (hw3 & 0xFF);

    (high << 16) | low
}

/// Encodes a 32-bit value back into a Thumb-2 MOVW+MOVT instruction pair.
unsafe fn thumb_mov32_encode(addr: *mut u8, value: u32) {
    let low = value & 0xFFFF;
    let high = value >> 16;

    let hw0 = core::ptr::read_unaligned(addr as *const u16) as u32;
    let hw1 = core::ptr::read_unaligned(addr.add(2) as *const u16) as u32;
    let hw0 = (hw0 & 0xFBF0) | ((low >> 12) & 0xF) | (((low >> 11) & 1) << 10);
    let hw1 = (hw1 & 0x8F00) | (((low >> 8) & 0x7) << 12) | (low & 0xFF);
    core::ptr::write_unaligned(addr as *mut u16, hw0 as u16);
    core::ptr::write_unaligned(addr.add(2) as *mut u16, hw1 as u16);

    let hw2 = core::ptr::read_unaligned(addr.add(4) as *const u16) as u32;
    let hw3 = core::ptr::read_unaligned(addr.add(6) as *const u16) as u32;
    let hw2 = (hw2 & 0xFBF0) | ((high >> 12) & 0xF) | (((high >> 11) & 1) << 10);
    let hw3 = (hw3 & 0x8F00) | (((high >> 8) & 0x7) << 12) | (high & 0xFF);
    core::ptr::write_unaligned(addr.add(4) as *mut u16, hw2 as u16);
    core::ptr::write_unaligned(addr.add(6) as *mut u16, hw3 as u16);
}

// ---------------------------------------------------------------------------
// Base relocations
// ---------------------------------------------------------------------------

/// Fixes PE base relocations. Handles HIGHLOW, DIR64, ARM_MOV32, and THUMB_MOV32.
pub fn fix_base_relocations(baseptr: *const c_void, ntheader: *const c_void) -> Result<(), PeError> {
    let basereloc = unsafe { data_directory(ntheader, IMAGE_DIRECTORY_ENTRY_BASERELOC) };
    if basereloc.Size == 0 {
        return Ok(());
    }

    let img_base = unsafe { image_base(ntheader) };
    let diff = (baseptr as usize).wrapping_sub(img_base);

    let mut relocptr =
        (baseptr as usize + basereloc.VirtualAddress as usize) as *const IMAGE_BASE_RELOCATION;

    while unsafe { (*relocptr).SizeOfBlock } != 0 {
        let block_size = unsafe { (*relocptr).SizeOfBlock } as usize;
        let entries = (block_size - core::mem::size_of::<IMAGE_BASE_RELOCATION>()) / 2;

        for i in 0..entries {
            let entry_ptr = (relocptr as usize
                + core::mem::size_of::<IMAGE_BASE_RELOCATION>()
                + i * 2) as *const u16;
            let entry = unsafe { *entry_ptr };
            let reloc_type = (entry >> 12) as u32;
            let offset = (entry & 0x0FFF) as usize;

            let addr = baseptr as usize + unsafe { (*relocptr).VirtualAddress } as usize + offset;

            match reloc_type {
                IMAGE_REL_BASED_ABSOLUTE => {}
                IMAGE_REL_BASED_HIGHLOW => {
                    let ptr = addr as *mut u32;
                    unsafe {
                        let val = core::ptr::read_unaligned(ptr);
                        core::ptr::write_unaligned(ptr, val.wrapping_add(diff as u32));
                    }
                }
                IMAGE_REL_BASED_DIR64 => {
                    let ptr = addr as *mut u64;
                    unsafe {
                        let val = core::ptr::read_unaligned(ptr);
                        core::ptr::write_unaligned(ptr, val.wrapping_add(diff as u64));
                    }
                }
                IMAGE_REL_BASED_ARM_MOV32 => unsafe {
                    let current = arm_mov32_extract(addr as *const u8);
                    arm_mov32_encode(addr as *mut u8, current.wrapping_add(diff as u32));
                },
                IMAGE_REL_BASED_THUMB_MOV32 => unsafe {
                    let current = thumb_mov32_extract(addr as *const u8);
                    thumb_mov32_encode(addr as *mut u8, current.wrapping_add(diff as u32));
                },
                _ => return Err(PeError::UnsupportedRelocationType),
            }
        }

        relocptr =
            unsafe { (relocptr as *const u8).add(block_size) as *const IMAGE_BASE_RELOCATION };
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Import table resolution
// ---------------------------------------------------------------------------

/// Resolves imports for both PE32 and PE32+.
/// The thunk size differs: 4 bytes for PE32, 8 bytes for PE32+.
pub fn write_import_table(baseptr: *const c_void, ntheader: *const c_void) -> Result<(), PeError> {
    let import_dir = unsafe { data_directory(ntheader, IMAGE_DIRECTORY_ENTRY_IMPORT) };
    if import_dir.Size == 0 {
        return Ok(());
    }

    let pe32 = unsafe { is_pe32(ntheader) };
    let thunk_size: usize = if pe32 { 4 } else { 8 };
    let ordinal_flag: u64 = if pe32 {
        IMAGE_ORDINAL_FLAG32 as u64
    } else {
        IMAGE_ORDINAL_FLAG64 as u64
    };

    let mut import_desc_ptr = baseptr as usize + import_dir.VirtualAddress as usize;

    while unsafe { (*(import_desc_ptr as *const IMAGE_IMPORT_DESCRIPTOR)).Name } != 0
        && unsafe { (*(import_desc_ptr as *const IMAGE_IMPORT_DESCRIPTOR)).FirstThunk } != 0
    {
        let mut import = unsafe { core::mem::zeroed::<IMAGE_IMPORT_DESCRIPTOR>() };
        unsafe {
            core::ptr::copy_nonoverlapping(
                import_desc_ptr as *const u8,
                &mut import as *mut IMAGE_IMPORT_DESCRIPTOR as *mut u8,
                core::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>(),
            );
        }

        let dllname_ptr = (baseptr as usize + import.Name as usize) as *const u8;
        let dllname = crate::utils::read_string_from_memory(dllname_ptr);

        // Try API set resolution for api-ms-win-* and ext-ms-win-* DLLs
        let dllhandle = if let Some(resolved) = resolve_api_set(dllname.as_bytes()) {
            debug_log!("[runpe] API set resolved: {} -> {:?}\n", dllname, core::str::from_utf8(&resolved));
            unsafe { LoadLibraryA(resolved.as_ptr()) }
        } else {
            unsafe { LoadLibraryA(dllname_ptr) }
        };
        if dllhandle.is_null() {
            import_desc_ptr += core::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
            continue;
        }

        // Read from OriginalFirstThunk (ILT), fall back to FirstThunk
        let oft = unsafe { import.Anonymous.OriginalFirstThunk } as usize;
        let mut ilt_ptr = if oft != 0 {
            baseptr as usize + oft
        } else {
            baseptr as usize + import.FirstThunk as usize
        };

        let mut i: usize = 0;

        loop {
            // Read thunk value — 4 bytes for PE32, 8 bytes for PE32+
            let thunk_value: u64 = if pe32 {
                let v = unsafe { core::ptr::read_unaligned(ilt_ptr as *const u32) };
                v as u64
            } else {
                unsafe { core::ptr::read_unaligned(ilt_ptr as *const u64) }
            };

            if thunk_value == 0 {
                break;
            }

            let funcaddress = if thunk_value & ordinal_flag != 0 {
                let ordinal = (thunk_value & 0xFFFF) as u16;
                unsafe { GetProcAddress(dllhandle, ordinal as usize as *const u8) }
            } else {
                // For PE32, thunk_value is a 32-bit RVA
                let rva = thunk_value as usize;
                let funcname_ptr = (baseptr as usize + rva + 2) as *const u8;
                if unsafe { *funcname_ptr } == 0 {
                    ilt_ptr += thunk_size;
                    i += 1;
                    continue;
                }
                unsafe { GetProcAddress(dllhandle, funcname_ptr) }
            };

            // Write resolved address into IAT (FirstThunk)
            // For PE32: write 4 bytes. For PE32+: write 8 bytes (usize on x64).
            let iat_entry = baseptr as usize + import.FirstThunk as usize + i * thunk_size;
            if pe32 {
                unsafe {
                    core::ptr::write_unaligned(iat_entry as *mut u32, funcaddress as u32);
                }
            } else {
                unsafe {
                    core::ptr::write_unaligned(iat_entry as *mut u64, funcaddress as u64);
                }
            }

            i += 1;
            ilt_ptr += thunk_size;
        }

        import_desc_ptr += core::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Per-section memory protections
// ---------------------------------------------------------------------------

/// Applies per-section memory protections using `VirtualProtect`.
pub unsafe fn change_memory_protection(
    baseptr: *const c_void,
    ntheader: *const c_void,
    dosheader: *const IMAGE_DOS_HEADER,
) -> Result<(), PeError> {
    let num_sections = number_of_sections(ntheader);
    let sec_offset = section_headers_offset(ntheader);
    let e_lfanew = (*dosheader).e_lfanew as usize;

    let mut section_ptr = (baseptr as usize + e_lfanew + sec_offset) as *const IMAGE_SECTION_HEADER;

    for _i in 0..num_sections {
        let chars = (*section_ptr).Characteristics;
        let virtual_size = (*section_ptr).Misc.VirtualSize as usize;
        let virtual_addr = (*section_ptr).VirtualAddress as usize;

        let is_exec = chars & IMAGE_SCN_MEM_EXECUTE != 0;
        let is_write = chars & IMAGE_SCN_MEM_WRITE != 0;

        let new_protect: PAGE_PROTECTION_FLAGS = if is_exec && is_write {
            PAGE_EXECUTE_READWRITE
        } else if is_exec {
            PAGE_EXECUTE_READ
        } else if is_write {
            PAGE_READWRITE
        } else {
            PAGE_READONLY
        };

        let section_addr = (baseptr as usize + virtual_addr) as *const c_void;
        let mut old_protect: PAGE_PROTECTION_FLAGS = 0;
        if VirtualProtect(section_addr, virtual_size, new_protect, &mut old_protect) == 0 {
            return Err(PeError::VirtualProtectFailed);
        }

        section_ptr = section_ptr.add(1);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Public helpers for lib.rs
// ---------------------------------------------------------------------------

/// Returns the AddressOfEntryPoint RVA, runtime-detected for PE32/PE32+.
pub unsafe fn get_entry_point_rva(ntheader: *const c_void) -> u32 {
    entry_point_rva(ntheader)
}

/// Returns whether the PE at ntheader is PE32 (32-bit).
pub unsafe fn is_pe32_format(ntheader: *const c_void) -> bool {
    is_pe32(ntheader)
}

// ---------------------------------------------------------------------------
// Delayed imports
// ---------------------------------------------------------------------------

/// Resolves delayed imports from DataDirectory[13].
/// Same resolution logic as regular imports. Only handles modern format (RVAs).
pub fn write_delayed_import_table(baseptr: *const c_void, ntheader: *const c_void) -> Result<(), PeError> {
    let delay_dir = unsafe { data_directory(ntheader, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) };
    if delay_dir.Size == 0 {
        return Ok(());
    }

    let pe32 = unsafe { is_pe32(ntheader) };
    let thunk_size: usize = if pe32 { 4 } else { 8 };
    let ordinal_flag: u64 = if pe32 {
        IMAGE_ORDINAL_FLAG32 as u64
    } else {
        IMAGE_ORDINAL_FLAG64 as u64
    };

    let mut desc_ptr = baseptr as usize + delay_dir.VirtualAddress as usize;

    loop {
        let desc = unsafe { &*(desc_ptr as *const IMAGE_DELAYLOAD_DESCRIPTOR) };
        if desc.DllNameRVA == 0 {
            break;
        }

        // Only handle modern format (Attributes bit 0 = 1 means RVAs)
        if desc.Attributes & 1 == 0 {
            desc_ptr += core::mem::size_of::<IMAGE_DELAYLOAD_DESCRIPTOR>();
            continue;
        }

        let dllname_ptr = (baseptr as usize + desc.DllNameRVA as usize) as *const u8;
        let dllname = crate::utils::read_string_from_memory(dllname_ptr);

        // Try API set resolution for api-ms-win-* and ext-ms-win-* DLLs
        let dllhandle = if let Some(resolved) = resolve_api_set(dllname.as_bytes()) {
            unsafe { LoadLibraryA(resolved.as_ptr()) }
        } else {
            unsafe { LoadLibraryA(dllname_ptr) }
        };
        if dllhandle.is_null() {
            desc_ptr += core::mem::size_of::<IMAGE_DELAYLOAD_DESCRIPTOR>();
            continue;
        }

        let mut int_ptr = baseptr as usize + desc.ImportNameTableRVA as usize;
        let mut iat_ptr = baseptr as usize + desc.ImportAddressTableRVA as usize;

        loop {
            let thunk_value: u64 = if pe32 {
                (unsafe { core::ptr::read_unaligned(int_ptr as *const u32) }) as u64
            } else {
                unsafe { core::ptr::read_unaligned(int_ptr as *const u64) }
            };

            if thunk_value == 0 {
                break;
            }

            let funcaddress = if thunk_value & ordinal_flag != 0 {
                let ordinal = (thunk_value & 0xFFFF) as u16;
                unsafe { GetProcAddress(dllhandle, ordinal as usize as *const u8) }
            } else {
                let rva = thunk_value as usize;
                let funcname_ptr = (baseptr as usize + rva + 2) as *const u8;
                unsafe { GetProcAddress(dllhandle, funcname_ptr) }
            };

            if pe32 {
                unsafe {
                    core::ptr::write_unaligned(iat_ptr as *mut u32, funcaddress as u32);
                }
            } else {
                unsafe {
                    core::ptr::write_unaligned(iat_ptr as *mut u64, funcaddress as u64);
                }
            }

            int_ptr += thunk_size;
            iat_ptr += thunk_size;
        }

        // Store loaded module handle
        if desc.ModuleHandleRVA != 0 {
            let handle_ptr = baseptr as usize + desc.ModuleHandleRVA as usize;
            if pe32 {
                unsafe { core::ptr::write_unaligned(handle_ptr as *mut u32, dllhandle as u32) }
            } else {
                unsafe { core::ptr::write_unaligned(handle_ptr as *mut u64, dllhandle as u64) }
            }
        }

        desc_ptr += core::mem::size_of::<IMAGE_DELAYLOAD_DESCRIPTOR>();
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Exception table registration (PDATA)
// ---------------------------------------------------------------------------

/// Registers exception handler tables for x64/ARM64 PE images.
/// Returns the function table pointer for cleanup, or null if nothing registered.
pub unsafe fn register_exception_table(
    baseptr: *const c_void,
    ntheader: *const c_void,
) -> *const RUNTIME_FUNCTION {
    if is_pe32(ntheader) {
        return core::ptr::null();
    }

    let exception_dir = data_directory(ntheader, IMAGE_DIRECTORY_ENTRY_EXCEPTION);
    if exception_dir.Size == 0 {
        return core::ptr::null();
    }

    let table_ptr =
        (baseptr as usize + exception_dir.VirtualAddress as usize) as *const RUNTIME_FUNCTION;
    let entry_count = exception_dir.Size / 12;

    let result = RtlAddFunctionTable(table_ptr, entry_count, baseptr as u64);
    if result == 0 {
        return core::ptr::null();
    }

    table_ptr
}

/// Unregisters previously registered exception handler tables.
pub unsafe fn unregister_exception_table(table_ptr: *const RUNTIME_FUNCTION) {
    if !table_ptr.is_null() {
        RtlDeleteFunctionTable(table_ptr);
    }
}

// ---------------------------------------------------------------------------
// TLS (Thread Local Storage) callbacks
// ---------------------------------------------------------------------------

/// Processes TLS callbacks. Must be called AFTER memory protections and BEFORE entry point.
/// TLS directory fields contain VAs (virtual addresses), not RVAs.
pub unsafe fn process_tls_callbacks(baseptr: *const c_void, ntheader: *const c_void) {
    let tls_dir = data_directory(ntheader, IMAGE_DIRECTORY_ENTRY_TLS);
    if tls_dir.Size == 0 {
        return;
    }

    let tls_addr = baseptr as usize + tls_dir.VirtualAddress as usize;

    if is_pe32(ntheader) {
        let tls = &*(tls_addr as *const IMAGE_TLS_DIRECTORY32);

        if tls.AddressOfIndex != 0 {
            core::ptr::write_unaligned(tls.AddressOfIndex as *mut u32, 0u32);
        }

        if tls.AddressOfCallBacks != 0 {
            let mut cb_ptr = tls.AddressOfCallBacks as *const u32;
            while core::ptr::read_unaligned(cb_ptr) != 0 {
                let callback: PIMAGE_TLS_CALLBACK =
                    core::mem::transmute(core::ptr::read_unaligned(cb_ptr) as usize);
                callback(
                    baseptr as *mut c_void,
                    DLL_PROCESS_ATTACH,
                    core::ptr::null_mut(),
                );
                cb_ptr = cb_ptr.add(1);
            }
        }
    } else {
        let tls = &*(tls_addr as *const IMAGE_TLS_DIRECTORY64);

        if tls.AddressOfIndex != 0 {
            core::ptr::write_unaligned(tls.AddressOfIndex as *mut u32, 0u32);
        }

        if tls.AddressOfCallBacks != 0 {
            let mut cb_ptr = tls.AddressOfCallBacks as *const u64;
            while core::ptr::read_unaligned(cb_ptr) != 0 {
                let callback: PIMAGE_TLS_CALLBACK =
                    core::mem::transmute(core::ptr::read_unaligned(cb_ptr) as usize);
                callback(
                    baseptr as *mut c_void,
                    DLL_PROCESS_ATTACH,
                    core::ptr::null_mut(),
                );
                cb_ptr = cb_ptr.add(1);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Export table resolution
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Forwarded exports resolution
// ---------------------------------------------------------------------------

/// Resolves a forwarded export string (e.g. "NTDLL.RtlAllocateHeap" or "NTDLL.#123").
unsafe fn resolve_forwarded_export(baseptr: *const c_void, func_rva: usize) -> *mut c_void {
    let forward_str = crate::utils::read_string_from_memory(
        (baseptr as usize + func_rva) as *const u8,
    );

    // Split on '.'
    let dot_pos = match forward_str.as_bytes().iter().position(|&b| b == b'.') {
        Some(p) => p,
        None => return core::ptr::null_mut(),
    };

    // Build DLL name with .dll suffix and null terminator
    let dll_part = &forward_str.as_bytes()[..dot_pos];
    let func_part = &forward_str.as_bytes()[dot_pos + 1..];

    let mut dll_name = alloc::vec::Vec::with_capacity(dll_part.len() + 5);
    dll_name.extend_from_slice(dll_part);
    dll_name.extend_from_slice(b".dll\0");

    let dll_handle = LoadLibraryA(dll_name.as_ptr());
    if dll_handle.is_null() {
        return core::ptr::null_mut();
    }

    // Check for ordinal forward: "#123"
    if !func_part.is_empty() && func_part[0] == b'#' {
        let ordinal_str = &func_part[1..];
        let mut ordinal: u16 = 0;
        for &b in ordinal_str {
            if b >= b'0' && b <= b'9' {
                ordinal = ordinal.wrapping_mul(10).wrapping_add((b - b'0') as u16);
            } else {
                break;
            }
        }
        return GetProcAddress(dll_handle, ordinal as usize as *const u8);
    }

    // Name-based forward
    let mut func_name = alloc::vec::Vec::with_capacity(func_part.len() + 1);
    func_name.extend_from_slice(func_part);
    func_name.push(0);
    GetProcAddress(dll_handle, func_name.as_ptr())
}

/// Resolves an export by name from a reflectively-loaded PE image.
/// Returns a pointer to the function, or null if not found.
/// Handles forwarded exports by loading the target DLL and resolving the forward.
pub unsafe fn get_export_by_name(
    baseptr: *const c_void,
    ntheader: *const c_void,
    name: &[u8],
) -> *mut c_void {
    let export_dir = data_directory(ntheader, IMAGE_DIRECTORY_ENTRY_EXPORT);
    if export_dir.Size == 0 {
        return core::ptr::null_mut();
    }

    let export_dir_start = export_dir.VirtualAddress as usize;
    let export_dir_end = export_dir_start + export_dir.Size as usize;
    let exports = &*((baseptr as usize + export_dir_start) as *const IMAGE_EXPORT_DIRECTORY);

    let names_ptr = (baseptr as usize + exports.AddressOfNames as usize) as *const u32;
    let ordinals_ptr = (baseptr as usize + exports.AddressOfNameOrdinals as usize) as *const u16;
    let functions_ptr = (baseptr as usize + exports.AddressOfFunctions as usize) as *const u32;

    for i in 0..exports.NumberOfNames as usize {
        let name_rva = core::ptr::read_unaligned(names_ptr.add(i));
        let export_name = (baseptr as usize + name_rva as usize) as *const u8;

        let mut j = 0;
        loop {
            let a = *export_name.add(j);
            let b = if j < name.len() { name[j] } else { 0 };
            if a != b {
                break;
            }
            if a == 0 {
                let ordinal_index = core::ptr::read_unaligned(ordinals_ptr.add(i)) as usize;
                let func_rva = core::ptr::read_unaligned(functions_ptr.add(ordinal_index)) as usize;

                if func_rva >= export_dir_start && func_rva < export_dir_end {
                    // Forwarded export — resolve it
                    return resolve_forwarded_export(baseptr, func_rva);
                }
                return (baseptr as usize + func_rva) as *mut c_void;
            }
            j += 1;
        }
    }

    core::ptr::null_mut()
}

/// Resolves an export by ordinal from a reflectively-loaded PE image.
/// Returns a pointer to the function, or null if not found.
/// Handles forwarded exports by loading the target DLL and resolving the forward.
pub unsafe fn get_export_by_ordinal(
    baseptr: *const c_void,
    ntheader: *const c_void,
    ordinal: u16,
) -> *mut c_void {
    let export_dir = data_directory(ntheader, IMAGE_DIRECTORY_ENTRY_EXPORT);
    if export_dir.Size == 0 {
        return core::ptr::null_mut();
    }

    let export_dir_start = export_dir.VirtualAddress as usize;
    let export_dir_end = export_dir_start + export_dir.Size as usize;
    let exports = &*((baseptr as usize + export_dir_start) as *const IMAGE_EXPORT_DIRECTORY);

    let index = (ordinal as u32).wrapping_sub(exports.Base);
    if index >= exports.NumberOfFunctions {
        return core::ptr::null_mut();
    }

    let functions_ptr = (baseptr as usize + exports.AddressOfFunctions as usize) as *const u32;
    let func_rva = core::ptr::read_unaligned(functions_ptr.add(index as usize)) as usize;

    if func_rva == 0 {
        return core::ptr::null_mut();
    }

    if func_rva >= export_dir_start && func_rva < export_dir_end {
        // Forwarded export — resolve it
        return resolve_forwarded_export(baseptr, func_rva);
    }

    (baseptr as usize + func_rva) as *mut c_void
}

// ---------------------------------------------------------------------------
// Bound imports invalidation
// ---------------------------------------------------------------------------

/// Zeros the Bound Import data directory entry to prevent stale pre-resolved addresses.
pub unsafe fn zero_bound_import_directory(_baseptr: *const c_void, ntheader: *const c_void) {
    if is_pe32(ntheader) {
        let nt = &mut *(ntheader as *mut IMAGE_NT_HEADERS32);
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
    } else {
        let nt = &mut *(ntheader as *mut IMAGE_NT_HEADERS64);
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
    }
}

// ---------------------------------------------------------------------------
// API Set Schema resolution
// ---------------------------------------------------------------------------

/// Resolves an API set DLL name (e.g. "api-ms-win-core-heap-l1-1-0.dll") to its
/// host DLL (e.g. "kernel32.dll") using the PEB ApiSetMap.
/// Returns a null-terminated Vec<u8> suitable for LoadLibraryA, or None.
pub fn resolve_api_set(dll_name: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    use crate::windows::{API_SET_NAMESPACE, API_SET_NAMESPACE_ENTRY, API_SET_VALUE_ENTRY};

    // Check prefix: "api-" or "ext-" (case-insensitive)
    if dll_name.len() < 4 {
        return None;
    }
    let prefix = [
        dll_name[0] | 0x20,
        dll_name[1] | 0x20,
        dll_name[2] | 0x20,
        dll_name[3],
    ];
    if prefix != *b"api-" && prefix != *b"ext-" {
        return None;
    }

    // Read PEB -> ApiSetMap
    let api_set_map: *const API_SET_NAMESPACE = unsafe {
        let peb: *mut u8;
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
        #[cfg(target_arch = "x86")]
        core::arch::asm!("mov {}, fs:[0x30]", out(reg) peb, options(nostack, preserves_flags));
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!("ldr {}, [x18, #0x60]", out(reg) peb, options(nostack, preserves_flags));

        let map_off: usize = if core::mem::size_of::<usize>() == 8 { 0x68 } else { 0x38 };
        *(peb.add(map_off) as *const *const API_SET_NAMESPACE)
    };

    if api_set_map.is_null() {
        return None;
    }

    let ns = unsafe { &*api_set_map };
    if ns.Version < 2 {
        return None;
    }

    // Build lookup key: strip ".dll" suffix and last "-N" segment, convert to lowercase wide
    let name_no_ext = if dll_name.len() > 4 {
        let lower4: [u8; 4] = [
            dll_name[dll_name.len() - 4] | 0x20,
            dll_name[dll_name.len() - 3] | 0x20,
            dll_name[dll_name.len() - 2] | 0x20,
            dll_name[dll_name.len() - 1] | 0x20,
        ];
        if lower4 == *b".dll" {
            &dll_name[..dll_name.len() - 4]
        } else {
            dll_name
        }
    } else {
        dll_name
    };

    // Strip last "-N" segment for the lookup key
    let lookup_key = if let Some(pos) = name_no_ext.iter().rposition(|&b| b == b'-') {
        &name_no_ext[..pos]
    } else {
        name_no_ext
    };

    // Linear search through namespace entries
    let base = api_set_map as *const u8;
    for i in 0..ns.Count {
        let entry_ptr = unsafe {
            base.add(ns.EntryOffset as usize + i as usize * core::mem::size_of::<API_SET_NAMESPACE_ENTRY>())
        } as *const API_SET_NAMESPACE_ENTRY;
        let entry = unsafe { &*entry_ptr };

        // Compare entry name (wide) with our lookup key (ascii)
        let entry_name_ptr = unsafe { base.add(entry.NameOffset as usize) } as *const u16;
        let entry_name_len = (entry.HashedLength as usize) / 2;

        if entry_name_len != lookup_key.len() {
            continue;
        }

        let mut matched = true;
        for j in 0..entry_name_len {
            let wide_char = unsafe { core::ptr::read_unaligned(entry_name_ptr.add(j)) } as u8;
            if (wide_char | 0x20) != (lookup_key[j] | 0x20) {
                matched = false;
                break;
            }
        }

        if !matched {
            continue;
        }

        // Found — read the first value entry
        if entry.ValueCount == 0 {
            return None;
        }

        let value_ptr = unsafe {
            base.add(entry.ValueOffset as usize)
        } as *const API_SET_VALUE_ENTRY;
        let value = unsafe { &*value_ptr };

        if value.ValueLength == 0 {
            return None;
        }

        // Convert wide host DLL name to ASCII null-terminated
        let host_ptr = unsafe { base.add(value.ValueOffset as usize) } as *const u16;
        let host_len = (value.ValueLength as usize) / 2;
        let mut result = alloc::vec::Vec::with_capacity(host_len + 1);
        for j in 0..host_len {
            let ch = unsafe { core::ptr::read_unaligned(host_ptr.add(j)) };
            if ch == 0 {
                break;
            }
            result.push(ch as u8);
        }
        result.push(0); // null terminator
        return Some(result);
    }

    None
}

// ---------------------------------------------------------------------------
// Security cookie initialization
// ---------------------------------------------------------------------------

/// Initializes __security_cookie from the Load Config directory.
/// PEs compiled with /GS need this to avoid false buffer overrun exceptions.
pub unsafe fn initialize_security_cookie(baseptr: *const c_void, ntheader: *const c_void) {
    let lc_dir = data_directory(ntheader, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
    if lc_dir.Size == 0 || lc_dir.VirtualAddress == 0 {
        return;
    }

    let lc_addr = baseptr as usize + lc_dir.VirtualAddress as usize;

    // Read the Size field (first u32 of the Load Config)
    let lc_size = core::ptr::read_unaligned(lc_addr as *const u32) as usize;

    // SecurityCookie VA offset differs by PE format:
    // PE32:  offset 60 in Load Config, needs lc_size >= 64
    // PE32+: offset 96 in Load Config, needs lc_size >= 104
    let cookie_va = if is_pe32(ntheader) {
        if lc_size < 64 {
            return;
        }
        core::ptr::read_unaligned((lc_addr + 60) as *const u32) as usize
    } else {
        if lc_size < 104 {
            return;
        }
        core::ptr::read_unaligned((lc_addr + 96) as *const u64) as usize
    };

    if cookie_va == 0 {
        return;
    }

    // Generate a pseudo-random value using rdtsc
    let random_value: usize;
    #[cfg(target_arch = "x86_64")]
    {
        let lo: u32;
        let hi: u32;
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack, preserves_flags));
        random_value = ((hi as u64) << 32 | lo as u64) as usize;
    }
    #[cfg(target_arch = "x86")]
    {
        let lo: u32;
        let hi: u32;
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack, preserves_flags));
        random_value = lo as usize ^ (hi as usize).wrapping_shl(16);
    }
    #[cfg(target_arch = "aarch64")]
    {
        let cnt: u64;
        core::arch::asm!("mrs {}, cntvct_el0", out(reg) cnt, options(nostack, preserves_flags));
        random_value = cnt as usize;
    }

    // Ensure the cookie value is not the default sentinel (0x00002B992DDFA232 for x64, 0xBB40E64E for x86)
    let cookie_value = if random_value == 0 || random_value == 0x00002B992DDFA232usize {
        random_value ^ 0xDEADBEEF
    } else {
        random_value
    };

    // Write the cookie
    if is_pe32(ntheader) {
        core::ptr::write_unaligned(cookie_va as *mut u32, cookie_value as u32);
    } else {
        core::ptr::write_unaligned(cookie_va as *mut u64, cookie_value as u64);
    }

    debug_log!("[runpe] Security cookie initialized at VA 0x{:X}\n", cookie_va);
}

// ---------------------------------------------------------------------------
// CFG (Control Flow Guard)
// ---------------------------------------------------------------------------

/// Registers valid CFG call targets for the loaded PE.
pub unsafe fn setup_cfg(baseptr: *const c_void, ntheader: *const c_void) {
    use crate::windows::{
        CFG_CALL_TARGET_INFO, CFG_CALL_TARGET_VALID, FnSetProcessValidCallTargets,
        IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT, IMAGE_GUARD_CF_INSTRUMENTED,
    };

    let lc_dir = data_directory(ntheader, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
    if lc_dir.Size == 0 || lc_dir.VirtualAddress == 0 {
        return;
    }

    let lc_addr = baseptr as usize + lc_dir.VirtualAddress as usize;
    let lc_size = core::ptr::read_unaligned(lc_addr as *const u32) as usize;

    // GuardFlags offset: PE32 = 88, PE32+ = 144
    // GuardCFFunctionTable offset: PE32 = 76, PE32+ = 128
    // GuardCFFunctionCount offset: PE32 = 80, PE32+ = 136
    let (guard_flags_off, table_off, count_off, min_size) = if is_pe32(ntheader) {
        (88usize, 76usize, 80usize, 92usize)
    } else {
        (144usize, 128usize, 136usize, 148usize)
    };

    if lc_size < min_size {
        return;
    }

    let guard_flags = core::ptr::read_unaligned((lc_addr + guard_flags_off) as *const u32);
    if guard_flags & IMAGE_GUARD_CF_INSTRUMENTED == 0 {
        return;
    }
    if guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT == 0 {
        return;
    }

    let func_table_va = if is_pe32(ntheader) {
        core::ptr::read_unaligned((lc_addr + table_off) as *const u32) as usize
    } else {
        core::ptr::read_unaligned((lc_addr + table_off) as *const u64) as usize
    };

    let func_count = if is_pe32(ntheader) {
        core::ptr::read_unaligned((lc_addr + count_off) as *const u32) as usize
    } else {
        core::ptr::read_unaligned((lc_addr + count_off) as *const u64) as usize
    };

    if func_table_va == 0 || func_count == 0 {
        return;
    }

    // The GuardCFG function table contains RVA entries (stride = 4 + extra bytes from GuardFlags >> 28)
    let extra_bytes = ((guard_flags >> 28) & 0xF) as usize;
    let stride = 4 + extra_bytes;

    // Dynamically load SetProcessValidCallTargets from kernelbase.dll
    let kernelbase = LoadLibraryA(b"kernelbase.dll\0".as_ptr());
    if kernelbase.is_null() {
        return;
    }

    let set_valid_fn = GetProcAddress(kernelbase, b"SetProcessValidCallTargets\0".as_ptr());
    if set_valid_fn.is_null() {
        return;
    }
    let set_valid: FnSetProcessValidCallTargets = core::mem::transmute(set_valid_fn);

    // Build CFG_CALL_TARGET_INFO array
    let mut targets = alloc::vec::Vec::with_capacity(func_count);
    for i in 0..func_count {
        let entry_addr = func_table_va + i * stride;
        let rva = core::ptr::read_unaligned(entry_addr as *const u32) as usize;
        targets.push(CFG_CALL_TARGET_INFO {
            Offset: rva,
            Flags: CFG_CALL_TARGET_VALID,
        });
    }

    // Get image size for region
    let img_size = if is_pe32(ntheader) {
        (*(ntheader as *const IMAGE_NT_HEADERS32)).OptionalHeader.SizeOfImage as usize
    } else {
        (*(ntheader as *const IMAGE_NT_HEADERS64)).OptionalHeader.SizeOfImage as usize
    };

    let process = crate::windows::GetCurrentProcess();
    set_valid(
        process,
        baseptr as *mut c_void,
        img_size,
        targets.len() as u32,
        targets.as_mut_ptr(),
    );

    // Set GuardCFCheckFunctionPointer to a no-op (ntdll!LdrpValidateUserCallTarget)
    // We read the address from ntdll to get the real validator
    let ntdll = LoadLibraryA(b"ntdll.dll\0".as_ptr());
    if !ntdll.is_null() {
        let validator = GetProcAddress(ntdll, b"LdrpValidateUserCallTarget\0".as_ptr());
        if !validator.is_null() {
            // GuardCFCheckFunctionPointer is at offset 112 (PE32+) or 72 (PE32) in Load Config
            let check_fn_off = if is_pe32(ntheader) { 72usize } else { 112usize };
            if lc_size > check_fn_off + core::mem::size_of::<usize>() {
                let check_fn_va = if is_pe32(ntheader) {
                    core::ptr::read_unaligned((lc_addr + check_fn_off) as *const u32) as usize
                } else {
                    core::ptr::read_unaligned((lc_addr + check_fn_off) as *const u64) as usize
                };
                if check_fn_va != 0 {
                    core::ptr::write_unaligned(
                        check_fn_va as *mut usize,
                        validator as usize,
                    );
                }
            }
        }
    }

    debug_log!("[runpe] CFG: registered {} valid call targets\n", func_count);
}

// ---------------------------------------------------------------------------
// Public data directory accessor (for lib.rs SxS check)
// ---------------------------------------------------------------------------

/// Public wrapper around data_directory for use by lib.rs.
pub unsafe fn data_directory_pub(
    ntheader: *const c_void,
    index: usize,
) -> crate::windows::IMAGE_DATA_DIRECTORY {
    data_directory(ntheader, index)
}

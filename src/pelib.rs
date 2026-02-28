use core::ffi::c_void;

use crate::windows::{
    GetProcAddress, LoadLibraryA, RtlAddFunctionTable, RtlDeleteFunctionTable, VirtualProtect,
    DLL_PROCESS_ATTACH, IMAGE_BASE_RELOCATION, IMAGE_DELAYLOAD_DESCRIPTOR,
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT,
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
pub fn get_headers_size(buffer: &[u8]) -> usize {
    if buffer.len() < 2 || buffer[0] != b'M' || buffer[1] != b'Z' {
        panic!("Not a PE file: missing MZ signature");
    }
    if buffer.len() < 0x40 {
        panic!("File too small for DOS header");
    }

    let offset = u32::from_le_bytes([buffer[60], buffer[61], buffer[62], buffer[63]]) as usize;

    if buffer.len() < offset + 4 + 20 + 2 {
        panic!("File too small to read optional header magic");
    }

    let magic = u16::from_le_bytes([buffer[offset + 4 + 20], buffer[offset + 4 + 20 + 1]]);
    match magic {
        IMAGE_NT_OPTIONAL_HDR64_MAGIC | IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
            // SizeOfHeaders is at OptionalHeader + 60 for both PE32 and PE32+
            let idx = offset + 24 + 60;
            if buffer.len() < idx + 4 {
                panic!("File too small to read SizeOfHeaders");
            }
            u32::from_le_bytes([
                buffer[idx],
                buffer[idx + 1],
                buffer[idx + 2],
                buffer[idx + 3],
            ]) as usize
        }
        _ => panic!("Invalid optional header magic: 0x{:04X}", magic),
    }
}

/// Returns the size of the PE image (SizeOfImage) from the raw buffer.
pub fn get_image_size(buffer: &[u8]) -> usize {
    if buffer.len() < 2 || buffer[0] != b'M' || buffer[1] != b'Z' {
        panic!("Not a PE file: missing MZ signature");
    }
    if buffer.len() < 0x40 {
        panic!("File too small for DOS header");
    }

    let offset = u32::from_le_bytes([buffer[60], buffer[61], buffer[62], buffer[63]]) as usize;

    if buffer.len() < offset + 4 + 20 + 2 {
        panic!("File too small to read optional header magic");
    }

    let magic = u16::from_le_bytes([buffer[offset + 4 + 20], buffer[offset + 4 + 20 + 1]]);
    match magic {
        IMAGE_NT_OPTIONAL_HDR64_MAGIC | IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
            // SizeOfImage is at OptionalHeader + 56 for both PE32 and PE32+
            let idx = offset + 24 + 56;
            if buffer.len() < idx + 4 {
                panic!("File too small to read SizeOfImage");
            }
            u32::from_le_bytes([
                buffer[idx],
                buffer[idx + 1],
                buffer[idx + 2],
                buffer[idx + 3],
            ]) as usize
        }
        _ => panic!("Invalid optional header magic: 0x{:04X}", magic),
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
) {
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
            section_ptr = unsafe { section_ptr.add(1) };
            continue;
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
pub fn fix_base_relocations(baseptr: *const c_void, ntheader: *const c_void) {
    let basereloc = unsafe { data_directory(ntheader, IMAGE_DIRECTORY_ENTRY_BASERELOC) };
    if basereloc.Size == 0 {
        return;
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
                _ => {}
            }
        }

        relocptr =
            unsafe { (relocptr as *const u8).add(block_size) as *const IMAGE_BASE_RELOCATION };
    }
}

// ---------------------------------------------------------------------------
// Import table resolution
// ---------------------------------------------------------------------------

/// Resolves imports for both PE32 and PE32+.
/// The thunk size differs: 4 bytes for PE32, 8 bytes for PE32+.
pub fn write_import_table(baseptr: *const c_void, ntheader: *const c_void) {
    let import_dir = unsafe { data_directory(ntheader, IMAGE_DIRECTORY_ENTRY_IMPORT) };
    if import_dir.Size == 0 {
        return;
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
        let dllhandle = unsafe { LoadLibraryA(dllname_ptr) };
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
}

// ---------------------------------------------------------------------------
// Per-section memory protections
// ---------------------------------------------------------------------------

/// Applies per-section memory protections using `VirtualProtect`.
pub unsafe fn change_memory_protection(
    baseptr: *const c_void,
    ntheader: *const c_void,
    dosheader: *const IMAGE_DOS_HEADER,
) {
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
        VirtualProtect(section_addr, virtual_size, new_protect, &mut old_protect);

        section_ptr = section_ptr.add(1);
    }
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
pub fn write_delayed_import_table(baseptr: *const c_void, ntheader: *const c_void) {
    let delay_dir = unsafe { data_directory(ntheader, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) };
    if delay_dir.Size == 0 {
        return;
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
        let dllhandle = unsafe { LoadLibraryA(dllname_ptr) };
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

/// Resolves an export by name from a reflectively-loaded PE image.
/// Returns a pointer to the function, or null if not found or forwarded.
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
                    return core::ptr::null_mut();
                }
                return (baseptr as usize + func_rva) as *mut c_void;
            }
            j += 1;
        }
    }

    core::ptr::null_mut()
}

/// Resolves an export by ordinal from a reflectively-loaded PE image.
/// Returns a pointer to the function, or null if not found or forwarded.
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
        return core::ptr::null_mut();
    }

    (baseptr as usize + func_rva) as *mut c_void
}

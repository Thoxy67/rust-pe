use alloc::string::String;
use alloc::vec::Vec;

/// This function converts a u8 array to a String, stopping at the first null byte.
///
/// # Arguments
///
/// * `arr` - A slice of u8 representing the array to convert.
///
/// # Returns
///
/// A String representing the converted array.
#[allow(unused)]
pub fn get_string_fromu8_array(arr: &[u8]) -> String {
    arr.iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as char)
        .collect()
}

/// This function converts an i8 array to a String, stopping at the first null byte.
///
/// # Arguments
///
/// * `arr` - A slice of i8 representing the array to convert.
///
/// # Returns
///
/// A String representing the converted array.
#[allow(unused)]
pub fn get_string_fromi8_array(arr: &[i8]) -> String {
    arr.iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8 as char)
        .collect()
}

/// Reads a null-terminated string from memory at the given address.
///
/// # Arguments
///
/// * `baseaddress` - A pointer to the base address of the string.
///
/// # Returns
///
/// A string containing the characters read from memory (without trailing nulls).
///
/// # Safety
///
/// The caller must ensure `baseaddress` points to valid, readable memory
/// containing a null-terminated string within 512 bytes.
pub fn read_string_from_memory(baseaddress: *const u8) -> String {
    const MAX_LEN: usize = 512;
    let mut len = 0usize;

    // Find the null terminator
    while len < MAX_LEN {
        let byte = unsafe { *baseaddress.add(len) };
        if byte == 0 {
            break;
        }
        len += 1;
    }

    // Build string from the valid bytes only (no trailing nulls)
    if len == 0 {
        return String::new();
    }

    let slice = unsafe { core::slice::from_raw_parts(baseaddress, len) };
    String::from_utf8_lossy(slice).into_owned()
}

/// Checks if a PE file is a .NET assembly by examining the CLR data directory
/// (IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, index 14).
///
/// This is the correct approach — matching how the Zig implementation checks
/// for .NET, rather than searching for ".NETFramework" byte patterns.
///
/// # Arguments
///
/// * `pe` - A byte slice of the PE file.
///
/// # Returns
///
/// `true` if the PE has a non-zero COM descriptor directory entry (i.e., is .NET).
pub fn check_dotnet(pe: &[u8]) -> bool {
    get_dotnet_version(pe).is_some()
}

/// Converts an RVA to a raw file offset using the PE section table.
///
/// Iterates through sections to find which section contains the RVA,
/// then calculates: file_offset = rva - section.VirtualAddress + section.PointerToRawData
pub fn rva_to_file_offset(pe: &[u8], rva: u32) -> Option<usize> {
    if pe.len() < 0x40 {
        return None;
    }
    let pe_offset = u32::from_le_bytes([pe[0x3C], pe[0x3D], pe[0x3E], pe[0x3F]]) as usize;
    if pe.len() < pe_offset + 6 {
        return None;
    }
    // Number of sections
    let num_sections = u16::from_le_bytes([pe[pe_offset + 6], pe[pe_offset + 7]]) as usize;
    // Size of optional header
    let size_of_opt = u16::from_le_bytes([pe[pe_offset + 20], pe[pe_offset + 21]]) as usize;
    // First section header offset
    let section_start = pe_offset + 24 + size_of_opt;

    for i in 0..num_sections {
        let sh = section_start + i * 40;
        if pe.len() < sh + 40 {
            return None;
        }
        let virtual_size = u32::from_le_bytes([pe[sh + 8], pe[sh + 9], pe[sh + 10], pe[sh + 11]]);
        let virtual_addr = u32::from_le_bytes([pe[sh + 12], pe[sh + 13], pe[sh + 14], pe[sh + 15]]);
        let raw_data_ptr = u32::from_le_bytes([pe[sh + 20], pe[sh + 21], pe[sh + 22], pe[sh + 23]]);

        if rva >= virtual_addr && rva < virtual_addr + virtual_size {
            return Some((rva - virtual_addr + raw_data_ptr) as usize);
        }
    }
    None
}

/// Extracts the .NET runtime version string from PE metadata.
///
/// Reads COR20 header → metadata RVA → BSJB signature → version string.
/// Returns the version string bytes (e.g., b"v4.0.30319") without null padding.
pub fn get_dotnet_version(pe: &[u8]) -> Option<&[u8]> {
    if pe.len() < 0x40 {
        return None;
    }
    let pe_offset = u32::from_le_bytes([pe[0x3C], pe[0x3D], pe[0x3E], pe[0x3F]]) as usize;
    if pe.len() < pe_offset + 24 + 2 {
        return None;
    }
    let magic = u16::from_le_bytes([pe[pe_offset + 24], pe[pe_offset + 25]]);

    // Get COM_DESCRIPTOR (index 14) data directory
    let data_dir_offset = match magic {
        crate::windows::IMAGE_NT_OPTIONAL_HDR32_MAGIC => pe_offset + 24 + 96,
        crate::windows::IMAGE_NT_OPTIONAL_HDR64_MAGIC => pe_offset + 24 + 112,
        _ => return None,
    };
    let clr_dir_offset = data_dir_offset + 14 * 8;
    if pe.len() < clr_dir_offset + 8 {
        return None;
    }

    let cor20_rva = u32::from_le_bytes([
        pe[clr_dir_offset],
        pe[clr_dir_offset + 1],
        pe[clr_dir_offset + 2],
        pe[clr_dir_offset + 3],
    ]);
    if cor20_rva == 0 {
        return None;
    }

    // Convert COR20 header RVA to file offset
    let cor20_off = rva_to_file_offset(pe, cor20_rva)?;
    if pe.len() < cor20_off + 16 {
        return None;
    }

    // COR20 header: offset +8 = MetaData RVA (u32), offset +12 = MetaData Size (u32)
    let metadata_rva = u32::from_le_bytes([
        pe[cor20_off + 8],
        pe[cor20_off + 9],
        pe[cor20_off + 10],
        pe[cor20_off + 11],
    ]);

    // Convert metadata RVA to file offset
    let metadata_off = rva_to_file_offset(pe, metadata_rva)?;
    if pe.len() < metadata_off + 16 {
        return None;
    }

    // Verify BSJB magic (0x424A5342)
    let bsjb = u32::from_le_bytes([
        pe[metadata_off],
        pe[metadata_off + 1],
        pe[metadata_off + 2],
        pe[metadata_off + 3],
    ]);
    if bsjb != 0x424A5342 {
        return None;
    }

    // Version string length at offset +12
    let ver_len = u32::from_le_bytes([
        pe[metadata_off + 12],
        pe[metadata_off + 13],
        pe[metadata_off + 14],
        pe[metadata_off + 15],
    ]) as usize;
    if ver_len == 0 || pe.len() < metadata_off + 16 + ver_len {
        return None;
    }

    // Version string at offset +16, trim trailing nulls
    let ver_bytes = &pe[metadata_off + 16..metadata_off + 16 + ver_len];
    let trimmed_len = ver_bytes.iter().position(|&b| b == 0).unwrap_or(ver_len);
    Some(&ver_bytes[..trimmed_len])
}

/// Converts an ASCII byte slice to a null-terminated UTF-16LE Vec for COM APIs.
pub fn ascii_to_wide(s: &[u8]) -> Vec<u16> {
    let mut wide: Vec<u16> = s.iter().map(|&b| b as u16).collect();
    wide.push(0);
    wide
}

/// Detects the platform of a PE file (32 or 64 bit).
///
/// # Arguments
///
/// * `bytes` - A slice containing the bytes of the PE file.
///
/// # Returns
///
/// An `Option` containing the platform (32 or 64), or `None` if invalid.
pub fn detect_platform(bytes: &[u8]) -> Option<u32> {
    // Check minimum size and MZ signature
    if bytes.len() < 0x40 {
        return None;
    }
    if bytes.get(0..2) != Some(&[0x4D, 0x5A]) {
        return None;
    }

    // Calculate the offset to the PE header from the DOS header
    let pe_offset = u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]);

    // Check that the PE header starts with the "PE\0\0" signature
    if bytes.get(pe_offset as usize..pe_offset as usize + 4) != Some(&[0x50, 0x45, 0x00, 0x00]) {
        return None;
    }

    // Determine the machine type from the "Machine" field in the PE header
    let machine =
        u16::from_le_bytes([bytes[pe_offset as usize + 4], bytes[pe_offset as usize + 5]]);
    match machine {
        0x014c => Some(32), // IMAGE_FILE_MACHINE_I386
        0x0200 => Some(64), // IMAGE_FILE_MACHINE_IA64
        0x8664 => Some(64), // IMAGE_FILE_MACHINE_AMD64
        0x01C4 => Some(32), // IMAGE_FILE_MACHINE_ARMNT
        0xAA64 => Some(64), // IMAGE_FILE_MACHINE_ARM64
        _ => None,
    }
}

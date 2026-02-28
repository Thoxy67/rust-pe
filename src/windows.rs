#![allow(non_snake_case, non_camel_case_types)]

use core::ffi::c_void;

// --- Type aliases ---
pub type VIRTUAL_ALLOCATION_TYPE = u32;
pub type PAGE_PROTECTION_FLAGS = u32;
pub type DWORD = u32;
pub type HANDLE = *mut c_void;
pub type LPTHREAD_START_ROUTINE = unsafe extern "system" fn(*mut c_void) -> u32;

// --- Memory allocation constants ---
pub const MEM_COMMIT: VIRTUAL_ALLOCATION_TYPE = 0x1000;
pub const MEM_RESERVE: VIRTUAL_ALLOCATION_TYPE = 0x2000;
pub const MEM_RELEASE: VIRTUAL_ALLOCATION_TYPE = 0x8000;

// --- Page protection constants ---
pub const PAGE_READONLY: PAGE_PROTECTION_FLAGS = 0x02;
pub const PAGE_READWRITE: PAGE_PROTECTION_FLAGS = 0x04;
pub const PAGE_EXECUTE_READ: PAGE_PROTECTION_FLAGS = 0x20;
pub const PAGE_EXECUTE_READWRITE: PAGE_PROTECTION_FLAGS = 0x40;

// --- PE directory entry indices ---
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

// --- Relocation types ---
pub const IMAGE_REL_BASED_ABSOLUTE: u32 = 0;
pub const IMAGE_REL_BASED_HIGHLOW: u32 = 3;
pub const IMAGE_REL_BASED_ARM_MOV32: u32 = 5;
pub const IMAGE_REL_BASED_THUMB_MOV32: u32 = 7;
pub const IMAGE_REL_BASED_DIR64: u32 = 10;

// --- PE signature ---
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"

// --- PE optional header magic ---
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x010B;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020B;

// --- Section characteristics ---
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

// --- Thread / sync constants ---
pub const INFINITE: u32 = 0xFFFF_FFFF;
pub const WAIT_OBJECT_0: u32 = 0x0000_0000;

// --- Ordinal import flags ---
pub const IMAGE_ORDINAL_FLAG64: usize = 1 << 63;
pub const IMAGE_ORDINAL_FLAG32: usize = 1 << 31;

#[link(name = "kernel32")]
extern "system" {
    pub fn VirtualAlloc(
        lpaddress: *const c_void,
        dwsize: usize,
        flallocationtype: VIRTUAL_ALLOCATION_TYPE,
        flprotect: PAGE_PROTECTION_FLAGS,
    ) -> *mut c_void;

    pub fn VirtualFree(
        lpaddress: *mut c_void,
        dwsize: usize,
        dwfreetype: VIRTUAL_ALLOCATION_TYPE,
    ) -> i32;

    pub fn VirtualProtect(
        lpaddress: *const c_void,
        dwsize: usize,
        flnewprotect: PAGE_PROTECTION_FLAGS,
        lpfloldprotect: *mut PAGE_PROTECTION_FLAGS,
    ) -> i32;

    pub fn GetProcAddress(hmodule: *mut c_void, lpprocname: *const u8) -> *mut c_void;

    pub fn LoadLibraryA(lplibfilename: *const u8) -> *mut c_void;

    pub fn CreateThread(
        lpthreadattributes: *const c_void,
        dwstacksize: usize,
        lpstartaddress: LPTHREAD_START_ROUTINE,
        lpparameter: *mut c_void,
        dwcreationflags: u32,
        lpthreadid: *mut u32,
    ) -> HANDLE;

    pub fn WaitForSingleObject(hhandle: HANDLE, dwmilliseconds: u32) -> u32;

    pub fn CloseHandle(hobject: HANDLE) -> i32;
}

#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

#[derive(Default)]
#[repr(C)]
pub struct IMAGE_NT_HEADERS32 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER32,
}

#[derive(Default)]
#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER32 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub BaseOfData: u32,
    pub ImageBase: u32,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u32,
    pub SizeOfStackCommit: u32,
    pub SizeOfHeapReserve: u32,
    pub SizeOfHeapCommit: u32,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[derive(Default)]
#[repr(C, packed(4))]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct IMAGE_BASE_RELOCATION {
    pub VirtualAddress: u32,
    pub SizeOfBlock: u32,
}
#[derive(Clone, Copy)]
#[repr(C)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [u8; 8],
    pub Misc: IMAGE_SECTION_HEADER_0,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: u32,
}
#[derive(Clone, Copy)]
#[repr(C)]
pub union IMAGE_SECTION_HEADER_0 {
    pub PhysicalAddress: u32,
    pub VirtualSize: u32,
}

#[derive(Clone, Copy)]
#[repr(C, packed(2))]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
pub struct IMAGE_IMPORT_DESCRIPTOR {
    pub Anonymous: IMAGE_IMPORT_DESCRIPTOR_0,
    pub TimeDateStamp: u32,
    pub ForwarderChain: u32,
    pub Name: u32,
    pub FirstThunk: u32,
}

#[repr(C)]
pub union IMAGE_IMPORT_DESCRIPTOR_0 {
    pub Characteristics: u32,
    pub OriginalFirstThunk: u32,
}

// ============================================================================
// Delay-load import descriptor
// ============================================================================

#[repr(C)]
pub struct IMAGE_DELAYLOAD_DESCRIPTOR {
    pub Attributes: u32,
    pub DllNameRVA: u32,
    pub ModuleHandleRVA: u32,
    pub ImportAddressTableRVA: u32,
    pub ImportNameTableRVA: u32,
    pub BoundImportAddressTableRVA: u32,
    pub UnloadInformationTableRVA: u32,
    pub TimeDateStamp: u32,
}

// ============================================================================
// Exception table (PDATA)
// ============================================================================

#[repr(C)]
pub struct RUNTIME_FUNCTION {
    pub BeginAddress: u32,
    pub EndAddress: u32,
    pub UnwindData: u32,
}

#[link(name = "kernel32")]
extern "system" {
    pub fn RtlAddFunctionTable(
        FunctionTable: *const RUNTIME_FUNCTION,
        EntryCount: u32,
        BaseAddress: u64,
    ) -> u8;

    pub fn RtlDeleteFunctionTable(FunctionTable: *const RUNTIME_FUNCTION) -> u8;
}

// ============================================================================
// TLS (Thread Local Storage)
// ============================================================================

pub const DLL_PROCESS_ATTACH: u32 = 1;

pub type PIMAGE_TLS_CALLBACK =
    unsafe extern "system" fn(DllHandle: *mut c_void, Reason: u32, Reserved: *mut c_void);

#[repr(C)]
pub struct IMAGE_TLS_DIRECTORY32 {
    pub StartAddressOfRawData: u32,
    pub EndAddressOfRawData: u32,
    pub AddressOfIndex: u32,
    pub AddressOfCallBacks: u32,
    pub SizeOfZeroFill: u32,
    pub Characteristics: u32,
}

#[repr(C)]
pub struct IMAGE_TLS_DIRECTORY64 {
    pub StartAddressOfRawData: u64,
    pub EndAddressOfRawData: u64,
    pub AddressOfIndex: u64,
    pub AddressOfCallBacks: u64,
    pub SizeOfZeroFill: u32,
    pub Characteristics: u32,
}

// ============================================================================
// Export table
// ============================================================================

#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub Name: u32,
    pub Base: u32,
    pub NumberOfFunctions: u32,
    pub NumberOfNames: u32,
    pub AddressOfFunctions: u32,
    pub AddressOfNames: u32,
    pub AddressOfNameOrdinals: u32,
}

// ============================================================================
// COM / CLR types for .NET assembly loading
// ============================================================================

pub type HRESULT = i32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

#[repr(C)]
pub struct SAFEARRAYBOUND {
    pub c_elements: u32,
    pub l_lbound: i32,
}

#[repr(C)]
pub struct SAFEARRAY {
    pub c_dims: u16,
    pub f_features: u16,
    pub cb_elements: u32,
    pub c_locks: u32,
    pub pv_data: *mut c_void,
    pub rgsabound: [SAFEARRAYBOUND; 1],
}

/// VARIANT structure (COM automation). 24 bytes on x64.
#[repr(C)]
pub struct VARIANT {
    pub vt: u16,
    pub w_reserved1: u16,
    pub w_reserved2: u16,
    pub w_reserved3: u16,
    pub data: VariantData,
}

/// Union portion of VARIANT — 16 bytes on x64 (largest member is BRECORD: two pointers).
#[repr(C)]
pub union VariantData {
    pub ptr_val: *mut c_void,
    pub uint_val: usize,
    pub int_val: isize,
    pub _pad: [u8; 16],
}

pub const VT_EMPTY: u16 = 0;
pub const VT_UI1: u16 = 17;
pub const VT_BSTR: u16 = 8;
pub const VT_ARRAY: u16 = 0x2000;
pub const VT_VARIANT: u16 = 12;
// --- COM vtable structs ---

/// IUnknown vtable (3 slots)
#[repr(C)]
pub struct IUnknownVtbl {
    pub QueryInterface: unsafe extern "system" fn(
        this: *mut c_void,
        riid: *const GUID,
        ppv_object: *mut *mut c_void,
    ) -> HRESULT,
    pub AddRef: unsafe extern "system" fn(this: *mut c_void) -> u32,
    pub Release: unsafe extern "system" fn(this: *mut c_void) -> u32,
}

/// ICLRMetaHost vtable — IUnknown(3) + GetRuntime at slot 3
#[repr(C)]
pub struct ICLRMetaHostVtbl {
    pub base: IUnknownVtbl,
    pub GetRuntime: unsafe extern "system" fn(
        this: *mut c_void,
        pwz_version: *const u16,
        riid: *const GUID,
        pp_runtime: *mut *mut c_void,
    ) -> HRESULT,
}

/// ICLRRuntimeInfo vtable — IUnknown(3) + 6 padding + GetInterface at slot 9
#[repr(C)]
pub struct ICLRRuntimeInfoVtbl {
    pub base: IUnknownVtbl,
    pub _pad0: usize,
    pub _pad1: usize,
    pub _pad2: usize,
    pub _pad3: usize,
    pub _pad4: usize,
    pub _pad5: usize,
    pub GetInterface: unsafe extern "system" fn(
        this: *mut c_void,
        rclsid: *const GUID,
        riid: *const GUID,
        pp_unk: *mut *mut c_void,
    ) -> HRESULT,
}

/// ICorRuntimeHost vtable — IUnknown(3) + 7 padding + Start(10) + pad(11,12) + GetDefaultDomain(13)
#[repr(C)]
pub struct ICorRuntimeHostVtbl {
    pub base: IUnknownVtbl,
    pub _pad0: usize,                                                   // slot 3
    pub _pad1: usize,                                                   // slot 4
    pub _pad2: usize,                                                   // slot 5
    pub _pad3: usize,                                                   // slot 6
    pub _pad4: usize,                                                   // slot 7
    pub _pad5: usize,                                                   // slot 8
    pub _pad6: usize,                                                   // slot 9
    pub Start: unsafe extern "system" fn(this: *mut c_void) -> HRESULT, // slot 10
    pub _pad7: usize,                                                   // slot 11
    pub _pad8: usize,                                                   // slot 12
    pub GetDefaultDomain:
        unsafe extern "system" fn(this: *mut c_void, p_app_domain: *mut *mut c_void) -> HRESULT, // slot 13
}

/// _AppDomain vtable — IDispatch(7) + ... + Load_3 at slot 45
#[repr(C)]
pub struct AppDomainVtbl {
    pub _slots: [usize; 45],
    pub Load_3: unsafe extern "system" fn(
        this: *mut c_void,
        raw_assembly: *mut SAFEARRAY,
        pp_assembly: *mut *mut c_void,
    ) -> HRESULT,
}

/// _Assembly vtable — IDispatch(7) + 9 methods + get_EntryPoint at slot 16
#[repr(C)]
pub struct AssemblyVtbl {
    pub _slots: [usize; 16],
    pub get_EntryPoint:
        unsafe extern "system" fn(this: *mut c_void, pp_method_info: *mut *mut c_void) -> HRESULT,
}

/// _MethodInfo vtable — IDispatch(7) + 30 methods + Invoke_3 at slot 37
#[repr(C)]
pub struct MethodInfoVtbl {
    pub _slots: [usize; 37],
    pub Invoke_3: unsafe extern "system" fn(
        this: *mut c_void,
        obj: VARIANT,
        parameters: *mut SAFEARRAY,
        ret: *mut VARIANT,
    ) -> HRESULT,
}

// --- GUID constants ---

pub const CLSID_CLR_META_HOST: GUID = GUID {
    data1: 0x9280188D,
    data2: 0x0E8E,
    data3: 0x4867,
    data4: [0xB3, 0x0C, 0x7F, 0xA8, 0x38, 0x84, 0xE8, 0xDE],
};

pub const IID_ICLR_META_HOST: GUID = GUID {
    data1: 0xD332DB9E,
    data2: 0xB9B3,
    data3: 0x4125,
    data4: [0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16],
};

pub const CLSID_COR_RUNTIME_HOST: GUID = GUID {
    data1: 0xCB2F6723,
    data2: 0xAB3A,
    data3: 0x11D2,
    data4: [0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E],
};

pub const IID_ICOR_RUNTIME_HOST: GUID = GUID {
    data1: 0xCB2F6722,
    data2: 0xAB3A,
    data3: 0x11D2,
    data4: [0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E],
};

pub const IID_ICLR_RUNTIME_INFO: GUID = GUID {
    data1: 0xBD39D1D2,
    data2: 0xBA2F,
    data3: 0x486A,
    data4: [0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91],
};

pub const IID_APP_DOMAIN: GUID = GUID {
    data1: 0x05F696DC,
    data2: 0x2B29,
    data3: 0x3663,
    data4: [0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13],
};

/// Function pointer type for CLRCreateInstance
pub type FnCLRCreateInstance = unsafe extern "system" fn(
    clsid: *const GUID,
    riid: *const GUID,
    pp_interface: *mut *mut c_void,
) -> HRESULT;

/// Function pointer type for SafeArrayCreate
pub type FnSafeArrayCreate = unsafe extern "system" fn(
    vt: u16,
    c_dims: u32,
    rgsabound: *mut SAFEARRAYBOUND,
) -> *mut SAFEARRAY;

/// Function pointer type for SafeArrayAccessData
pub type FnSafeArrayAccessData =
    unsafe extern "system" fn(psa: *mut SAFEARRAY, pp_data: *mut *mut c_void) -> HRESULT;

/// Function pointer type for SafeArrayUnaccessData
pub type FnSafeArrayUnaccessData = unsafe extern "system" fn(psa: *mut SAFEARRAY) -> HRESULT;

/// Function pointer type for SafeArrayDestroy
pub type FnSafeArrayDestroy = unsafe extern "system" fn(psa: *mut SAFEARRAY) -> HRESULT;

/// Function pointer type for SysAllocString
pub type FnSysAllocString = unsafe extern "system" fn(psz: *const u16) -> *mut u16;

use core::ffi::c_void;
use core::ptr;

use crate::utils;
use crate::windows::*;

fn empty_variant() -> VARIANT {
    VARIANT {
        vt: VT_EMPTY,
        w_reserved1: 0,
        w_reserved2: 0,
        w_reserved3: 0,
        data: VariantData {
            ptr_val: ptr::null_mut(),
        },
    }
}

/// Calls IUnknown::Release on a COM interface pointer.
unsafe fn release_com(punk: *mut c_void) {
    if !punk.is_null() {
        let vtbl = *(punk as *const *const IUnknownVtbl);
        ((*vtbl).Release)(punk);
    }
}

/// Creates a SAFEARRAY(VT_UI1) wrapping the given byte buffer.
unsafe fn create_safearray_from_bytes(
    buffer: &[u8],
    sa_create: FnSafeArrayCreate,
    sa_access: FnSafeArrayAccessData,
    sa_unaccess: FnSafeArrayUnaccessData,
) -> *mut SAFEARRAY {
    let mut bound = SAFEARRAYBOUND {
        c_elements: buffer.len() as u32,
        l_lbound: 0,
    };
    let sa = sa_create(VT_UI1, 1, &mut bound);
    if sa.is_null() {
        return ptr::null_mut();
    }

    let mut pv_data: *mut c_void = ptr::null_mut();
    let hr = sa_access(sa, &mut pv_data);
    if hr < 0 || pv_data.is_null() {
        return sa;
    }
    ptr::copy_nonoverlapping(buffer.as_ptr(), pv_data as *mut u8, buffer.len());
    sa_unaccess(sa);
    sa
}

/// Creates a SAFEARRAY of VARIANTs containing BSTR arguments for Main(string[] args).
///
/// Returns the outer SAFEARRAY (1 element = one VARIANT holding VT_ARRAY|VT_BSTR).
unsafe fn create_args_safearray(
    args: &[&str],
    sa_create: FnSafeArrayCreate,
    sa_access: FnSafeArrayAccessData,
    sa_unaccess: FnSafeArrayUnaccessData,
    sys_alloc: FnSysAllocString,
) -> *mut SAFEARRAY {
    // Build inner SAFEARRAY of BSTRs
    let mut bstr_bound = SAFEARRAYBOUND {
        c_elements: args.len() as u32,
        l_lbound: 0,
    };
    let bstr_sa = sa_create(VT_BSTR, 1, &mut bstr_bound);
    if bstr_sa.is_null() {
        return ptr::null_mut();
    }

    let mut bstr_data: *mut c_void = ptr::null_mut();
    if sa_access(bstr_sa, &mut bstr_data) < 0 {
        return ptr::null_mut();
    }
    let bstr_arr = bstr_data as *mut *mut u16;
    for (i, arg) in args.iter().enumerate() {
        let wide = utils::ascii_to_wide(arg.as_bytes());
        let bstr = sys_alloc(wide.as_ptr());
        *bstr_arr.add(i) = bstr;
    }
    sa_unaccess(bstr_sa);

    // Wrap in a VARIANT (VT_ARRAY | VT_BSTR)
    // Build outer SAFEARRAY of 1 VARIANT
    let mut outer_bound = SAFEARRAYBOUND {
        c_elements: 1,
        l_lbound: 0,
    };
    let outer_sa = sa_create(VT_VARIANT, 1, &mut outer_bound);
    if outer_sa.is_null() {
        return ptr::null_mut();
    }
    let mut outer_data: *mut c_void = ptr::null_mut();
    if sa_access(outer_sa, &mut outer_data) < 0 {
        return ptr::null_mut();
    }
    let var_ptr = outer_data as *mut VARIANT;
    ptr::write(
        var_ptr,
        VARIANT {
            vt: VT_ARRAY | VT_BSTR,
            w_reserved1: 0,
            w_reserved2: 0,
            w_reserved3: 0,
            data: VariantData {
                ptr_val: bstr_sa as *mut c_void,
            },
        },
    );
    sa_unaccess(outer_sa);
    outer_sa
}

/// Loads and executes a .NET assembly from a raw PE buffer using CLR hosting.
///
/// # Arguments
///
/// * `buffer` - The raw bytes of the .NET PE assembly.
/// * `args` - Command-line arguments to pass to Main(string[] args).
///
/// # Safety
///
/// Calls Windows COM APIs, loads the CLR, and executes arbitrary .NET code.
pub unsafe fn execute_dotnet_assembly(buffer: &[u8], args: &[&str]) {
    // --- Dynamic-load mscoree.dll and oleaut32.dll ---
    let mscoree = LoadLibraryA(b"mscoree.dll\0".as_ptr());
    if mscoree.is_null() {
        panic!(".NET: failed to load mscoree.dll");
    }
    let oleaut32 = LoadLibraryA(b"oleaut32.dll\0".as_ptr());
    if oleaut32.is_null() {
        panic!(".NET: failed to load oleaut32.dll");
    }

    let p_clr_create = GetProcAddress(mscoree, b"CLRCreateInstance\0".as_ptr());
    if p_clr_create.is_null() {
        panic!(".NET: CLRCreateInstance not found");
    }
    let clr_create_instance: FnCLRCreateInstance = core::mem::transmute(p_clr_create);

    let sa_create: FnSafeArrayCreate =
        core::mem::transmute(GetProcAddress(oleaut32, b"SafeArrayCreate\0".as_ptr()));
    let sa_access: FnSafeArrayAccessData =
        core::mem::transmute(GetProcAddress(oleaut32, b"SafeArrayAccessData\0".as_ptr()));
    let sa_unaccess: FnSafeArrayUnaccessData = core::mem::transmute(GetProcAddress(
        oleaut32,
        b"SafeArrayUnaccessData\0".as_ptr(),
    ));
    let sa_destroy: FnSafeArrayDestroy =
        core::mem::transmute(GetProcAddress(oleaut32, b"SafeArrayDestroy\0".as_ptr()));
    let sys_alloc: FnSysAllocString =
        core::mem::transmute(GetProcAddress(oleaut32, b"SysAllocString\0".as_ptr()));

    // --- Extract .NET version from PE metadata ---
    let version = match utils::get_dotnet_version(buffer) {
        Some(v) => v,
        None => panic!(".NET: could not extract runtime version from PE metadata"),
    };
    let version_wide = utils::ascii_to_wide(version);

    // --- COM chain: MetaHost -> RuntimeInfo -> RuntimeHost ---
    let mut meta_host: *mut c_void = ptr::null_mut();
    let hr = clr_create_instance(&CLSID_CLR_META_HOST, &IID_ICLR_META_HOST, &mut meta_host);
    if hr < 0 || meta_host.is_null() {
        panic!(".NET: CLRCreateInstance failed (0x{:08X})", hr as u32);
    }

    let mut runtime_info: *mut c_void = ptr::null_mut();
    let meta_vtbl = *(meta_host as *const *const ICLRMetaHostVtbl);
    let hr = ((*meta_vtbl).GetRuntime)(
        meta_host,
        version_wide.as_ptr(),
        &IID_ICLR_RUNTIME_INFO,
        &mut runtime_info,
    );
    if hr < 0 || runtime_info.is_null() {
        release_com(meta_host);
        panic!(".NET: GetRuntime failed (0x{:08X})", hr as u32);
    }

    let mut runtime_host: *mut c_void = ptr::null_mut();
    let ri_vtbl = *(runtime_info as *const *const ICLRRuntimeInfoVtbl);
    let hr = ((*ri_vtbl).GetInterface)(
        runtime_info,
        &CLSID_COR_RUNTIME_HOST,
        &IID_ICOR_RUNTIME_HOST,
        &mut runtime_host,
    );
    if hr < 0 || runtime_host.is_null() {
        release_com(runtime_info);
        release_com(meta_host);
        panic!(
            ".NET: GetInterface for ICorRuntimeHost failed (0x{:08X})",
            hr as u32
        );
    }

    // --- Start CLR and get default AppDomain ---
    let rh_vtbl = *(runtime_host as *const *const ICorRuntimeHostVtbl);
    let hr = ((*rh_vtbl).Start)(runtime_host);
    if hr < 0 {
        release_com(runtime_host);
        release_com(runtime_info);
        release_com(meta_host);
        panic!(".NET: ICorRuntimeHost::Start failed (0x{:08X})", hr as u32);
    }

    let mut app_domain_unk: *mut c_void = ptr::null_mut();
    let hr = ((*rh_vtbl).GetDefaultDomain)(runtime_host, &mut app_domain_unk);
    if hr < 0 || app_domain_unk.is_null() {
        release_com(runtime_host);
        release_com(runtime_info);
        release_com(meta_host);
        panic!(".NET: GetDefaultDomain failed (0x{:08X})", hr as u32);
    }

    // QI for _AppDomain
    let mut app_domain: *mut c_void = ptr::null_mut();
    let unk_vtbl = *(app_domain_unk as *const *const IUnknownVtbl);
    let hr = ((*unk_vtbl).QueryInterface)(app_domain_unk, &IID_APP_DOMAIN, &mut app_domain);
    release_com(app_domain_unk);
    if hr < 0 || app_domain.is_null() {
        release_com(runtime_host);
        release_com(runtime_info);
        release_com(meta_host);
        panic!(
            ".NET: QueryInterface for _AppDomain failed (0x{:08X})",
            hr as u32
        );
    }

    // --- Load assembly from byte array ---
    let byte_sa = create_safearray_from_bytes(buffer, sa_create, sa_access, sa_unaccess);
    if byte_sa.is_null() {
        release_com(app_domain);
        release_com(runtime_host);
        release_com(runtime_info);
        release_com(meta_host);
        panic!(".NET: failed to create SafeArray for assembly bytes");
    }

    let ad_vtbl = *(app_domain as *const *const AppDomainVtbl);
    let mut assembly: *mut c_void = ptr::null_mut();
    let hr = ((*ad_vtbl).Load_3)(app_domain, byte_sa, &mut assembly);
    sa_destroy(byte_sa);
    if hr < 0 || assembly.is_null() {
        release_com(app_domain);
        release_com(runtime_host);
        release_com(runtime_info);
        release_com(meta_host);
        panic!(".NET: _AppDomain::Load_3 failed (0x{:08X})", hr as u32);
    }

    // --- Get entry point MethodInfo ---
    let asm_vtbl = *(assembly as *const *const AssemblyVtbl);
    let mut method_info: *mut c_void = ptr::null_mut();
    let hr = ((*asm_vtbl).get_EntryPoint)(assembly, &mut method_info);
    if hr < 0 || method_info.is_null() {
        release_com(assembly);
        release_com(app_domain);
        release_com(runtime_host);
        release_com(runtime_info);
        release_com(meta_host);
        panic!(
            ".NET: _Assembly::get_EntryPoint failed (0x{:08X})",
            hr as u32
        );
    }

    // --- Invoke entry point ---
    let mi_vtbl = *(method_info as *const *const MethodInfoVtbl);

    let obj = empty_variant();
    let mut ret_val = empty_variant();

    let params_sa = create_args_safearray(args, sa_create, sa_access, sa_unaccess, sys_alloc);

    let hr = ((*mi_vtbl).Invoke_3)(method_info, obj, params_sa, &mut ret_val);

    // Cleanup
    if !params_sa.is_null() {
        sa_destroy(params_sa);
    }
    release_com(method_info);
    release_com(assembly);
    release_com(app_domain);
    release_com(runtime_host);
    release_com(runtime_info);
    release_com(meta_host);

    if hr < 0 {
        panic!(".NET: _MethodInfo::Invoke_3 failed (0x{:08X})", hr as u32);
    }
}

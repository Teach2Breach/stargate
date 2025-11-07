use crate::signature::{FunctionSignature, SignatureDatabase, SignatureError};
use byont::*;

/// Extract all function signatures from a DLL
pub fn extract_all_signatures(
    dll_name: &str,
    signature_length: usize,
) -> Result<SignatureDatabase, SignatureError> {
    let mut dll_name_clean = dll_name.to_lowercase();
    if dll_name_clean.ends_with(".dll") {
        dll_name_clean = dll_name_clean.trim_end_matches(".dll").to_string();
    }
    let dll_name_full = format!("{}.dll", dll_name_clean);

    // Get clean DLL
    let clean_dll = get_clean_dll(&dll_name_clean)
        .ok_or_else(|| SignatureError::DllNotFound(dll_name_clean.clone()))?;

    // Allocate executable memory and copy the DLL into it
    let (memory, size) = allocate_executable_memory(&clean_dll)
        .ok_or(SignatureError::MemoryAllocationFailed)?;

    // Copy security directory
    let _ = copy_security_directory_raw(memory, size, &dll_name_full);

    // Verify security directory
    let _ = verify_security_directory_raw(memory, size);

    // Apply relocations
    let (clean_base, _ntdll_base, _delta) = apply_relocations_raw(memory, size)
        .ok_or(SignatureError::RelocationFailed)?;

    // Get all exported function names
    let function_names = get_all_export_names(memory);
    if function_names.is_empty() {
        free_executable_memory(memory);
        return Err(SignatureError::NoExportDirectory);
    }

    // Create signature database
    let mut database = SignatureDatabase::new();

    // Extract signatures for all functions
    for func_name in function_names {
        if let Some((signature_bytes, function_rva)) =
            extract_function_signature(memory, clean_base, &func_name, signature_length)
        {
            let signature = FunctionSignature::new(
                dll_name_clean.clone(),
                func_name,
                "dynamic".to_string(), // Version will be detected by byont
                signature_bytes,
                function_rva,
            );
            database.add_signature(signature);
        }
    }

    // Cleanup
    free_executable_memory(memory);

    Ok(database)
}

/// Extract a single function signature from a DLL
pub fn extract_single_signature(
    dll_name: &str,
    function_name: &str,
    signature_length: usize,
) -> Result<Option<FunctionSignature>, SignatureError> {
    let mut dll_name_clean = dll_name.to_lowercase();
    if dll_name_clean.ends_with(".dll") {
        dll_name_clean = dll_name_clean.trim_end_matches(".dll").to_string();
    }

    // Get clean DLL
    let clean_dll = get_clean_dll(&dll_name_clean)
        .ok_or_else(|| SignatureError::DllNotFound(dll_name_clean.clone()))?;

    // Allocate executable memory and copy the DLL into it
    let (memory, size) = allocate_executable_memory(&clean_dll)
        .ok_or(SignatureError::MemoryAllocationFailed)?;

    // Copy security directory
    let _ = copy_security_directory_raw(memory, size, &format!("{}.dll", dll_name_clean));

    // Verify security directory
    let _ = verify_security_directory_raw(memory, size);

    // Apply relocations
    let (clean_base, _ntdll_base, _delta) = apply_relocations_raw(memory, size)
        .ok_or(SignatureError::RelocationFailed)?;

    // Extract signature for specific function
    let result = extract_function_signature(memory, clean_base, function_name, signature_length)
        .map(|(signature_bytes, function_rva)| {
            FunctionSignature::new(
                dll_name_clean,
                function_name.to_string(),
                "dynamic".to_string(), // Version will be detected by byont
                signature_bytes,
                function_rva,
            )
        });

    // Cleanup
    free_executable_memory(memory);

    Ok(result)
}

/// Extract all function signatures from an already-loaded DLL (given base address)
pub fn extract_all_signatures_from_loaded(
    dll_name: &str,
    dll_base: usize,
    signature_length: usize,
) -> Result<SignatureDatabase, SignatureError> {
    let mut dll_name_clean = dll_name.to_lowercase();
    if dll_name_clean.ends_with(".dll") {
        dll_name_clean = dll_name_clean.trim_end_matches(".dll").to_string();
    }

    // Start from export enumeration using the provided base address
    let memory = dll_base as *mut u8;
    let function_names = get_all_export_names(memory);
    if function_names.is_empty() {
        return Err(SignatureError::NoExportDirectory);
    }

    // Create signature database
    let mut database = SignatureDatabase::new();

    // For RVA calculations on a loaded module, the base is the module base
    let clean_base = dll_base;

    // Extract signatures for all functions
    for func_name in function_names {
        if let Some((signature_bytes, function_rva)) =
            extract_function_signature(memory, clean_base, &func_name, signature_length)
        {
            let signature = FunctionSignature::new(
                dll_name_clean.clone(),
                func_name,
                "dynamic".to_string(),
                signature_bytes,
                function_rva,
            );
            database.add_signature(signature);
        }
    }

    Ok(database)
}

/// Get all exported function names from a DLL
pub fn get_all_export_names(memory: *mut u8) -> Vec<String> {
    unsafe {
        // DOS header
        let dos_header = memory as *const u8;
        if *(dos_header as *const u16) != 0x5A4D {
            // MZ
            return Vec::new();
        }
        let e_lfanew = *(dos_header.offset(0x3C) as *const u32) as usize;
        let pe_header = memory.add(e_lfanew) as *const u8;
        if *(pe_header as *const u32) != 0x00004550 {
            // PE\0\0
            return Vec::new();
        }
        // File header is 20 bytes, Optional header follows
        let optional_header = pe_header.add(24);
        let magic = *(optional_header as *const u16);
        if magic != 0x20B {
            return Vec::new();
        }
        // Data Directory array starts at offset 112 in Optional Header for PE32+
        let data_dir = optional_header.add(112);
        let export_rva = *(data_dir as *const u32) as usize;
        let export_size = *(data_dir.add(4) as *const u32) as usize;
        if export_rva == 0 || export_size == 0 {
            return Vec::new();
        }
        let export_dir = memory.add(export_rva) as *const u8;
        let number_of_names = *(export_dir.add(24) as *const u32) as usize;
        let names_rva = *(export_dir.add(32) as *const u32) as usize;
        if number_of_names == 0 || names_rva == 0 {
            return Vec::new();
        }
        let names_array = memory.add(names_rva) as *const u32;
        let mut function_names = Vec::new();
        for i in 0..number_of_names {
            let name_rva = *names_array.add(i) as usize;
            if name_rva == 0 {
                continue;
            }
            let name_ptr = memory.add(name_rva) as *const u8;
            let mut name_bytes = Vec::new();
            for j in 0..256 {
                let b = *name_ptr.add(j);
                if b == 0 {
                    break;
                }
                name_bytes.push(b);
            }
            if let Ok(name) = String::from_utf8(name_bytes) {
                function_names.push(name);
            }
        }
        function_names
    }
}

/// Extract function signature from memory
fn extract_function_signature(
    memory: *mut u8,
    clean_base: usize,
    func_name: &str,
    signature_length: usize,
) -> Option<(Vec<u8>, usize)> {
    unsafe {
        // DOS header
        let dos_header = memory as *const u8;
        if *(dos_header as *const u16) != 0x5A4D {
            // MZ
            return None;
        }
        let e_lfanew = *(dos_header.offset(0x3C) as *const u32) as usize;
        let pe_header = memory.add(e_lfanew) as *const u8;
        if *(pe_header as *const u32) != 0x00004550 {
            // PE\0\0
            return None;
        }
        // File header is 20 bytes, Optional header follows
        let optional_header = pe_header.add(24);
        let magic = *(optional_header as *const u16);
        if magic != 0x20B {
            return None;
        }
        // Data Directory array starts at offset 112 in Optional Header for PE32+
        let data_dir = optional_header.add(112);
        let export_rva = *(data_dir as *const u32) as usize;
        let export_size = *(data_dir.add(4) as *const u32) as usize;
        if export_rva == 0 || export_size == 0 {
            return None;
        }
        let export_dir = memory.add(export_rva) as *const u8;
        let number_of_names = *(export_dir.add(24) as *const u32) as usize;
        let names_rva = *(export_dir.add(32) as *const u32) as usize;
        let functions_rva = *(export_dir.add(28) as *const u32) as usize;
        let ordinals_rva = *(export_dir.add(36) as *const u32) as usize;

        if number_of_names == 0 || names_rva == 0 || functions_rva == 0 || ordinals_rva == 0 {
            return None;
        }

        let names_array = memory.add(names_rva) as *const u32;
        let functions_array = memory.add(functions_rva) as *const u32;
        let ordinals_array = memory.add(ordinals_rva) as *const u16;

        // Search for the function name
        for i in 0..number_of_names {
            let name_rva = *names_array.add(i) as usize;
            if name_rva == 0 {
                continue;
            }
            let name_ptr = memory.add(name_rva) as *const u8;
            let mut name_bytes = Vec::new();
            for j in 0..256 {
                let b = *name_ptr.add(j);
                if b == 0 {
                    break;
                }
                name_bytes.push(b);
            }
            if let Ok(name) = String::from_utf8(name_bytes) {
                if name == func_name {
                    // Found the function, get its address
                    let ordinal = *ordinals_array.add(i) as usize;
                    let function_rva = *functions_array.add(ordinal) as usize;
                    let func_addr = memory.add(function_rva) as usize;
                    let rva = func_addr - clean_base;

                    // Extract signature bytes
                    let signature_bytes = std::slice::from_raw_parts(func_addr as *const u8, signature_length);

                    return Some((signature_bytes.to_vec(), rva));
                }
            }
        }

        None
    }
}

/// Extract function bytes from system-loaded DLL
pub fn extract_system_function_bytes(
    function_address: *mut u8,
    signature_length: usize,
) -> Vec<u8> {
    unsafe {
        let func_bytes = std::slice::from_raw_parts(function_address as *const u8, signature_length);
        func_bytes.to_vec()
    }
} 
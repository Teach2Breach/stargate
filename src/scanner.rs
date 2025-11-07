use crate::signature::{FunctionSignature, SignatureDatabase, SignatureError};
use moonwalk::find_dll_base;

/// Result of a signature scan operation
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub function_name: String,
    pub dll_name: String,
    pub found_address: usize,
    pub expected_rva: usize,
    pub actual_rva: usize,
    pub signature_matches: bool,
    pub confidence_score: f32,
    pub scan_method: ScanMethod,
    pub hook_detected: bool,
    pub hook_details: Option<HookDetails>,
}

/// Method used to find the function
#[derive(Debug, Clone)]
pub enum ScanMethod {
    ExactMatch,
    PartialMatch,
    RelocatedMatch,
    HookedFunction,
    AlternativeLocation,
}

/// Details about detected hooks
#[derive(Debug, Clone)]
pub struct HookDetails {
    pub hook_type: HookType,
    pub original_bytes: Vec<u8>,
    pub hook_bytes: Vec<u8>,
    pub hook_offset: usize,
    pub jump_target: Option<usize>,
}

/// Types of hooks that can be detected
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum HookType {
    JumpHook,      // JMP instruction at function start
    CallHook,      // CALL instruction at function start
    InlineHook,    // Modified bytes within function
    IATHook,       // Import Address Table hook
    Unknown,
}

/// Scan a loaded DLL for functions matching signatures in our database
pub fn scan_loaded_dll(
    dll_name: &str,
    db: &SignatureDatabase,
) -> Result<Vec<ScanResult>, SignatureError> {
    let mut results = Vec::new();
    
    // Find the loaded DLL in memory
    let dll_base = find_dll_base(dll_name)
        .ok_or_else(|| SignatureError::DllNotFound(dll_name.to_string()))?;
    
    // Get all signatures for this DLL
    let signatures = db.get_signatures_by_dll(dll_name);
    
    for signature in signatures {
        // Skip data exports that commonly cause false positives
        if is_likely_data_export(&signature.function_name) {
            continue;
        }
        
        if let Some(scan_result) = find_function_by_signature(dll_base, signature) {
            results.push(scan_result);
        }
    }
    
    Ok(results)
}

/// Scan all loaded DLLs that have signatures in our database
pub fn scan_all_loaded_dlls(
    db: &SignatureDatabase,
) -> Vec<ScanResult> {
    let mut all_results = Vec::new();
    
    // Get unique DLL names from database
    let stats = db.get_stats();
    let dll_names: Vec<_> = stats.dll_counts.keys().collect();
    
    for dll_name in dll_names {
        if let Ok(results) = scan_loaded_dll(dll_name, db) {
            all_results.extend(results);
        }
    }
    
    all_results
}

/// Find a specific function by signature in a loaded DLL
pub fn find_specific_function(
    dll_name: &str,
    function_name: &str,
    db: &SignatureDatabase,
) -> Option<ScanResult> {
    let dll_base = find_dll_base(dll_name)?;
    
    if let Some(signature) = db.get_signature(dll_name, function_name, "dynamic") {
        find_function_by_signature(dll_base, signature)
    } else {
        None
    }
}

/// Core function to find a function by its signature with hook-resistant logic
fn find_function_by_signature(
    dll_base: usize,
    signature: &FunctionSignature,
) -> Option<ScanResult> {
    // Method 1: Try exact match at expected RVA
    if let Some(result) = try_exact_match(dll_base, signature) {
        return Some(result);
    }
    
    // Method 2: Try partial match with hook detection
    if let Some(result) = try_partial_match_with_hook_detection(dll_base, signature) {
        return Some(result);
    }
    
    // Method 3: Scan for signature in nearby memory regions
    if let Some(result) = scan_nearby_regions(dll_base, signature) {
        return Some(result);
    }
    
    // Method 4: Try alternative locations (common hook locations)
    if let Some(result) = try_alternative_locations(dll_base, signature) {
        return Some(result);
    }
    
    None
}

/// Try exact match at the expected RVA location
fn try_exact_match(dll_base: usize, signature: &FunctionSignature) -> Option<ScanResult> {
    let expected_address = dll_base + signature.function_rva;
    
    // Check if the memory is readable
    if !is_memory_readable(expected_address, signature.signature_bytes.len()) {
        return None;
    }
    
    let actual_bytes = unsafe {
        std::slice::from_raw_parts(expected_address as *const u8, signature.signature_bytes.len())
    };
    
    if actual_bytes == signature.signature_bytes.as_slice() {
        return Some(ScanResult {
            function_name: signature.function_name.clone(),
            dll_name: signature.dll_name.clone(),
            found_address: expected_address,
            expected_rva: signature.function_rva,
            actual_rva: signature.function_rva,
            signature_matches: true,
            confidence_score: 1.0,
            scan_method: ScanMethod::ExactMatch,
            hook_detected: false,
            hook_details: None,
        });
    }
    
    None
}

/// Try partial match with hook detection
fn try_partial_match_with_hook_detection(
    dll_base: usize,
    signature: &FunctionSignature,
) -> Option<ScanResult> {
    let expected_address = dll_base + signature.function_rva;
    
    if !is_memory_readable(expected_address, signature.signature_bytes.len()) {
        return None;
    }
    
    let actual_bytes = unsafe {
        std::slice::from_raw_parts(expected_address as *const u8, signature.signature_bytes.len())
    };
    
    // Check for common hook patterns
    let hook_info = detect_hook_pattern(actual_bytes, &signature.signature_bytes);
    
    if let Some(hook_details) = hook_info {
        // Function is hooked, but we found it
        return Some(ScanResult {
            function_name: signature.function_name.clone(),
            dll_name: signature.dll_name.clone(),
            found_address: expected_address,
            expected_rva: signature.function_rva,
            actual_rva: signature.function_rva,
            signature_matches: false,
            confidence_score: 0.8,
            scan_method: ScanMethod::HookedFunction,
            hook_detected: true,
            hook_details: Some(hook_details),
        });
    }
    
    // Try partial matching (ignore first few bytes that might be hooked)
    let partial_match = try_partial_signature_match(actual_bytes, &signature.signature_bytes);
    
    if partial_match > 0.7 {
        return Some(ScanResult {
            function_name: signature.function_name.clone(),
            dll_name: signature.dll_name.clone(),
            found_address: expected_address,
            expected_rva: signature.function_rva,
            actual_rva: signature.function_rva,
            signature_matches: false,
            confidence_score: partial_match,
            scan_method: ScanMethod::PartialMatch,
            hook_detected: true,
            hook_details: None,
        });
    }
    
    None
}

/// Scan nearby memory regions for the signature
fn scan_nearby_regions(dll_base: usize, signature: &FunctionSignature) -> Option<ScanResult> {
    // Define search range around expected RVA
    let search_start = dll_base.saturating_sub(0x1000);
    let search_end = dll_base + 0x100000; // Search up to 1MB forward
    
    // Scan in chunks
    let chunk_size = 0x1000;
    let signature_len = signature.signature_bytes.len();
    
    for addr in (search_start..search_end).step_by(chunk_size) {
        if !is_memory_readable(addr, chunk_size) {
            continue;
        }
        
        let chunk = unsafe {
            std::slice::from_raw_parts(addr as *const u8, chunk_size)
        };
        
        // Search for signature in this chunk
        for offset in 0..=(chunk_size - signature_len) {
            let candidate = &chunk[offset..offset + signature_len];
            
            if candidate == signature.signature_bytes.as_slice() {
                let found_address = addr + offset;
                let actual_rva = found_address - dll_base;
                
                return Some(ScanResult {
                    function_name: signature.function_name.clone(),
                    dll_name: signature.dll_name.clone(),
                    found_address,
                    expected_rva: signature.function_rva,
                    actual_rva,
                    signature_matches: true,
                    confidence_score: 0.9,
                    scan_method: ScanMethod::RelocatedMatch,
                    hook_detected: false,
                    hook_details: None,
                });
            }
        }
    }
    
    None
}

/// Try alternative locations where functions might be relocated
fn try_alternative_locations(dll_base: usize, signature: &FunctionSignature) -> Option<ScanResult> {
    // Common alternative locations to check
    let alternative_rvas = vec![
        signature.function_rva + 0x1000,  // Common relocation offset
        signature.function_rva - 0x1000,  // Backward relocation
        signature.function_rva + 0x2000,  // Larger offset
    ];
    
    for alt_rva in alternative_rvas {
        let alt_address = dll_base + alt_rva;
        
        if !is_memory_readable(alt_address, signature.signature_bytes.len()) {
            continue;
        }
        
        let actual_bytes = unsafe {
            std::slice::from_raw_parts(alt_address as *const u8, signature.signature_bytes.len())
        };
        
        if actual_bytes == signature.signature_bytes.as_slice() {
            return Some(ScanResult {
                function_name: signature.function_name.clone(),
                dll_name: signature.dll_name.clone(),
                found_address: alt_address,
                expected_rva: signature.function_rva,
                actual_rva: alt_rva,
                signature_matches: true,
                confidence_score: 0.85,
                scan_method: ScanMethod::AlternativeLocation,
                hook_detected: false,
                hook_details: None,
            });
        }
    }
    
    None
}

/// Detect common hook patterns with improved logic
fn detect_hook_pattern(actual_bytes: &[u8], expected_bytes: &[u8]) -> Option<HookDetails> {
    if actual_bytes.len() < 5 {
        return None;
    }
    
    // Check for ntdll syscall pattern first (most common)
    if actual_bytes.len() >= 4 && actual_bytes[0] == 0x4C && actual_bytes[1] == 0x8B && actual_bytes[2] == 0xD1 {
        // This is the standard ntdll syscall prologue: mov r10, rcx
        match actual_bytes[3] {
            0xE9 => {
                // JMP instruction - definitely hooked
                let jump_offset = u32::from_le_bytes([
                    actual_bytes[4], actual_bytes[5], actual_bytes[6], actual_bytes[7]
                ]) as usize;
                let jump_target = actual_bytes.as_ptr() as usize + 8 + jump_offset;
                
                return Some(HookDetails {
                    hook_type: HookType::JumpHook,
                    original_bytes: expected_bytes[..8].to_vec(),
                    hook_bytes: actual_bytes[..8].to_vec(),
                    hook_offset: 0,
                    jump_target: Some(jump_target),
                });
            }
            0xB8 => {
                // Normal syscall - not hooked
                return None;
            }
            _ => {
                // Unknown pattern after syscall prologue - likely hooked
                return Some(HookDetails {
                    hook_type: HookType::Unknown,
                    original_bytes: expected_bytes[..4].to_vec(),
                    hook_bytes: actual_bytes[..4].to_vec(),
                    hook_offset: 0,
                    jump_target: None,
                });
            }
        }
    }
    
    // Check for JMP instruction (0xE9) at the beginning
    if actual_bytes[0] == 0xE9 {
        let jump_offset = u32::from_le_bytes([
            actual_bytes[1], actual_bytes[2], actual_bytes[3], actual_bytes[4]
        ]) as usize;
        let jump_target = actual_bytes.as_ptr() as usize + 5 + jump_offset;
        
        return Some(HookDetails {
            hook_type: HookType::JumpHook,
            original_bytes: expected_bytes[..5].to_vec(),
            hook_bytes: actual_bytes[..5].to_vec(),
            hook_offset: 0,
            jump_target: Some(jump_target),
        });
    }
    
    // Check for CALL instruction (0xE8) at the beginning
    if actual_bytes[0] == 0xE8 {
        let call_offset = u32::from_le_bytes([
            actual_bytes[1], actual_bytes[2], actual_bytes[3], actual_bytes[4]
        ]) as usize;
        let call_target = actual_bytes.as_ptr() as usize + 5 + call_offset;
        
        return Some(HookDetails {
            hook_type: HookType::CallHook,
            original_bytes: expected_bytes[..5].to_vec(),
            hook_bytes: actual_bytes[..5].to_vec(),
            hook_offset: 0,
            jump_target: Some(call_target),
        });
    }
    
    // Check for PUSH + RET pattern (common hook technique)
    if actual_bytes.len() >= 6 && actual_bytes[0] == 0x68 && actual_bytes[5] == 0xC3 {
        // PUSH imm32 + RET pattern
        let push_value = u32::from_le_bytes([
            actual_bytes[1], actual_bytes[2], actual_bytes[3], actual_bytes[4]
        ]) as usize;
        
        return Some(HookDetails {
            hook_type: HookType::JumpHook,
            original_bytes: expected_bytes[..6].to_vec(),
            hook_bytes: actual_bytes[..6].to_vec(),
            hook_offset: 0,
            jump_target: Some(push_value),
        });
    }
    
    // Check for MOV + JMP pattern
    if actual_bytes.len() >= 7 && actual_bytes[0] == 0x48 && actual_bytes[1] == 0xB8 && actual_bytes[6] == 0xFF && actual_bytes[7] == 0xE0 {
        // MOV RAX, imm64 + JMP RAX pattern
        let target = u64::from_le_bytes([
            actual_bytes[2], actual_bytes[3], actual_bytes[4], actual_bytes[5],
            actual_bytes[6], actual_bytes[7], actual_bytes[8], actual_bytes[9]
        ]) as usize;
        
        return Some(HookDetails {
            hook_type: HookType::JumpHook,
            original_bytes: expected_bytes[..10].to_vec(),
            hook_bytes: actual_bytes[..10].to_vec(),
            hook_offset: 0,
            jump_target: Some(target),
        });
    }
    
    // Check for inline hook (modified bytes in the middle)
    // Look for differences beyond the first few bytes
    let check_start = 4; // Skip first 4 bytes as they might be legitimately different
    for i in check_start..actual_bytes.len().saturating_sub(4) {
        if actual_bytes[i..i+4] != expected_bytes[i..i+4] {
            return Some(HookDetails {
                hook_type: HookType::InlineHook,
                original_bytes: expected_bytes[i..i+4].to_vec(),
                hook_bytes: actual_bytes[i..i+4].to_vec(),
                hook_offset: i,
                jump_target: None,
            });
        }
    }
    
    None
}

/// Try partial signature matching (ignore first few bytes)
fn try_partial_signature_match(actual_bytes: &[u8], expected_bytes: &[u8]) -> f32 {
    if actual_bytes.len() != expected_bytes.len() {
        return 0.0;
    }
    
    let min_match_length = 8; // Minimum bytes to match
    let mut match_count = 0;
    
    // Skip first few bytes (common hook location) and match the rest
    for i in min_match_length..actual_bytes.len() {
        if actual_bytes[i] == expected_bytes[i] {
            match_count += 1;
        }
    }
    
    if match_count == 0 {
        return 0.0;
    }
    
    match_count as f32 / (actual_bytes.len() - min_match_length) as f32
}

/// Check if a function name is likely a data export (not a function)
fn is_likely_data_export(function_name: &str) -> bool {
    // Common data export patterns that cause false positives
    let data_patterns = [
        "NlsMbCodePageTag",
        "RtlNtdllName", 
        "NlsMbOemCodePageTag",
        "LdrSystemDllInitBlock",
        "NlsAnsiCodePage",
        "KiUserInvertedFunctionTable",
        "RtlpFreezeTimeBias",

    ];
    
    data_patterns.contains(&function_name)
}

/// Check if memory is readable
fn is_memory_readable(address: usize, size: usize) -> bool {
    // This is a simplified check - in a real implementation,
    // you'd want to use VirtualQuery or similar to check memory protection
    if address == 0 || size == 0 {
        return false;
    }
    
    // Try to read a small amount to test if memory is accessible
    unsafe {
        let test_ptr = address as *const u8;
        
        // This will cause a segfault if memory is not readable
        // In a real implementation, you'd use proper memory protection checking
        let _ = std::ptr::read_volatile(test_ptr);
        true
    }
}

/// Print scan results in a formatted way
pub fn print_scan_results(results: &[ScanResult]) {
    println!("\n=== Signature Scan Results ===");
    println!("Found {} functions", results.len());
    
    let mut hook_count = 0;
    let mut exact_match_count = 0;
    
    for result in results {
        println!("\nFunction: {} in {}", result.function_name, result.dll_name);
        println!("  Found at: 0x{:x} (RVA: 0x{:x})", result.found_address, result.actual_rva);
        println!("  Expected RVA: 0x{:x}", result.expected_rva);
        println!("  Method: {:?}", result.scan_method);
        println!("  Confidence: {:.1}%", result.confidence_score * 100.0);
        
        if result.hook_detected {
            hook_count += 1;
            println!("  ⚠️  HOOK DETECTED!");
            if let Some(hook_details) = &result.hook_details {
                println!("  Hook type: {:?}", hook_details.hook_type);
                println!("  Hook offset: 0x{:x}", hook_details.hook_offset);
                if let Some(target) = hook_details.jump_target {
                    println!("  Jump target: 0x{:x}", target);
                }
            }
        } else {
            exact_match_count += 1;
        }
    }
    
    println!("\n=== Summary ===");
    println!("Exact matches: {}", exact_match_count);
    println!("Hooked functions: {}", hook_count);
    println!("Total scanned: {}", results.len());
} 
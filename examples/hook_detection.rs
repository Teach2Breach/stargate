use stargate::*;
use std::fs::File;
use std::io::Write;
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Hook Detection Scanner");
    println!("This example scans for hooked functions and writes detailed results to hooks.txt");

    // Step 1: Extract signatures from clean DLLs
    println!("\n=== Step 1: Extracting Signatures ===");
    
    let mut combined_db = SignatureDatabase::new();
    
    // Extract signatures from common DLLs that are often targeted by hooks
    let dlls_to_scan = vec![
        "ntdll",
        "kernel32", 
    ];
    
    for dll_name in &dlls_to_scan {
        println!("Extracting {} signatures...", dll_name);
        match extract_all_signatures(dll_name, 32) {
            Ok(db) => {
                println!("  Extracted {} signatures", db.len());
                for sig in db.get_all_signatures() {
                    combined_db.add_signature(sig.clone());
                }
            }
            Err(e) => {
                println!("  Failed to extract {}: {}", dll_name, e);
            }
        }
    }
    
    println!("Combined database contains {} signatures", combined_db.len());

    // Step 2: Scan all loaded DLLs for hooks
    println!("\n=== Step 2: Scanning for Hooks ===");
    
    let mut all_results = Vec::new();
    
    for dll_name in &dlls_to_scan {
        println!("Scanning loaded {}...", dll_name);
        match scan_loaded_dll(dll_name, &combined_db) {
            Ok(results) => {
                println!("  Found {} functions", results.len());
                all_results.extend(results);
            }
            Err(e) => {
                println!("  Failed to scan {}: {}", dll_name, e);
            }
        }
    }
    
    // Step 3: Filter and analyze hooked functions
    println!("\n=== Step 3: Analyzing Hooked Functions ===");
    
    let hooked_functions: Vec<&ScanResult> = all_results
        .iter()
        .filter(|r| r.hook_detected)
        .collect();
    
    println!("Found {} hooked functions out of {} total functions", 
             hooked_functions.len(), all_results.len());
    
    // Step 4: Write detailed results to hooks.txt
    println!("\n=== Step 4: Writing Results to hooks.txt ===");
    
    let mut file = File::create("hooks.txt")?;
    
    // Write header
    writeln!(file, "HOOK DETECTION REPORT")?;
    writeln!(file, "Generated: {}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs())?;
    writeln!(file, "Total functions scanned: {}", all_results.len())?;
    writeln!(file, "Hooked functions found: {}", hooked_functions.len())?;
    writeln!(file, "{}", "=".repeat(80))?;
    writeln!(file)?;
    
    // Group hooks by type
    let mut hooks_by_type: HashMap<&HookType, Vec<&ScanResult>> = HashMap::new();
    for result in &hooked_functions {
        if let Some(hook_details) = &result.hook_details {
            hooks_by_type.entry(&hook_details.hook_type)
                .or_insert_with(Vec::new)
                .push(result);
        }
    }
    
    // Write summary by hook type
    writeln!(file, "HOOK TYPE SUMMARY:")?;
    writeln!(file, "{}", "-".repeat(40))?;
    for (hook_type, functions) in &hooks_by_type {
        writeln!(file, "{:?}: {} functions", hook_type, functions.len())?;
    }
    writeln!(file)?;
    
    // Write detailed information for each hooked function
    writeln!(file, "DETAILED HOOK ANALYSIS:")?;
    writeln!(file, "{}", "=".repeat(80))?;
    writeln!(file)?;
    
    for (i, result) in hooked_functions.iter().enumerate() {
        writeln!(file, "HOOK #{:03}", i + 1)?;
        writeln!(file, "{}", "-".repeat(40))?;
        writeln!(file, "Function: {}", result.function_name)?;
        writeln!(file, "DLL: {}", result.dll_name)?;
        writeln!(file, "Found Address: 0x{:x}", result.found_address)?;
        writeln!(file, "Expected RVA: 0x{:x}", result.expected_rva)?;
        writeln!(file, "Actual RVA: 0x{:x}", result.actual_rva)?;
        writeln!(file, "Scan Method: {:?}", result.scan_method)?;
        writeln!(file, "Confidence Score: {:.1}%", result.confidence_score * 100.0)?;
        
        if let Some(hook_details) = &result.hook_details {
            writeln!(file, "Hook Type: {:?}", hook_details.hook_type)?;
            writeln!(file, "Hook Offset: 0x{:x}", hook_details.hook_offset)?;
            
            // Write original vs hook bytes
            writeln!(file, "Original Bytes: {}", bytes_to_hex(&hook_details.original_bytes))?;
            writeln!(file, "Hook Bytes:     {}", bytes_to_hex(&hook_details.hook_bytes))?;
            
            if let Some(target) = hook_details.jump_target {
                writeln!(file, "Jump/Call Target: 0x{:x}", target)?;
                
                // Try to identify what's at the target address
                if let Some(target_info) = identify_target_address(target) {
                    writeln!(file, "Target Analysis: {}", target_info)?;
                }
            }
            
            // Additional analysis based on hook type
            match hook_details.hook_type {
                HookType::JumpHook => {
                    writeln!(file, "Analysis: Function start has been replaced with a JMP instruction")?;
                    writeln!(file, "          This is a common API hooking technique")?;
                }
                HookType::CallHook => {
                    writeln!(file, "Analysis: Function start has been replaced with a CALL instruction")?;
                    writeln!(file, "          This may indicate function wrapping or logging")?;
                }
                HookType::InlineHook => {
                    writeln!(file, "Analysis: Function body has been modified at offset 0x{:x}", hook_details.hook_offset)?;
                    writeln!(file, "          This is an inline hook, more difficult to detect")?;
                }
                HookType::IATHook => {
                    writeln!(file, "Analysis: Import Address Table has been modified")?;
                    writeln!(file, "          Function calls are being redirected")?;
                }
                HookType::Unknown => {
                    writeln!(file, "Analysis: Unknown hook type detected")?;
                    writeln!(file, "          Manual investigation required")?;
                }
            }
        }
        
        writeln!(file)?;
        writeln!(file, "Potential Impact:")?;
        writeln!(file, "  - Function behavior may be modified")?;
        writeln!(file, "  - Security monitoring may be bypassed")?;
        writeln!(file, "  - System integrity may be compromised")?;
        writeln!(file)?;
        
        // Add separator between hooks
        if i < hooked_functions.len() - 1 {
            writeln!(file, "{}", "=".repeat(80))?;
            writeln!(file)?;
        }
    }
    
    // Write footer with recommendations
    writeln!(file, "RECOMMENDATIONS:")?;
    writeln!(file, "{}", "=".repeat(80))?;
    writeln!(file)?;
    writeln!(file, "1. Investigate the source of each detected hook")?;
    writeln!(file, "2. Check if hooks are legitimate (security software, debugging tools)")?;
    writeln!(file, "3. Verify system integrity with trusted tools")?;
    writeln!(file, "4. Consider using hook-resistant function calling methods")?;
    writeln!(file, "5. Monitor for new hooks in critical system functions")?;
    writeln!(file)?;
    writeln!(file, "Note: This report was generated by Stargate hook detection scanner")?;
    writeln!(file, "      Some legitimate software may use hooks for monitoring or security")?;
    
    println!("Detailed hook report written to hooks.txt");
    println!("Found {} hooked functions", hooked_functions.len());
    
    // Step 5: Show summary on console
    println!("\n=== Step 5: Console Summary ===");
    
    if !hooked_functions.is_empty() {
        println!("⚠️  HOOKED FUNCTIONS DETECTED:");
        for result in &hooked_functions {
            println!("  {}!{} at 0x{:x}", 
                     result.dll_name, 
                     result.function_name, 
                     result.found_address);
            
            if let Some(hook_details) = &result.hook_details {
                println!("    Hook type: {:?}", hook_details.hook_type);
                if let Some(target) = hook_details.jump_target {
                    println!("    Target: 0x{:x}", target);
                }
            }
        }
    } else {
        println!("✅ No hooks detected in scanned functions");
    }
    
    println!("\n✅ Hook detection example completed successfully!");
    println!("Check hooks.txt for detailed analysis");
    
    Ok(())
}

/// Convert bytes to hex string
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Try to identify what's at a target address
fn identify_target_address(address: usize) -> Option<String> {
    // This is a simplified implementation
    // In a real scenario, you'd want to:
    // 1. Check if the address is in a known module
    // 2. Try to disassemble the code
    // 3. Check if it's a known hook library
    
    // For now, just check if it's in a reasonable range
    if address > 0x10000000 && address < 0x7FFFFFFF {
        Some("Address appears to be in user space".to_string())
    } else if address > 0x80000000 {
        Some("Address appears to be in kernel space".to_string())
    } else {
        Some("Address range unknown".to_string())
    }
} 
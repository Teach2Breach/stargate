use stargate::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("DLL Inspector - Signature Scanning Example");
    println!("This example demonstrates hook-resistant signature scanning");

    // Step 1: Extract signatures from clean DLLs
    println!("\n=== Step 1: Extracting Signatures ===");
    
    let mut combined_db = SignatureDatabase::new();
    
    // Extract ntdll signatures
    println!("Extracting ntdll signatures...");
    let ntdll_db = extract_all_signatures("ntdll", 32)?;
    println!("Extracted {} ntdll signatures", ntdll_db.len());
    
    // Extract kernel32 signatures
    println!("Extracting kernel32 signatures...");
    let kernel32_db = extract_all_signatures("kernel32", 32)?;
    println!("Extracted {} kernel32 signatures", kernel32_db.len());
    
    // Combine databases
    for sig in ntdll_db.get_all_signatures() {
        combined_db.add_signature(sig.clone());
    }
    for sig in kernel32_db.get_all_signatures() {
        combined_db.add_signature(sig.clone());
    }
    
    println!("Combined database contains {} signatures", combined_db.len());

    // Step 2: Scan loaded DLLs for matching functions
    println!("\n=== Step 2: Scanning Loaded DLLs ===");
    
    // Scan ntdll
    println!("Scanning loaded ntdll.dll...");
    let ntdll_results = scan_loaded_dll("ntdll", &combined_db)?;
    println!("Found {} functions in loaded ntdll", ntdll_results.len());
    
    // Scan kernel32
    println!("Scanning loaded kernel32.dll...");
    let kernel32_results = scan_loaded_dll("kernel32", &combined_db)?;
    println!("Found {} functions in loaded kernel32", kernel32_results.len());
    
    // Combine all results
    let mut all_results = ntdll_results;
    all_results.extend(kernel32_results);
    
    // Step 3: Analyze results
    println!("\n=== Step 3: Analysis Results ===");
    
    let exact_matches = all_results.iter().filter(|r| r.signature_matches).count();
    let hooked_functions = all_results.iter().filter(|r| r.hook_detected).count();
    let relocated_functions = all_results.iter().filter(|r| r.expected_rva != r.actual_rva).count();
    
    println!("Total functions found: {}", all_results.len());
    println!("Exact signature matches: {}", exact_matches);
    println!("Hooked functions detected: {}", hooked_functions);
    println!("Relocated functions: {}", relocated_functions);
    
    // Step 4: Show detailed results for specific functions
    println!("\n=== Step 4: Detailed Function Analysis ===");
    
    let interesting_functions = vec![
        "NtQuerySystemTime",
        "NtCreateFile", 
        "Sleep",
        "CreateFileW",
    ];
    
    for func_name in interesting_functions {
        if let Some(result) = all_results.iter().find(|r| r.function_name == func_name) {
            println!("\nFunction: {}", func_name);
            println!("  DLL: {}", result.dll_name);
            println!("  Found at: 0x{:x}", result.found_address);
            println!("  Expected RVA: 0x{:x}", result.expected_rva);
            println!("  Actual RVA: 0x{:x}", result.actual_rva);
            println!("  Scan method: {:?}", result.scan_method);
            println!("  Confidence: {:.1}%", result.confidence_score * 100.0);
            
            if result.hook_detected {
                println!("  ⚠️  HOOK DETECTED!");
                if let Some(hook_details) = &result.hook_details {
                    println!("    Hook type: {:?}", hook_details.hook_type);
                    println!("    Hook offset: 0x{:x}", hook_details.hook_offset);
                    if let Some(target) = hook_details.jump_target {
                        println!("    Jump target: 0x{:x}", target);
                    }
                }
            } else if result.signature_matches {
                println!("  ✅ Signature matches exactly!");
            }
            
            if result.expected_rva != result.actual_rva {
                println!("  📍 Function relocated by 0x{:x} bytes", 
                    result.actual_rva.abs_diff(result.expected_rva));
            }
        } else {
            println!("\nFunction: {} - NOT FOUND", func_name);
        }
    }
    
    // Step 5: Demonstrate specific function search
    println!("\n=== Step 5: Specific Function Search ===");
    
    if let Some(result) = find_specific_function("ntdll", "NtQuerySystemTime", &combined_db) {
        println!("Found NtQuerySystemTime:");
        println!("  Address: 0x{:x}", result.found_address);
        println!("  Method: {:?}", result.scan_method);
        println!("  Hooked: {}", result.hook_detected);
    }
    
    // Step 6: Show hook detection capabilities
    println!("\n=== Step 6: Hook Detection Summary ===");
    
    let hook_types: std::collections::HashMap<_, usize> = all_results
        .iter()
        .filter_map(|r| r.hook_details.as_ref().map(|h| &h.hook_type))
        .fold(std::collections::HashMap::new(), |mut acc, hook_type| {
            *acc.entry(hook_type).or_insert(0) += 1;
            acc
        });
    
    if !hook_types.is_empty() {
        println!("Detected hook types:");
        for (hook_type, count) in hook_types {
            println!("  {:?}: {} functions", hook_type, count);
        }
    } else {
        println!("No hooks detected in scanned functions");
    }
    
    // Step 7: Call the Sleep function at the found address (if found and signature matches exactly)
    println!("\n=== Step 7: Call the Sleep function at the found address ===");
    if let Some(result) = all_results.iter().find(|r| r.function_name == "Sleep" && r.dll_name == "kernel32" && r.signature_matches) {
        println!("About to call Sleep at 0x{:x} (should sleep for 5 seconds)...", result.found_address);
        unsafe {
            // Cast the found address to a function pointer: extern "system" fn(u32)
            let sleep_fn: extern "system" fn(u32) = std::mem::transmute(result.found_address);
            sleep_fn(5000); // Sleep for 5000 ms (5 seconds)
        }
        println!("Woke up after calling Sleep at 0x{:x}!", result.found_address);
    } else {
        println!("Could not find an exact match for kernel32!Sleep to call.");
    }
    
    println!("\n✅ Signature scanning example completed successfully!");
    Ok(())
} 
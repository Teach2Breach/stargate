use stargate::*;
use std::fs::File;
use std::io::Write;
use byont::*;
use moonwalk::find_dll_base;
use winapi::ctypes::c_void;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Stargate Unhook Example");
    println!("This example demonstrates enhanced hook detection and unhooking using nt_unhooker");
    println!("⚠️  WARNING: This example will attempt to unhook ntdll functions!");
    println!("   Only run this in a controlled environment!");

    // Step 1: Extract signatures from ntdll
    println!("\n=== Step 1: Extracting Signatures ===");
    
    let db = extract_all_signatures("ntdll", 32)?;
    println!("Extracted {} signatures from ntdll", db.len());

    // Step 2: Initial hook detection scan
    println!("\n=== Step 2: Initial Hook Detection ===");
    
    let initial_results = scan_loaded_dll("ntdll", &db)?;
    println!("Scanned {} functions", initial_results.len());
    
    let initial_hooked: Vec<&ScanResult> = initial_results
        .iter()
        .filter(|r| r.hook_detected)
        .collect();
    
    println!("Found {} hooked functions before unhooking", initial_hooked.len());
    
    // Step 3: Write initial results to file
    println!("\n=== Step 3: Writing Initial Analysis ===");
    
    let mut file = File::create("unhook_report.txt")?;
    
    writeln!(file, "STARGATE UNHOOK REPORT")?;
    writeln!(file, "Generated: {}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs())?;
    writeln!(file, "Total functions scanned: {}", initial_results.len())?;
    writeln!(file, "Hooked functions found (before): {}", initial_hooked.len())?;
    writeln!(file, "{}", "=".repeat(80))?;
    writeln!(file)?;
    
    // Write initial hooked functions
    if !initial_hooked.is_empty() {
        writeln!(file, "INITIAL HOOKED FUNCTIONS (BEFORE UNHOOKING):")?;
        writeln!(file, "{}", "-".repeat(50))?;
        for (i, result) in initial_hooked.iter().enumerate() {
            writeln!(file, "{:03}. {}!{} at 0x{:x}", 
                     i + 1, result.dll_name, result.function_name, result.found_address)?;
            
            if let Some(hook_details) = &result.hook_details {
                writeln!(file, "    Hook type: {:?}", hook_details.hook_type)?;
                if let Some(target) = hook_details.jump_target {
                    writeln!(file, "    Target: 0x{:x}", target)?;
                }
            }
        }
        writeln!(file)?;
    }
    
    // Step 4: Perform unhooking using nt_unhooker
    println!("\n=== Step 4: Unhooking Functions ===");
    
    if !initial_hooked.is_empty() {
        println!("Attempting to unhook {} functions using nt_unhooker...", initial_hooked.len());
        
        // Get clean ntdll bytes and base address for unhooking
        let clean_ntdll = match get_clean_dll("ntdll") {
            Some(dll) => dll,
            None => {
                println!("❌ Failed to get clean ntdll");
                writeln!(file, "❌ Failed to get clean ntdll")?;
                return Ok(());
            }
        };
        
        // Get ntdll base address
        let ntdll_base = match find_dll_base("ntdll") {
            Some(addr) => addr as *mut c_void,
            None => {
                println!("❌ Failed to get ntdll base address");
                writeln!(file, "❌ Failed to get ntdll base address")?;
                return Ok(());
            }
        };
        
        // Call nt_unhooker's unhook_ntdll function
        let unhook_success = nt_unhooker::unhook_ntdll(&clean_ntdll, ntdll_base);
        
        if unhook_success {
            println!("✅ nt_unhooker unhook_ntdll() completed successfully");
            writeln!(file, "UNHOOKING RESULTS:")?;
            writeln!(file, "✅ nt_unhooker unhook_ntdll() completed successfully")?;
        } else {
            println!("❌ nt_unhooker unhook_ntdll() failed");
            writeln!(file, "❌ nt_unhooker unhook_ntdll() failed")?;
        }
    } else {
        println!("No hooks detected, skipping unhooking");
        writeln!(file, "No hooks detected, skipping unhooking")?;
    }
    
    writeln!(file)?;
    
    // Step 5: Post-unhook verification scan
    println!("\n=== Step 5: Post-Unhook Verification ===");
    
    // Wait a moment for unhooking to take effect
    std::thread::sleep(std::time::Duration::from_millis(100));
    
    let post_results = scan_loaded_dll("ntdll", &db)?;
    println!("Post-unhook scan completed: {} functions", post_results.len());
    
    let post_hooked: Vec<&ScanResult> = post_results
        .iter()
        .filter(|r| r.hook_detected)
        .collect();
    
    println!("Found {} hooked functions after unhooking", post_hooked.len());
    
    // Step 6: Compare results and write analysis
    println!("\n=== Step 6: Analysis and Comparison ===");
    
    writeln!(file, "POST-UNHOOK VERIFICATION:")?;
    writeln!(file, "{}", "=".repeat(80))?;
    writeln!(file, "Hooked functions found (after): {}", post_hooked.len())?;
    writeln!(file)?;
    
    // Calculate unhooking success rate
    let unhooked_count = initial_hooked.len().saturating_sub(post_hooked.len());
    let success_rate = if initial_hooked.len() > 0 {
        (unhooked_count as f64 / initial_hooked.len() as f64) * 100.0
    } else {
        100.0
    };
    
    println!("Unhooking Results:");
    println!("  Initial hooks: {}", initial_hooked.len());
    println!("  Remaining hooks: {}", post_hooked.len());
    println!("  Successfully unhooked: {}", unhooked_count);
    println!("  Success rate: {:.1}%", success_rate);
    
    writeln!(file, "UNHOOKING SUMMARY:")?;
    writeln!(file, "  Initial hooks: {}", initial_hooked.len())?;
    writeln!(file, "  Remaining hooks: {}", post_hooked.len())?;
    writeln!(file, "  Successfully unhooked: {}", unhooked_count)?;
    writeln!(file, "  Success rate: {:.1}%", success_rate)?;
    writeln!(file)?;
    
    // Write remaining hooked functions
    if !post_hooked.is_empty() {
        writeln!(file, "REMAINING HOOKED FUNCTIONS (AFTER UNHOOKING):")?;
        writeln!(file, "{}", "-".repeat(50))?;
        for (i, result) in post_hooked.iter().enumerate() {
            writeln!(file, "{:03}. {}!{} at 0x{:x}", 
                     i + 1, result.dll_name, result.function_name, result.found_address)?;
            
            if let Some(hook_details) = &result.hook_details {
                writeln!(file, "    Hook type: {:?}", hook_details.hook_type)?;
                if let Some(target) = hook_details.jump_target {
                    writeln!(file, "    Target: 0x{:x}", target)?;
                }
            }
        }
        writeln!(file)?;
    }
    
    // Step 7: Detailed comparison of specific functions
    writeln!(file, "DETAILED FUNCTION COMPARISON:")?;
    writeln!(file, "{}", "=".repeat(80))?;
    writeln!(file)?;
    
    for initial_result in &initial_hooked {
        let function_name = &initial_result.function_name;
        
        // Find corresponding post-unhook result
        let post_result = post_results.iter().find(|r| r.function_name == *function_name);
        
        writeln!(file, "Function: {}", function_name)?;
        writeln!(file, "  Before: Hooked = {}", initial_result.hook_detected)?;
        writeln!(file, "  After:  Hooked = {}", post_result.map(|r| r.hook_detected).unwrap_or(false))?;
        
        if let Some(post) = post_result {
            if initial_result.hook_detected && !post.hook_detected {
                writeln!(file, "  Status: ✅ Successfully unhooked")?;
            } else if initial_result.hook_detected && post.hook_detected {
                writeln!(file, "  Status: ❌ Still hooked")?;
                
                // Compare hook details
                if let (Some(initial_hook), Some(post_hook)) = (&initial_result.hook_details, &post.hook_details) {
                    if initial_hook.hook_type != post_hook.hook_type {
                        writeln!(file, "  Note: Hook type changed from {:?} to {:?}", 
                                initial_hook.hook_type, post_hook.hook_type)?;
                    }
                }
            } else {
                writeln!(file, "  Status: ℹ️  No change")?;
            }
        } else {
            writeln!(file, "  Status: ⚠️  Function not found in post-scan")?;
        }
        writeln!(file)?;
    }
    
    // Step 8: Console summary
    println!("\n=== Step 7: Final Summary ===");
    
    if initial_hooked.is_empty() {
        println!("✅ No hooks were detected initially");
    } else if post_hooked.is_empty() {
        println!("🎉 All {} hooks were successfully removed!", initial_hooked.len());
    } else {
        println!("⚠️  Unhooking Results:");
        println!("   Successfully unhooked: {}/{} functions", unhooked_count, initial_hooked.len());
        println!("   Remaining hooks: {}", post_hooked.len());
        
        if !post_hooked.is_empty() {
            println!("   Remaining hooked functions:");
            for result in &post_hooked {
                println!("     - {}!{}", result.dll_name, result.function_name);
            }
        }
    }
    
    // Write final recommendations
    writeln!(file, "RECOMMENDATIONS:")?;
    writeln!(file, "{}", "=".repeat(80))?;
    writeln!(file)?;
    
    if success_rate >= 80.0 {
        writeln!(file, "✅ Excellent unhooking success rate ({:.1}%)", success_rate)?;
        writeln!(file, "   Most hooks were successfully removed")?;
    } else if success_rate >= 50.0 {
        writeln!(file, "⚠️  Moderate unhooking success rate ({:.1}%)", success_rate)?;
        writeln!(file, "   Some hooks remain - manual investigation may be needed")?;
    } else {
        writeln!(file, "❌ Low unhooking success rate ({:.1}%)", success_rate)?;
        writeln!(file, "   Most hooks remain - consider alternative unhooking methods")?;
    }
    
    writeln!(file)?;
    writeln!(file, "Next Steps:")?;
    writeln!(file, "1. Investigate remaining hooks manually")?;
    writeln!(file, "2. Check if remaining hooks are legitimate system hooks")?;
    writeln!(file, "3. Consider using alternative unhooking techniques")?;
    writeln!(file, "4. Monitor system stability after unhooking")?;
    writeln!(file)?;
    writeln!(file, "Note: This report was generated by Stargate unhook example")?;
    writeln!(file, "      Unhooking may affect system stability - use with caution")?;
    
    println!("\n✅ Unhook example completed successfully!");
    println!("Check unhook_report.txt for detailed analysis");
    
    Ok(())
} 
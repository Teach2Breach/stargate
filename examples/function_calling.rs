use stargate::*;
use std::ffi::c_void;

// Function pointer types for demo functions
type GetTickCountFunc = extern "system" fn() -> u32;
type SleepFunc = extern "system" fn(u32) -> ();
type QueryPerformanceCounterFunc = extern "system" fn(*mut i64) -> i32;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Function Calling Demo - Finding and calling functions via signatures");

    // Extract signatures from kernel32 (contains GetTickCount and Sleep)
    let db = extract_all_signatures("kernel32", 32)?;
    
    // Demo 1: Call GetTickCount (returns system uptime in milliseconds)
    if let Some(result) = find_specific_function("kernel32", "GetTickCount", &db) {
        println!("Found GetTickCount at 0x{:x}", result.found_address);
        
        let get_tick_count: GetTickCountFunc = unsafe { 
            std::mem::transmute(result.found_address as *const c_void) 
        };
        
        let uptime = get_tick_count();
        println!("System uptime: {} milliseconds", uptime);
    }

    // Demo 2: Call Sleep (demonstrates function with parameters)
    if let Some(result) = find_specific_function("kernel32", "Sleep", &db) {
        println!("Found Sleep at 0x{:x}", result.found_address);
        
        let sleep_func: SleepFunc = unsafe { 
            std::mem::transmute(result.found_address as *const c_void) 
        };
        
        println!("Sleeping for 1 second...");
        sleep_func(1000);
        println!("Woke up!");
    }

    // Demo 3: Call QueryPerformanceCounter (demonstrates output parameter)
    if let Some(result) = find_specific_function("kernel32", "QueryPerformanceCounter", &db) {
        println!("Found QueryPerformanceCounter at 0x{:x}", result.found_address);
        
        let query_perf_counter: QueryPerformanceCounterFunc = unsafe { 
            std::mem::transmute(result.found_address as *const c_void) 
        };
        
        let mut counter = 0i64;
        let result_code = query_perf_counter(&mut counter);
        
        if result_code != 0 {
            println!("Performance counter: {}", counter);
        } else {
            println!("QueryPerformanceCounter failed");
        }
    }

    // Demo 4: Try ntdll function - NtGetTickCount (alternative to GetTickCount)
    let ntdll_db = extract_all_signatures("ntdll", 32)?;
    
    if let Some(result) = find_specific_function("ntdll", "NtGetTickCount", &ntdll_db) {
        println!("Found NtGetTickCount at 0x{:x}", result.found_address);
        
        // NtGetTickCount has the same signature as GetTickCount
        let nt_get_tick_count: GetTickCountFunc = unsafe { 
            std::mem::transmute(result.found_address as *const c_void) 
        };
        
        let nt_uptime = nt_get_tick_count();
        println!("NtGetTickCount uptime: {} milliseconds", nt_uptime);
    }

    println!("✅ Function calling demo completed successfully!");
    Ok(())
} 
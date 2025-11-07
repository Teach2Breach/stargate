use stargate::*;
use std::ffi::c_void;

type NtQuerySystemTimeFunc = extern "system" fn(lpSystemTime: *mut i64) -> i32;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Extract signatures from ntdll (silent, no printing)
    let db = extract_all_signatures("ntdll", 32)?;

    // Find and call NtQuerySystemTime
    if let Some(result) = find_specific_function("ntdll", "NtQuerySystemTime", &db) {
        let query_time: NtQuerySystemTimeFunc = unsafe { std::mem::transmute(result.found_address as *const c_void) };
        let mut system_time = 0i64;
        let status = query_time(&mut system_time);
        println!("NtQuerySystemTime: {} (status: {})", system_time, status);
    } else {
        println!("NtQuerySystemTime: not found");
    }
    Ok(())
} 
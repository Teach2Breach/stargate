use stargate::*;
use std::ffi::c_void;

type GetTickCountFunc = extern "system" fn() -> u32;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Extract signatures from kernel32 (silent, no printing)
    let db = extract_all_signatures("kernel32", 32)?;

    // Find and call GetTickCount
    if let Some(result) = find_specific_function("kernel32", "GetTickCount", &db) {
        let get_tick_count: GetTickCountFunc = unsafe { std::mem::transmute(result.found_address as *const c_void) };
        let uptime = get_tick_count();
        println!("GetTickCount: {}", uptime);
    } else {
        println!("GetTickCount: not found");
    }
    Ok(())
} 
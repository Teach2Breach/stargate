//! Stargate Library
//! 
//! A novel library for locating function addresses in loaded Windows DLLs without relying on Export Address Table (EAT) parsing.
//! 
//! ## Features
//! 
//! - Extract function signatures from clean DLL files
//! - Store signatures in memory for fast access
//! - Compare signatures with system-loaded functions
//! - Support for multiple Windows versions
//! 
//! ## Example
//! 
//! ```rust
//! use stargate::{extract_all_signatures, scan_loaded_dll};
//! 
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Extract signatures from clean ntdll
//!     let db = extract_all_signatures("ntdll", 32)?;
//!     
//!     // Scan loaded ntdll for functions
//!     let results = scan_loaded_dll("ntdll", &db)?;
//!     
//!     // Find specific function
//!     if let Some(result) = results.iter().find(|r| r.function_name == "NtQuerySystemTime") {
//!         println!("Found NtQuerySystemTime at 0x{:x}", result.found_address);
//!     }
//!     
//!     Ok(())
//! }
//! ```

pub mod signature;
pub mod extractor;
pub mod comparison;
pub mod scanner;

// Re-export main types and functions for convenience
pub use signature::{
    FunctionSignature,
    SignatureDatabase,
    SignatureError,
    ComparisonResult,
    SignatureDifference,
    DatabaseStats,
};

pub use extractor::{
    extract_all_signatures,
    extract_single_signature,
    get_all_export_names,
    extract_system_function_bytes,
    get_system_dll_address,
    get_system_function_address,
};

pub use comparison::{
    compare_signatures,
    compare_with_system,
    compare_all_with_system,
    print_comparison_result,
    print_comparison_summary,
};

pub use scanner::{
    scan_loaded_dll,
    scan_all_loaded_dlls,
    find_specific_function,
    print_scan_results,
    ScanResult,
    ScanMethod,
    HookDetails,
    HookType,
};

/// Default signature length for function signatures
pub const DEFAULT_SIGNATURE_LENGTH: usize = 32;

/// Get the current Windows version by detecting from loaded ntdll
pub fn get_windows_version() -> String {
    // This will be dynamically detected by byont when downloading clean DLLs
    // For now, return a placeholder that will be overridden
    "dynamic".to_string()
}

/// Extract all signatures from a DLL with default settings
pub fn extract_all_signatures_default(dll_name: &str) -> Result<SignatureDatabase, SignatureError> {
    extract_all_signatures(dll_name, DEFAULT_SIGNATURE_LENGTH)
}

/// Extract a single signature with default settings
pub fn extract_single_signature_default(
    dll_name: &str,
    function_name: &str,
) -> Result<Option<FunctionSignature>, SignatureError> {
    extract_single_signature(dll_name, function_name, DEFAULT_SIGNATURE_LENGTH)
}

/// Compare a function with system using default settings
pub fn compare_with_system_default(
    db: &SignatureDatabase,
    dll_name: &str,
    function_name: &str,
) -> Result<ComparisonResult, SignatureError> {
    compare_with_system(db, dll_name, function_name, "dynamic", DEFAULT_SIGNATURE_LENGTH)
}

/// Compare all signatures with system using default settings
pub fn compare_all_with_system_default(
    db: &SignatureDatabase,
    dll_name: &str,
) -> Vec<(String, ComparisonResult)> {
    compare_all_with_system(db, dll_name, "dynamic", DEFAULT_SIGNATURE_LENGTH)
} 
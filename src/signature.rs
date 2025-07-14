use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Represents a function signature extracted from a DLL
#[derive(Debug, Clone)]
pub struct FunctionSignature {
    pub dll_name: String,
    pub function_name: String,
    pub windows_version: String,
    pub signature_bytes: Vec<u8>,
    pub signature_length: usize,
    pub function_rva: usize,
    pub created_at: u64,
}

impl FunctionSignature {
    /// Create a new function signature
    pub fn new(
        dll_name: String,
        function_name: String,
        windows_version: String,
        signature_bytes: Vec<u8>,
        function_rva: usize,
    ) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            signature_length: signature_bytes.len(),
            signature_bytes,
            function_rva,
            dll_name,
            function_name,
            windows_version,
            created_at,
        }
    }

    /// Get the signature bytes as a hex string
    pub fn signature_hex(&self) -> String {
        self.signature_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join("")
    }

    /// Get the signature bytes as a formatted hex string with spaces
    pub fn signature_hex_formatted(&self) -> String {
        self.signature_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join(" ")
    }
}

/// In-memory database for storing function signatures
#[derive(Debug, Default)]
pub struct SignatureDatabase {
    signatures: HashMap<(String, String, String), FunctionSignature>,
}

impl SignatureDatabase {
    /// Create a new empty signature database
    pub fn new() -> Self {
        Self {
            signatures: HashMap::new(),
        }
    }

    /// Add a function signature to the database
    pub fn add_signature(&mut self, signature: FunctionSignature) -> bool {
        let key = (
            signature.dll_name.clone(),
            signature.function_name.clone(),
            signature.windows_version.clone(),
        );
        
        let is_new = !self.signatures.contains_key(&key);
        self.signatures.insert(key, signature);
        is_new
    }

    /// Get a function signature by DLL name, function name, and Windows version
    pub fn get_signature(
        &self,
        dll_name: &str,
        function_name: &str,
        windows_version: &str,
    ) -> Option<&FunctionSignature> {
        let key = (dll_name.to_string(), function_name.to_string(), windows_version.to_string());
        self.signatures.get(&key)
    }

    /// Get all signatures for a specific DLL
    pub fn get_signatures_by_dll(&self, dll_name: &str) -> Vec<&FunctionSignature> {
        self.signatures
            .values()
            .filter(|sig| sig.dll_name == dll_name)
            .collect()
    }

    /// Get all signatures for a specific DLL and Windows version
    pub fn get_signatures_by_dll_and_version(
        &self,
        dll_name: &str,
        windows_version: &str,
    ) -> Vec<&FunctionSignature> {
        self.signatures
            .values()
            .filter(|sig| sig.dll_name == dll_name && sig.windows_version == windows_version)
            .collect()
    }

    /// Get all signatures in the database
    pub fn get_all_signatures(&self) -> Vec<&FunctionSignature> {
        self.signatures.values().collect()
    }

    /// Get the total number of signatures in the database
    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    /// Check if the database is empty
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Clear all signatures from the database
    pub fn clear(&mut self) {
        self.signatures.clear();
    }

    /// Get statistics about the database
    pub fn get_stats(&self) -> DatabaseStats {
        let mut dll_counts = HashMap::new();
        let mut version_counts = HashMap::new();

        for signature in self.signatures.values() {
            *dll_counts.entry(signature.dll_name.clone()).or_insert(0) += 1;
            *version_counts.entry(signature.windows_version.clone()).or_insert(0) += 1;
        }

        DatabaseStats {
            total_signatures: self.signatures.len(),
            unique_dlls: dll_counts.len(),
            unique_versions: version_counts.len(),
            dll_counts,
            version_counts,
        }
    }
}

/// Statistics about the signature database
#[derive(Debug)]
pub struct DatabaseStats {
    pub total_signatures: usize,
    pub unique_dlls: usize,
    pub unique_versions: usize,
    pub dll_counts: HashMap<String, usize>,
    pub version_counts: HashMap<String, usize>,
}

/// Result of comparing two function signatures
#[derive(Debug, Clone)]
pub struct ComparisonResult {
    pub matches: bool,
    pub differences: Vec<SignatureDifference>,
    pub db_signature: Option<FunctionSignature>,
    pub system_bytes: Vec<u8>,
}

impl ComparisonResult {
    pub fn new(
        matches: bool,
        differences: Vec<SignatureDifference>,
        db_signature: Option<FunctionSignature>,
        system_bytes: Vec<u8>,
    ) -> Self {
        Self {
            matches,
            differences,
            db_signature,
            system_bytes,
        }
    }
}

/// Represents a difference between two signatures
#[derive(Debug, Clone)]
pub enum SignatureDifference {
    ByteMismatch {
        offset: usize,
        db_byte: u8,
        system_byte: u8,
    },
    LengthMismatch {
        db_length: usize,
        system_length: usize,
    },
    MissingInDatabase,
}

/// Custom error type for signature operations
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("DLL not found: {0}")]
    DllNotFound(String),
    
    #[error("Function not found: {0}")]
    FunctionNotFound(String),
    
    #[error("Invalid PE header")]
    InvalidPeHeader,
    
    #[error("No export directory found")]
    NoExportDirectory,
    
    #[error("Memory allocation failed")]
    MemoryAllocationFailed,
    
    #[error("Relocation failed")]
    RelocationFailed,
    
    #[error("Security directory copy failed")]
    SecurityDirectoryCopyFailed,
    
    #[error("Unknown error: {0}")]
    Unknown(String),
} 
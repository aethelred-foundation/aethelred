//! Aethelred SDK Snapshot Testing
//!
//! Snapshot testing for AI/ML applications. Captures model outputs,
//! tensor values, and other artifacts for regression testing.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

// ============ Snapshot Storage ============

/// Storage backend for snapshots
pub trait SnapshotStorage: Send + Sync {
    fn load(&self, name: &str) -> Result<Option<Snapshot>, SnapshotError>;
    fn save(&self, name: &str, snapshot: &Snapshot) -> Result<(), SnapshotError>;
    fn delete(&self, name: &str) -> Result<(), SnapshotError>;
    fn list(&self) -> Result<Vec<String>, SnapshotError>;
}

/// File-based snapshot storage
pub struct FileStorage {
    base_path: PathBuf,
}

impl FileStorage {
    pub fn new(base_path: impl AsRef<Path>) -> Self {
        let path = base_path.as_ref().to_path_buf();
        fs::create_dir_all(&path).ok();
        FileStorage { base_path: path }
    }

    fn snapshot_path(&self, name: &str) -> PathBuf {
        self.base_path.join(format!("{}.snap", name))
    }
}

impl SnapshotStorage for FileStorage {
    fn load(&self, name: &str) -> Result<Option<Snapshot>, SnapshotError> {
        let path = self.snapshot_path(name);
        if !path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&path)
            .map_err(|e| SnapshotError::IoError(e.to_string()))?;
        let snapshot: Snapshot = serde_json::from_str(&content)
            .map_err(|e| SnapshotError::ParseError(e.to_string()))?;

        Ok(Some(snapshot))
    }

    fn save(&self, name: &str, snapshot: &Snapshot) -> Result<(), SnapshotError> {
        let path = self.snapshot_path(name);
        let content = serde_json::to_string_pretty(snapshot)
            .map_err(|e| SnapshotError::SerializeError(e.to_string()))?;

        fs::write(&path, content)
            .map_err(|e| SnapshotError::IoError(e.to_string()))?;

        Ok(())
    }

    fn delete(&self, name: &str) -> Result<(), SnapshotError> {
        let path = self.snapshot_path(name);
        if path.exists() {
            fs::remove_file(&path)
                .map_err(|e| SnapshotError::IoError(e.to_string()))?;
        }
        Ok(())
    }

    fn list(&self) -> Result<Vec<String>, SnapshotError> {
        let mut names = Vec::new();
        for entry in fs::read_dir(&self.base_path)
            .map_err(|e| SnapshotError::IoError(e.to_string()))?
        {
            let entry = entry.map_err(|e| SnapshotError::IoError(e.to_string()))?;
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "snap") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    names.push(stem.to_string());
                }
            }
        }
        Ok(names)
    }
}

/// In-memory snapshot storage for testing
pub struct MemoryStorage {
    snapshots: RwLock<HashMap<String, Snapshot>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        MemoryStorage {
            snapshots: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotStorage for MemoryStorage {
    fn load(&self, name: &str) -> Result<Option<Snapshot>, SnapshotError> {
        Ok(self.snapshots.read().unwrap().get(name).cloned())
    }

    fn save(&self, name: &str, snapshot: &Snapshot) -> Result<(), SnapshotError> {
        self.snapshots.write().unwrap().insert(name.to_string(), snapshot.clone());
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<(), SnapshotError> {
        self.snapshots.write().unwrap().remove(name);
        Ok(())
    }

    fn list(&self) -> Result<Vec<String>, SnapshotError> {
        Ok(self.snapshots.read().unwrap().keys().cloned().collect())
    }
}

// ============ Snapshot Types ============

/// A stored snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub name: String,
    pub content: SnapshotContent,
    pub metadata: SnapshotMetadata,
    pub hash: String,
}

/// Content of a snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SnapshotContent {
    Text { value: String },
    Json { value: serde_json::Value },
    Tensor { shape: Vec<usize>, data: Vec<f32> },
    Binary { data: Vec<u8>, format: String },
    ModelOutput { outputs: HashMap<String, serde_json::Value> },
}

/// Metadata about a snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    pub created_at: String,
    pub updated_at: String,
    pub version: u32,
    pub tags: Vec<String>,
    pub custom: HashMap<String, String>,
}

impl SnapshotMetadata {
    pub fn new() -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        SnapshotMetadata {
            created_at: now.clone(),
            updated_at: now,
            version: 1,
            tags: Vec::new(),
            custom: HashMap::new(),
        }
    }
}

impl Default for SnapshotMetadata {
    fn default() -> Self {
        Self::new()
    }
}

/// Error type for snapshot operations
#[derive(Debug)]
pub enum SnapshotError {
    IoError(String),
    ParseError(String),
    SerializeError(String),
    NotFound(String),
    Mismatch { expected: String, actual: String },
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotError::IoError(e) => write!(f, "IO error: {}", e),
            SnapshotError::ParseError(e) => write!(f, "Parse error: {}", e),
            SnapshotError::SerializeError(e) => write!(f, "Serialize error: {}", e),
            SnapshotError::NotFound(name) => write!(f, "Snapshot not found: {}", name),
            SnapshotError::Mismatch { expected, actual } => {
                write!(f, "Snapshot mismatch:\nExpected:\n{}\n\nActual:\n{}", expected, actual)
            }
        }
    }
}

impl std::error::Error for SnapshotError {}

// ============ Snapshot Manager ============

/// Configuration for snapshot testing
#[derive(Debug, Clone)]
pub struct SnapshotConfig {
    /// Update snapshots instead of comparing
    pub update_snapshots: bool,
    /// Tolerance for tensor comparisons
    pub tensor_tolerance: f64,
    /// Include metadata in comparisons
    pub compare_metadata: bool,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        SnapshotConfig {
            update_snapshots: std::env::var("UPDATE_SNAPSHOTS").is_ok(),
            tensor_tolerance: 1e-6,
            compare_metadata: false,
        }
    }
}

/// Manager for snapshot testing
pub struct SnapshotManager {
    storage: Arc<dyn SnapshotStorage>,
    config: SnapshotConfig,
}

impl SnapshotManager {
    pub fn new(storage: Arc<dyn SnapshotStorage>, config: SnapshotConfig) -> Self {
        SnapshotManager { storage, config }
    }

    pub fn file_based(path: impl AsRef<Path>) -> Self {
        SnapshotManager {
            storage: Arc::new(FileStorage::new(path)),
            config: SnapshotConfig::default(),
        }
    }

    pub fn in_memory() -> Self {
        SnapshotManager {
            storage: Arc::new(MemoryStorage::new()),
            config: SnapshotConfig::default(),
        }
    }

    /// Assert text matches snapshot
    pub fn assert_text(&self, name: &str, actual: &str) -> Result<(), SnapshotError> {
        let content = SnapshotContent::Text { value: actual.to_string() };
        self.assert_snapshot(name, content)
    }

    /// Assert JSON matches snapshot
    pub fn assert_json(&self, name: &str, actual: &serde_json::Value) -> Result<(), SnapshotError> {
        let content = SnapshotContent::Json { value: actual.clone() };
        self.assert_snapshot(name, content)
    }

    /// Assert tensor matches snapshot
    pub fn assert_tensor(&self, name: &str, shape: &[usize], data: &[f32]) -> Result<(), SnapshotError> {
        let content = SnapshotContent::Tensor {
            shape: shape.to_vec(),
            data: data.to_vec(),
        };
        self.assert_snapshot(name, content)
    }

    /// Assert model output matches snapshot
    pub fn assert_model_output(
        &self,
        name: &str,
        outputs: HashMap<String, serde_json::Value>,
    ) -> Result<(), SnapshotError> {
        let content = SnapshotContent::ModelOutput { outputs };
        self.assert_snapshot(name, content)
    }

    /// Core snapshot assertion
    fn assert_snapshot(&self, name: &str, actual_content: SnapshotContent) -> Result<(), SnapshotError> {
        let hash = self.compute_hash(&actual_content);

        let actual_snapshot = Snapshot {
            name: name.to_string(),
            content: actual_content,
            metadata: SnapshotMetadata::new(),
            hash,
        };

        match self.storage.load(name)? {
            Some(expected) => {
                if self.config.update_snapshots {
                    // Update mode: save new snapshot
                    self.storage.save(name, &actual_snapshot)?;
                    Ok(())
                } else {
                    // Compare mode
                    self.compare_snapshots(&expected, &actual_snapshot)
                }
            }
            None => {
                // No existing snapshot, create it
                self.storage.save(name, &actual_snapshot)?;
                Ok(())
            }
        }
    }

    /// Compare two snapshots
    fn compare_snapshots(&self, expected: &Snapshot, actual: &Snapshot) -> Result<(), SnapshotError> {
        match (&expected.content, &actual.content) {
            (SnapshotContent::Text { value: e }, SnapshotContent::Text { value: a }) => {
                if e != a {
                    return Err(SnapshotError::Mismatch {
                        expected: e.clone(),
                        actual: a.clone(),
                    });
                }
            }
            (SnapshotContent::Json { value: e }, SnapshotContent::Json { value: a }) => {
                if e != a {
                    return Err(SnapshotError::Mismatch {
                        expected: serde_json::to_string_pretty(e).unwrap(),
                        actual: serde_json::to_string_pretty(a).unwrap(),
                    });
                }
            }
            (SnapshotContent::Tensor { shape: es, data: ed }, SnapshotContent::Tensor { shape: as_, data: ad }) => {
                if es != as_ {
                    return Err(SnapshotError::Mismatch {
                        expected: format!("shape: {:?}", es),
                        actual: format!("shape: {:?}", as_),
                    });
                }

                for (i, (e, a)) in ed.iter().zip(ad.iter()).enumerate() {
                    if (e - a).abs() > self.config.tensor_tolerance as f32 {
                        return Err(SnapshotError::Mismatch {
                            expected: format!("data[{}] = {}", i, e),
                            actual: format!("data[{}] = {}", i, a),
                        });
                    }
                }
            }
            (SnapshotContent::ModelOutput { outputs: e }, SnapshotContent::ModelOutput { outputs: a }) => {
                if e != a {
                    return Err(SnapshotError::Mismatch {
                        expected: serde_json::to_string_pretty(e).unwrap(),
                        actual: serde_json::to_string_pretty(a).unwrap(),
                    });
                }
            }
            _ => {
                return Err(SnapshotError::Mismatch {
                    expected: format!("{:?}", expected.content),
                    actual: format!("{:?}", actual.content),
                });
            }
        }

        Ok(())
    }

    /// Compute hash of snapshot content
    fn compute_hash(&self, content: &SnapshotContent) -> String {
        let json = serde_json::to_string(content).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// List all snapshots
    pub fn list_snapshots(&self) -> Result<Vec<String>, SnapshotError> {
        self.storage.list()
    }

    /// Delete a snapshot
    pub fn delete_snapshot(&self, name: &str) -> Result<(), SnapshotError> {
        self.storage.delete(name)
    }

    /// Check if snapshot exists
    pub fn snapshot_exists(&self, name: &str) -> Result<bool, SnapshotError> {
        Ok(self.storage.load(name)?.is_some())
    }
}

// ============ Inline Snapshot ============

/// Inline snapshot for embedding expected values in tests
pub struct InlineSnapshot {
    content: String,
}

impl InlineSnapshot {
    pub fn new(content: &str) -> Self {
        InlineSnapshot {
            content: content.to_string(),
        }
    }

    pub fn assert_eq(&self, actual: &str) {
        let expected = self.content.trim();
        let actual = actual.trim();

        if expected != actual {
            panic!(
                "Inline snapshot mismatch:\n\nExpected:\n{}\n\nActual:\n{}",
                expected, actual
            );
        }
    }
}

// ============ Snapshot Diff ============

/// Compute diff between two strings
pub fn diff(expected: &str, actual: &str) -> String {
    use std::fmt::Write;

    let mut result = String::new();
    let expected_lines: Vec<&str> = expected.lines().collect();
    let actual_lines: Vec<&str> = actual.lines().collect();

    let max_lines = expected_lines.len().max(actual_lines.len());

    for i in 0..max_lines {
        let exp = expected_lines.get(i).unwrap_or(&"");
        let act = actual_lines.get(i).unwrap_or(&"");

        if exp != act {
            writeln!(result, "- {}", exp).unwrap();
            writeln!(result, "+ {}", act).unwrap();
        } else {
            writeln!(result, "  {}", exp).unwrap();
        }
    }

    result
}

// ============ Tensor Snapshot Utilities ============

/// Create a readable string representation of a tensor
pub fn tensor_to_string(shape: &[usize], data: &[f32], precision: usize) -> String {
    let mut result = String::new();
    result.push_str(&format!("shape: {:?}\n", shape));

    if shape.len() == 1 {
        // 1D tensor
        result.push_str("[");
        for (i, v) in data.iter().enumerate() {
            if i > 0 {
                result.push_str(", ");
            }
            result.push_str(&format!("{:.prec$}", v, prec = precision));
        }
        result.push_str("]");
    } else if shape.len() == 2 {
        // 2D tensor (matrix)
        let rows = shape[0];
        let cols = shape[1];
        result.push_str("[\n");
        for i in 0..rows {
            result.push_str("  [");
            for j in 0..cols {
                if j > 0 {
                    result.push_str(", ");
                }
                result.push_str(&format!("{:.prec$}", data[i * cols + j], prec = precision));
            }
            result.push_str("],\n");
        }
        result.push_str("]");
    } else {
        // Higher-dimensional: just show summary
        result.push_str(&format!("data: {:?}", &data[..data.len().min(10)]));
        if data.len() > 10 {
            result.push_str(" ...");
        }
    }

    result
}

// ============ Golden File Testing ============

/// Manager for golden file testing
pub struct GoldenFileManager {
    base_path: PathBuf,
    update_mode: bool,
}

impl GoldenFileManager {
    pub fn new(base_path: impl AsRef<Path>) -> Self {
        GoldenFileManager {
            base_path: base_path.as_ref().to_path_buf(),
            update_mode: std::env::var("UPDATE_GOLDEN").is_ok(),
        }
    }

    pub fn assert_golden(&self, name: &str, actual: &str) -> Result<(), SnapshotError> {
        let path = self.base_path.join(name);

        if self.update_mode || !path.exists() {
            fs::create_dir_all(path.parent().unwrap())
                .map_err(|e| SnapshotError::IoError(e.to_string()))?;
            fs::write(&path, actual)
                .map_err(|e| SnapshotError::IoError(e.to_string()))?;
            return Ok(());
        }

        let expected = fs::read_to_string(&path)
            .map_err(|e| SnapshotError::IoError(e.to_string()))?;

        if expected != actual {
            Err(SnapshotError::Mismatch {
                expected,
                actual: actual.to_string(),
            })
        } else {
            Ok(())
        }
    }

    pub fn assert_golden_json<T: Serialize>(&self, name: &str, actual: &T) -> Result<(), SnapshotError> {
        let json = serde_json::to_string_pretty(actual)
            .map_err(|e| SnapshotError::SerializeError(e.to_string()))?;
        self.assert_golden(name, &json)
    }
}

// ============ Macros ============

/// Macro for inline snapshot testing
#[macro_export]
macro_rules! assert_snapshot {
    ($actual:expr, $expected:expr) => {
        let snapshot = $crate::snapshot::InlineSnapshot::new($expected);
        snapshot.assert_eq(&$actual.to_string());
    };
}

/// Macro for file-based snapshot testing
#[macro_export]
macro_rules! assert_snapshot_file {
    ($manager:expr, $name:expr, $actual:expr) => {
        $manager.assert_text($name, &$actual.to_string())
            .expect(&format!("Snapshot mismatch for '{}'", $name));
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_storage() {
        let storage = MemoryStorage::new();

        let snapshot = Snapshot {
            name: "test".to_string(),
            content: SnapshotContent::Text { value: "hello".to_string() },
            metadata: SnapshotMetadata::new(),
            hash: "abc".to_string(),
        };

        storage.save("test", &snapshot).unwrap();

        let loaded = storage.load("test").unwrap();
        assert!(loaded.is_some());
    }

    #[test]
    fn test_snapshot_manager() {
        let manager = SnapshotManager::in_memory();

        manager.assert_text("test1", "hello world").unwrap();
        manager.assert_text("test1", "hello world").unwrap();
    }

    #[test]
    fn test_tensor_snapshot() {
        let manager = SnapshotManager::in_memory();

        let shape = vec![2, 3];
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0];

        manager.assert_tensor("tensor1", &shape, &data).unwrap();
        manager.assert_tensor("tensor1", &shape, &data).unwrap();
    }

    #[test]
    fn test_inline_snapshot() {
        let snapshot = InlineSnapshot::new("hello world");
        snapshot.assert_eq("hello world");
    }

    #[test]
    fn test_diff() {
        let expected = "line1\nline2\nline3";
        let actual = "line1\nmodified\nline3";

        let d = diff(expected, actual);
        assert!(d.contains("- line2"));
        assert!(d.contains("+ modified"));
    }
}

//! Timestamped History Layout, Replay, and Retention Engine
//!
//! Implements deterministic audit history snapshots at `artifacts/oscal/history/<timestamp>_<git-sha>/`,
//! with `index.json`, same-second collision suffixes, retention pruning, and byte-for-byte replay verification.

use chrono::{DateTime, Utc};
use oscal_diagnostics::OscalErrorCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::{
    validate_assessment_plan, validate_assessment_results, validate_poam,
    validate_system_security_plan,
};

/// Record metadata index cataloging the environment, provenance, and artifact digests
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoryRecordIndex {
    pub record_id: String,
    pub timestamp: DateTime<Utc>,
    pub git_sha: String,
    pub record_kind: String, // "build" | "release"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_record_id: Option<String>,
    pub toolchains: BTreeMap<String, String>,
    pub schema_hashes: BTreeMap<String, String>,
    pub artifact_hashes: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_tag: Option<String>,
}

/// Retention policy governing history pruning
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryRetentionConfig {
    pub max_records: usize,
    pub retain_tagged_releases: bool,
}

impl Default for HistoryRetentionConfig {
    fn default() -> Self {
        Self {
            max_records: 50,
            retain_tagged_releases: true,
        }
    }
}

/// Summary outcome of an audit replay evaluation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReplayReport {
    pub record_id: String,
    pub verified_artifacts: Vec<String>,
    pub toolchains_verified: bool,
    pub schemas_verified: bool,
}

/// Computes SHA-256 digest of raw bytes
pub fn compute_bytes_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Computes SHA-256 digest of a file
pub fn compute_file_sha256(path: &Path) -> Result<String, std::io::Error> {
    let bytes = fs::read(path)?;
    Ok(compute_bytes_sha256(&bytes))
}

/// Resolves Git SHA from environment variables, Git CLI, or defaults to "nogit"
pub fn resolve_git_sha(repo_root: &Path) -> String {
    if let Ok(val) = std::env::var("GIT_SHA") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Ok(val) = std::env::var("CI_COMMIT_SHA") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    if let Ok(output) = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo_root)
        .output()
    {
        if output.status.success() {
            let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !sha.is_empty() {
                return sha;
            }
        }
    }

    "nogit".to_string()
}

/// Resolves Git tag pointing at the specified commit, or None
pub fn resolve_git_tag(repo_root: &Path, git_sha: &str) -> Option<String> {
    if git_sha == "nogit" {
        return None;
    }
    if let Ok(output) = std::process::Command::new("git")
        .args(["describe", "--exact-match", "--tags", git_sha])
        .current_dir(repo_root)
        .output()
    {
        if output.status.success() {
            let tag = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !tag.is_empty() {
                return Some(tag);
            }
        }
    }
    None
}

/// Generates a collision-free record ID with monotonic sequence suffix if same-second
pub fn generate_record_id(history_dir: &Path, now: DateTime<Utc>, git_sha: &str) -> String {
    let ts_str = now.format("%Y-%m-%dT%H-%M-%SZ").to_string();
    let short_sha = &git_sha[..git_sha.len().min(7)];
    let base_name = format!("{}_{}", ts_str, short_sha);

    let base_dir = history_dir.join(&base_name);
    if !base_dir.exists() {
        return base_name;
    }

    // Handle collision by finding the next monotonic suffix: .1, .2, etc.
    let mut max_seq = 0;
    if let Ok(entries) = fs::read_dir(history_dir) {
        for entry in entries.flatten() {
            if let Ok(file_name) = entry.file_name().into_string() {
                if file_name.starts_with(&base_name) {
                    if let Some(suffix) = file_name.strip_prefix(&format!("{}.", base_name)) {
                        if let Ok(seq) = suffix.parse::<usize>() {
                            max_seq = max_seq.max(seq);
                        }
                    }
                }
            }
        }
    }

    format!("{}.{}", base_name, max_seq + 1)
}

/// Returns the 9 pinned schema and catalog hashes from PROVENANCE.toml
pub fn get_pinned_schema_hashes() -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert(
        "schemas/oscal_assessment-results_schema.json".to_string(),
        "fdee9614db5a21ad0c1747945def60810278fc5bf7287d2bf93ce2f53ed46977".to_string(),
    );
    m.insert(
        "schemas/oscal_poam_schema.json".to_string(),
        "7e06835a32ab03561e96cfc9c623dd7b1ffd3924958a0e6a333008cb711b0f5f".to_string(),
    );
    m.insert(
        "schemas/oscal_catalog_schema.json".to_string(),
        "936c53978eb47880dfa8b471640ae09b111b38d837686022ef7db07e26fa629d".to_string(),
    );
    m.insert(
        "schemas/oscal_ssp_schema.json".to_string(),
        "c361dd9aadb7e0cf9b195194f2e1e88829d2b2b183d0e3ac32d4590d1acb72dd".to_string(),
    );
    m.insert(
        "schemas/oscal_assessment-plan_schema.json".to_string(),
        "add46ade21dc1659f7bac0e83637a9270ba1468ebf6bbd26ac0c6085d2eb0e67".to_string(),
    );
    m.insert(
        "schemas/lean-rust.schema.json".to_string(),
        "18698eb2dcd6b518d4393692cc377748663c28a8a95ce8241201d96395aade56".to_string(),
    );
    m.insert(
        "schemas/suppressed-findings.schema.json".to_string(),
        "50f1501455c24b24b140c84ef9f8f633628bfe6fe75847c1a2fbb65c9aeaf559".to_string(),
    );
    m.insert(
        "crates/oscal-engine/control-id-map.toml".to_string(),
        "1450c8a3adda5455f012c1baf98d30b7902d6c18f7da493a1a4092be62bf3fd7".to_string(),
    );
    m.insert(
        "schemas/catalogs/NIST_SP_800-53_rev5_catalog.json".to_string(),
        "6c39acc31c7d492a80acd6dd2af0ebc19bf8084974fd38ac9ed684a56beef3ac".to_string(),
    );
    m
}

/// Collects host toolchain versions
pub fn collect_host_toolchains() -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();

    let query_tool = |cmd: &str, args: &[&str]| -> String {
        match std::process::Command::new(cmd).args(args).output() {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                stdout
                    .lines()
                    .next()
                    .unwrap_or("unknown")
                    .trim()
                    .to_string()
            }
            _ => "unknown".to_string(),
        }
    };

    m.insert("rustc".to_string(), query_tool("rustc", &["--version"]));
    m.insert("kani".to_string(), query_tool("kani", &["--version"]));
    m.insert(
        "charon".to_string(),
        query_tool("charon", &["toolchain-version"]),
    );
    m.insert("lean".to_string(), query_tool("lean", &["--version"]));
    m.insert("lake".to_string(), query_tool("lake", &["--version"]));

    m
}

/// Writes an atomic timestamped history record to `artifacts/oscal/history/<timestamp>_<git-sha>/`
// The arguments are the record's fields in schema order; a parameter struct
// would only restate the record it writes.
#[allow(clippy::too_many_arguments)]
pub fn emit_history_record(
    history_root: &Path,
    record_kind: &str, // "build" | "release"
    ssp_str: &str,
    sap_str: &str,
    ar_str: &str,
    poam_str: Option<&str>,
    telemetry_val: &serde_json::Value,
    now: DateTime<Utc>,
    repo_root: &Path,
    retention: Option<&HistoryRetentionConfig>,
    gate_outcome: Option<&str>,
) -> Result<HistoryRecordIndex, Vec<String>> {
    fs::create_dir_all(history_root)
        .map_err(|e| vec![format!("Failed to create history root directory: {}", e)])?;

    let git_sha = resolve_git_sha(repo_root);
    let git_tag = resolve_git_tag(repo_root, &git_sha);
    let record_id = generate_record_id(history_root, now, &git_sha);
    let record_dir = history_root.join(&record_id);

    fs::create_dir_all(&record_dir).map_err(|e| {
        vec![format!(
            "Failed to create record directory {}: {}",
            record_dir.display(),
            e
        )]
    })?;

    let mut artifact_hashes = BTreeMap::new();

    // 1. Write SSP
    let ssp_path = record_dir.join("system-security-plan.json");
    fs::write(&ssp_path, ssp_str)
        .map_err(|e| vec![format!("Failed to write SSP history artifact: {}", e)])?;
    artifact_hashes.insert(
        "system-security-plan.json".to_string(),
        compute_bytes_sha256(ssp_str.as_bytes()),
    );

    // 2. Write SAP
    let sap_path = record_dir.join("assessment-plan.json");
    fs::write(&sap_path, sap_str)
        .map_err(|e| vec![format!("Failed to write SAP history artifact: {}", e)])?;
    artifact_hashes.insert(
        "assessment-plan.json".to_string(),
        compute_bytes_sha256(sap_str.as_bytes()),
    );

    // 3. Write AR
    let ar_path = record_dir.join("assessment-results.json");
    fs::write(&ar_path, ar_str)
        .map_err(|e| vec![format!("Failed to write AR history artifact: {}", e)])?;
    artifact_hashes.insert(
        "assessment-results.json".to_string(),
        compute_bytes_sha256(ar_str.as_bytes()),
    );

    // 4. Write POA&M (if present)
    if let Some(p_str) = poam_str {
        let poam_path = record_dir.join("poam.json");
        fs::write(&poam_path, p_str)
            .map_err(|e| vec![format!("Failed to write POA&M history artifact: {}", e)])?;
        artifact_hashes.insert(
            "poam.json".to_string(),
            compute_bytes_sha256(p_str.as_bytes()),
        );
    }

    // 5. Write Telemetry digest
    let telemetry_str = serde_json::to_string_pretty(telemetry_val)
        .map_err(|e| vec![format!("Failed to serialize telemetry for history: {}", e)])?;
    let telem_path = record_dir.join("telemetry.json");
    fs::write(&telem_path, &telemetry_str)
        .map_err(|e| vec![format!("Failed to write telemetry history artifact: {}", e)])?;
    artifact_hashes.insert(
        "telemetry.json".to_string(),
        compute_bytes_sha256(telemetry_str.as_bytes()),
    );

    let index = HistoryRecordIndex {
        record_id: record_id.clone(),
        timestamp: now,
        git_sha,
        record_kind: record_kind.to_string(),
        parent_record_id: find_latest_prior_record_id(history_root, &record_id),
        toolchains: collect_host_toolchains(),
        schema_hashes: get_pinned_schema_hashes(),
        artifact_hashes,
        gate_outcome: gate_outcome.map(|s| s.to_string()),
        git_tag,
    };

    let index_str = serde_json::to_string_pretty(&index)
        .map_err(|e| vec![format!("Failed to serialize history index: {}", e)])?;
    fs::write(record_dir.join("index.json"), &index_str).map_err(|e| {
        vec![format!(
            "Failed to write index.json in {}: {}",
            record_dir.display(),
            e
        )]
    })?;

    // 6. Enforce retention pruning
    let ret_cfg = retention.cloned().unwrap_or_default();
    let _ = prune_history_records(history_root, &ret_cfg);

    Ok(index)
}

/// Finds the most recent prior history record ID in history root
fn find_latest_prior_record_id(history_root: &Path, current_record_id: &str) -> Option<String> {
    let mut records = Vec::new();
    if let Ok(entries) = fs::read_dir(history_root) {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if name != current_record_id && entry.path().join("index.json").exists() {
                    records.push(name);
                }
            }
        }
    }
    records.sort();
    records.pop()
}

/// Prunes older history records exceeding `max_records`, preserving tagged releases
pub fn prune_history_records(
    history_root: &Path,
    config: &HistoryRetentionConfig,
) -> Result<Vec<String>, std::io::Error> {
    if !history_root.exists() {
        return Ok(Vec::new());
    }

    struct RecordItem {
        id: String,
        timestamp: DateTime<Utc>,
        is_tagged: bool,
        path: PathBuf,
    }

    let mut records: Vec<RecordItem> = Vec::new();

    for entry in fs::read_dir(history_root)? {
        let entry = entry?;
        let path = entry.path();
        let index_path = path.join("index.json");
        if index_path.exists() {
            if let Ok(content) = fs::read_to_string(&index_path) {
                if let Ok(index) = serde_json::from_str::<HistoryRecordIndex>(&content) {
                    let id = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string();
                    records.push(RecordItem {
                        id,
                        timestamp: index.timestamp,
                        is_tagged: index.git_tag.is_some(),
                        path,
                    });
                }
            }
        }
    }

    if records.len() <= config.max_records {
        return Ok(Vec::new());
    }

    // Sort ascending by timestamp (oldest first)
    records.sort_by_key(|a| a.timestamp);

    let mut surplus = records.len() - config.max_records;
    let mut pruned = Vec::new();

    for item in records {
        if surplus == 0 {
            break;
        }
        if config.retain_tagged_releases && item.is_tagged {
            continue; // Retain tagged release
        }

        if fs::remove_dir_all(&item.path).is_ok() {
            eprintln!(
                "[HISTORY PRUNE] Pruned historical record '{}' exceeding retention limit (max: {})",
                item.id, config.max_records
            );
            pruned.push(item.id);
            surplus -= 1;
        }
    }

    Ok(pruned)
}

/// Evaluates byte-for-byte replay verification of a historical continuous authorization record
pub fn replay_history_record(
    record_dir: &Path,
    verify_toolchains: bool,
) -> Result<ReplayReport, Vec<String>> {
    let index_path = record_dir.join("index.json");
    if !index_path.exists() {
        return Err(vec![format!(
            "History record directory '{}' is missing index.json [{}]",
            record_dir.display(),
            OscalErrorCode::ReplayMismatch.as_str()
        )]);
    }

    let index_str = fs::read_to_string(&index_path)
        .map_err(|e| vec![format!("Failed to read index.json: {}", e)])?;
    let index: HistoryRecordIndex = serde_json::from_str(&index_str)
        .map_err(|e| vec![format!("Failed to parse index.json: {}", e)])?;

    let mut errors = Vec::new();

    // 1. Toolchain verification
    if verify_toolchains {
        let host_toolchains = collect_host_toolchains();
        for (tool, expected_ver) in &index.toolchains {
            if let Some(host_ver) = host_toolchains.get(tool) {
                if host_ver != expected_ver
                    && !expected_ver.contains("unknown")
                    && !host_ver.contains("unknown")
                {
                    errors.push(format!(
                        "Replay toolchain mismatch for '{}': recorded version is '{}', but host environment has '{}' [{}]",
                        tool, expected_ver, host_ver, OscalErrorCode::ReplayToolchainMismatch.as_str()
                    ));
                }
            }
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    // 2. Artifact byte-for-byte fidelity & schema conformance
    let mut verified_artifacts = Vec::new();

    for (file_name, expected_sha256) in &index.artifact_hashes {
        let file_path = record_dir.join(file_name);
        if !file_path.exists() {
            errors.push(format!(
                "Replay failed: recorded artifact '{}' is missing from historical directory [{}]",
                file_name,
                OscalErrorCode::ReplayMismatch.as_str()
            ));
            continue;
        }

        let bytes = fs::read(&file_path)
            .map_err(|e| vec![format!("Failed to read '{}': {}", file_path.display(), e)])?;
        let computed_sha256 = compute_bytes_sha256(&bytes);

        if &computed_sha256 != expected_sha256 {
            errors.push(format!(
                "Replay artifact mismatch for '{}': computed hash '{}' differs from recorded hash '{}' [{}]",
                file_name, computed_sha256, expected_sha256, OscalErrorCode::ReplayMismatch.as_str()
            ));
            continue;
        }

        // Validate schema conformance of recorded artifact
        let json_val: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!(
                    "Replay failed: artifact '{}' is malformed JSON: {} [{}]",
                    file_name,
                    e,
                    OscalErrorCode::ReplayMismatch.as_str()
                ));
                continue;
            }
        };

        match file_name.as_str() {
            "system-security-plan.json" => {
                if let Err(schema_errs) = validate_system_security_plan(&json_val) {
                    errors.push(format!(
                        "Recorded SSP fails schema validation: {:?} [{}]",
                        schema_errs,
                        OscalErrorCode::ReplayMismatch.as_str()
                    ));
                }
            }
            "assessment-plan.json" => {
                if let Err(schema_errs) = validate_assessment_plan(&json_val) {
                    errors.push(format!(
                        "Recorded SAP fails schema validation: {:?} [{}]",
                        schema_errs,
                        OscalErrorCode::ReplayMismatch.as_str()
                    ));
                }
            }
            "assessment-results.json" => {
                if let Err(schema_errs) = validate_assessment_results(&json_val) {
                    errors.push(format!(
                        "Recorded AR fails schema validation: {:?} [{}]",
                        schema_errs,
                        OscalErrorCode::ReplayMismatch.as_str()
                    ));
                }
            }
            "poam.json" => {
                if let Err(schema_errs) = validate_poam(&json_val) {
                    errors.push(format!(
                        "Recorded POA&M fails schema validation: {:?} [{}]",
                        schema_errs,
                        OscalErrorCode::ReplayMismatch.as_str()
                    ));
                }
            }
            _ => {} // telemetry.json is unstructured map
        }

        verified_artifacts.push(file_name.clone());
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    Ok(ReplayReport {
        record_id: index.record_id,
        verified_artifacts,
        toolchains_verified: verify_toolchains,
        schemas_verified: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_git_sha_resolution_fallback_chain() {
        let repo_root = Path::new(".");

        unsafe {
            std::env::set_var("GIT_SHA", "test_env_sha_123456789");
        }
        assert_eq!(resolve_git_sha(repo_root), "test_env_sha_123456789");

        unsafe {
            std::env::remove_var("GIT_SHA");
            std::env::set_var("CI_COMMIT_SHA", "test_ci_sha_987654321");
        }
        assert_eq!(resolve_git_sha(repo_root), "test_ci_sha_987654321");

        unsafe {
            std::env::remove_var("CI_COMMIT_SHA");
        }
        let resolved = resolve_git_sha(repo_root);
        assert!(
            !resolved.is_empty(),
            "Must resolve either git commit or nogit"
        );
    }

    #[test]
    fn test_same_second_collision_suffix() {
        let test_dir = Path::new("target/test_history_collision");
        let _ = fs::remove_dir_all(test_dir);
        fs::create_dir_all(test_dir).unwrap();

        let now = DateTime::parse_from_rfc3339("2026-11-10T15:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let git_sha = "abcdef123456789";

        // 1st record: no suffix
        let r1 = generate_record_id(test_dir, now, git_sha);
        assert_eq!(r1, "2026-11-10T15-30-00Z_abcdef1");
        fs::create_dir(test_dir.join(&r1)).unwrap();

        // 2nd record same second: .1
        let r2 = generate_record_id(test_dir, now, git_sha);
        assert_eq!(r2, "2026-11-10T15-30-00Z_abcdef1.1");
        fs::create_dir(test_dir.join(&r2)).unwrap();

        // 3rd record same second: .2
        let r3 = generate_record_id(test_dir, now, git_sha);
        assert_eq!(r3, "2026-11-10T15-30-00Z_abcdef1.2");

        let _ = fs::remove_dir_all(test_dir);
    }

    #[test]
    fn test_retention_policy_prunes_oldest_non_tagged() {
        let test_dir = Path::new("target/test_history_retention");
        let _ = fs::remove_dir_all(test_dir);
        fs::create_dir_all(test_dir).unwrap();

        let base_time = DateTime::parse_from_rfc3339("2026-11-10T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        // Create 5 records: record 0, 1, 2, 3, 4
        // Record 1 is tagged ("v1.0.0")
        for i in 0..5 {
            let t = base_time + chrono::Duration::hours(i);
            let id = format!("rec_{}", i);
            let dir = test_dir.join(&id);
            fs::create_dir_all(&dir).unwrap();

            let tag = if i == 1 {
                Some("v1.0.0".to_string())
            } else {
                None
            };
            let index = HistoryRecordIndex {
                record_id: id,
                timestamp: t,
                git_sha: format!("sha_{}", i),
                record_kind: "release".to_string(),
                parent_record_id: None,
                toolchains: BTreeMap::new(),
                schema_hashes: BTreeMap::new(),
                artifact_hashes: BTreeMap::new(),
                gate_outcome: Some("passed".to_string()),
                git_tag: tag,
            };
            fs::write(
                dir.join("index.json"),
                serde_json::to_string(&index).unwrap(),
            )
            .unwrap();
        }

        // Retention: max 3 records, retain tagged releases
        let config = HistoryRetentionConfig {
            max_records: 3,
            retain_tagged_releases: true,
        };

        let pruned = prune_history_records(test_dir, &config).unwrap();
        assert_eq!(pruned.len(), 2, "Should prune 2 records to reach max 3");
        assert_eq!(pruned, vec!["rec_0".to_string(), "rec_2".to_string()]);

        // Record 0 was oldest untagged: pruned
        assert!(!test_dir.join("rec_0").exists());
        // Record 1 was tagged: retained despite being old!
        assert!(test_dir.join("rec_1").exists());
        // Record 2 was next oldest untagged: pruned
        assert!(!test_dir.join("rec_2").exists());
        // Records 3 and 4: retained
        assert!(test_dir.join("rec_3").exists());
        assert!(test_dir.join("rec_4").exists());

        let _ = fs::remove_dir_all(test_dir);
    }

    #[test]
    fn test_replay_lifecycle_and_defect_detection() {
        let test_dir = Path::new("target/test_history_replay");
        let _ = fs::remove_dir_all(test_dir);
        fs::create_dir_all(test_dir).unwrap();

        let now = Utc::now();
        let repo_root = Path::new(".");

        let index = emit_history_record(
            test_dir,
            "release",
            "{\"system-security-plan\":{}}",
            "{\"assessment-plan\":{}}",
            "{\"assessment-results\":{}}",
            Some("{\"plan-of-action-and-milestones\":{}}"),
            &serde_json::json!({ "total": 7 }),
            now,
            repo_root,
            None,
            Some("passed"),
        )
        .unwrap();

        let record_dir = test_dir.join(&index.record_id);

        // Verify SHA-256 matches
        let ssp_file = record_dir.join("system-security-plan.json");
        let hash = compute_file_sha256(&ssp_file).unwrap();
        assert_eq!(hash, index.artifact_hashes["system-security-plan.json"]);

        // Tamper with artifact: mutate content
        fs::write(&ssp_file, "TAMPERED_CONTENT").unwrap();
        let replay_res = replay_history_record(&record_dir, false);
        assert!(replay_res.is_err());
        let errs = replay_res.unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains("E-OSCAL-019")),
            "Tampered artifact must fail with E-OSCAL-019: {:?}",
            errs
        );

        let _ = fs::remove_dir_all(test_dir);
    }
}

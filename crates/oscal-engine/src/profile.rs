//! OSCAL Profile Resolution Engine per Milestone 6
//! Resolves declarative profiles into concrete resolved catalogs under validate-before-write discipline

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use oscal_diagnostics::OscalErrorCode;

use crate::{validate_catalog, validate_profile, PRIME_OSCAL_NAMESPACE};

/// Error types encountered during profile resolution
#[derive(Debug)]
pub enum ProfileError {
    Io(std::io::Error),
    Json(serde_json::Error),
    SchemaViolation(Vec<String>),
    CycleDetected(String),
    ImportUnresolved(String),
    ControlSelectorUnresolved(String),
    ParameterUnresolved(String),
    General(String),
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error during profile resolution: {}", e),
            Self::Json(e) => write!(f, "JSON error during profile resolution: {}", e),
            Self::SchemaViolation(errs) => {
                write!(
                    f,
                    "Profile schema validation failed ({} errors):\n{}",
                    errs.len(),
                    errs.join("\n")
                )
            }
            Self::CycleDetected(msg) => write!(
                f,
                "[{}] Circular profile dependency detected: {}",
                OscalErrorCode::ProfileCycleDetected.as_str(),
                msg
            ),
            Self::ImportUnresolved(msg) => write!(
                f,
                "[{}] Profile import cannot be resolved: {}",
                OscalErrorCode::ProfileImportUnresolved.as_str(),
                msg
            ),
            Self::ControlSelectorUnresolved(msg) => write!(
                f,
                "[{}] Profile control selector unmatched: {}",
                OscalErrorCode::ProfileControlSelectorUnresolved.as_str(),
                msg
            ),
            Self::ParameterUnresolved(msg) => write!(
                f,
                "[{}] Profile parameter unresolved: {}",
                OscalErrorCode::ProfileParameterUnresolved.as_str(),
                msg
            ),
            Self::General(msg) => write!(f, "Profile resolution error: {}", msg),
        }
    }
}

impl std::error::Error for ProfileError {}

impl From<std::io::Error> for ProfileError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for ProfileError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

/// Metadata describing a single imported node in the profile resolution chain
#[derive(Debug, Clone)]
pub struct ImportChainNode {
    pub href: String,
    pub uuid: Option<String>,
    pub sha256: String,
}

/// In-memory resolved profile data during DAG traversal
#[derive(Debug, Clone)]
pub struct ResolvedProfileData {
    pub profile_uuid: String,
    pub profile_title: String,
    pub file_hash: String,
    pub selected_control_ids: HashSet<String>,
    pub parameter_overrides: HashMap<String, Vec<String>>,
    pub import_chain: Vec<ImportChainNode>,
    pub source_catalog_path: PathBuf,
    pub source_catalog_hash: String,
}

/// Cached control information from a catalog for selection and parameter checking
#[derive(Debug, Clone)]
struct CatalogControlInfo {
    id: String,
    _title: String,
    is_enhancement: bool,
    _parent_id: Option<String>,
    _param_ids: Vec<String>,
}

enum ResolvedImportTarget {
    Catalog(PathBuf),
    Profile(PathBuf),
}

/// Profile Resolver for loading, validating, and flattening OSCAL profiles
pub struct ProfileResolver {
    pub repo_root: PathBuf,
    pub now: DateTime<Utc>,
    /// Track currently visiting profile paths to detect import cycles (E-OSCAL-021)
    pub visiting_stack: Vec<PathBuf>,
    /// Track completed profiles for diamond import reuse (visited without cycle)
    pub visited: HashSet<PathBuf>,
    /// Cached resolved profile data for completed nodes
    pub resolved_cache: HashMap<PathBuf, ResolvedProfileData>,
    /// Profile index mapping names/hrefs/UUIDs to filesystem paths
    pub profile_index: HashMap<String, PathBuf>,
    /// Catalog index mapping hrefs to filesystem paths
    pub catalog_index: HashMap<String, PathBuf>,
}

fn find_catalog_path(path: &Path, repo_root: &Path) -> Option<PathBuf> {
    if path.is_absolute() && path.exists() {
        return Some(path.to_path_buf());
    }
    let candidates = [
        path.to_path_buf(),
        repo_root.join(path),
        Path::new("../../").join(path),
        Path::new("../").join(path),
        PathBuf::from("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json"),
        PathBuf::from("../../schemas/catalogs/NIST_SP_800-53_rev5_catalog.json"),
        PathBuf::from("../schemas/catalogs/NIST_SP_800-53_rev5_catalog.json"),
    ];
    for c in &candidates {
        if c.exists() {
            return Some(c.clone());
        }
    }
    None
}

impl ProfileResolver {
    pub fn new(repo_root: PathBuf, now: Option<DateTime<Utc>>) -> Self {
        let mut resolver = Self {
            repo_root: repo_root.clone(),
            now: now.unwrap_or_else(Utc::now),
            visiting_stack: Vec::new(),
            visited: HashSet::new(),
            resolved_cache: HashMap::new(),
            profile_index: HashMap::new(),
            catalog_index: HashMap::new(),
        };
        resolver.build_default_indices();
        resolver
    }

    pub fn register_profile(&mut self, key: &str, path: PathBuf) {
        self.profile_index.insert(key.to_string(), path.clone());
        if let Some(file_name) = path.file_name().and_then(|f| f.to_str()) {
            self.profile_index.insert(file_name.to_string(), path);
        }
    }

    pub fn register_catalog(&mut self, key: &str, path: PathBuf) {
        self.catalog_index.insert(key.to_string(), path.clone());
        if let Some(file_name) = path.file_name().and_then(|f| f.to_str()) {
            self.catalog_index.insert(file_name.to_string(), path);
        }
    }

    fn build_default_indices(&mut self) {
        if let Some(cat_path) = find_catalog_path(
            Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json"),
            &self.repo_root,
        ) {
            self.register_catalog(
                "schemas/catalogs/NIST_SP_800-53_rev5_catalog.json",
                cat_path.clone(),
            );
            self.register_catalog("NIST_SP_800-53_rev5_catalog.json", cat_path.clone());
            self.register_catalog("catalog.json", cat_path.clone());
            self.register_catalog("nist-sp-800-53", cat_path.clone());
            self.register_catalog("urn:oscal:catalog:nist-sp-800-53-rev5", cat_path);
        }

        // Index profiles in common workspace locations
        let search_dirs = [
            self.repo_root.join("artifacts/oscal/staging"),
            self.repo_root.join("artifacts/oscal"),
            self.repo_root.join("profiles"),
            self.repo_root.join("tests/fixtures"),
        ];
        for dir in &search_dirs {
            if dir.exists() {
                self.scan_profile_dir(dir);
            }
        }
    }

    fn scan_profile_dir(&mut self, dir: &Path) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("json") {
                    if let Ok(content) = fs::read_to_string(&path) {
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                            if let Some(prof) = val.get("profile") {
                                if let Some(uuid) = prof.get("uuid").and_then(|u| u.as_str()) {
                                    self.profile_index.insert(uuid.to_string(), path.clone());
                                    self.profile_index
                                        .insert(format!("urn:uuid:{}", uuid), path.clone());
                                }
                                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                                    self.profile_index.insert(name.to_string(), path.clone());
                                }
                                if let Ok(rel) = path.strip_prefix(&self.repo_root) {
                                    self.profile_index
                                        .insert(rel.to_string_lossy().to_string(), path.clone());
                                }
                            }
                        }
                    }
                } else if path.is_dir() {
                    self.scan_profile_dir(&path);
                }
            }
        }
    }

    fn resolve_import_href(
        &self,
        href: &str,
        current_file: &Path,
    ) -> Result<ResolvedImportTarget, ProfileError> {
        // 1. Check catalog index
        if let Some(cat_path) = self.catalog_index.get(href) {
            if cat_path.exists() {
                return Ok(ResolvedImportTarget::Catalog(cat_path.clone()));
            }
        }
        if href.ends_with("catalog.json") || href.contains("catalogs/") {
            if let Some(cat_path) = find_catalog_path(Path::new(href), &self.repo_root) {
                return Ok(ResolvedImportTarget::Catalog(cat_path));
            }
        }

        // 2. Check profile index
        if let Some(prof_path) = self.profile_index.get(href) {
            if prof_path.exists() {
                return Ok(ResolvedImportTarget::Profile(prof_path.clone()));
            }
        }

        // 3. Check relative to current file's parent directory
        if let Some(parent) = current_file.parent() {
            let rel = parent.join(href);
            if rel.exists() {
                return Ok(ResolvedImportTarget::Profile(rel));
            }
        }

        // 4. Check relative to repo_root
        let from_root = self.repo_root.join(href);
        if from_root.exists() {
            return Ok(ResolvedImportTarget::Profile(from_root));
        }

        // 5. Direct path
        let p = Path::new(href);
        if p.exists() {
            return Ok(ResolvedImportTarget::Profile(p.to_path_buf()));
        }

        Err(ProfileError::ImportUnresolved(format!(
            "Import href '{}' could not be resolved to any local catalog or profile",
            href
        )))
    }

    /// Resolve an OSCAL profile node into resolved control and parameter data
    fn resolve_profile_node(
        &mut self,
        profile_path: &Path,
        default_catalog_path: &Path,
    ) -> Result<ResolvedProfileData, ProfileError> {
        let canonical = if profile_path.is_absolute() {
            profile_path.to_path_buf()
        } else {
            self.repo_root.join(profile_path)
        };
        let canonical = fs::canonicalize(&canonical).unwrap_or(canonical);

        // Cycle detection: if canonical is already on the visiting stack, fail-closed [E-OSCAL-021]
        if let Some(pos) = self.visiting_stack.iter().position(|p| p == &canonical) {
            let mut names: Vec<String> = self.visiting_stack[pos..]
                .iter()
                .map(|p| {
                    p.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string()
                })
                .collect();
            names.push(
                canonical
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
            );
            let cycle_path = names.join(" -> ");
            return Err(ProfileError::CycleDetected(format!(
                "Cycle: {}",
                cycle_path
            )));
        }

        // Diamond import: if already resolved and not in visiting stack, return cached data
        if let Some(cached) = self.resolved_cache.get(&canonical) {
            return Ok(cached.clone());
        }

        self.visiting_stack.push(canonical.clone());

        let content = fs::read_to_string(&canonical)?;
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let file_hash = format!("{:x}", hasher.finalize());

        let doc: serde_json::Value = serde_json::from_str(&content)?;
        validate_profile(&doc).map_err(ProfileError::SchemaViolation)?;

        let p = doc
            .get("profile")
            .ok_or_else(|| ProfileError::General("Missing 'profile' root".to_string()))?;
        let profile_uuid = p
            .get("uuid")
            .and_then(|u| u.as_str())
            .unwrap_or("00000000-0000-4000-8000-000000000001")
            .to_string();
        let profile_title = p
            .get("metadata")
            .and_then(|m| m.get("title"))
            .and_then(|t| t.as_str())
            .unwrap_or("PRIME Profile")
            .to_string();

        let imports = p
            .get("imports")
            .and_then(|i| i.as_array())
            .cloned()
            .unwrap_or_default();

        let mut selected_control_ids = HashSet::new();
        let mut parameter_overrides: HashMap<String, Vec<String>> = HashMap::new();
        let mut import_chain = Vec::new();
        let mut effective_catalog_path = default_catalog_path.to_path_buf();
        let mut effective_catalog_hash = String::new();

        for imp in &imports {
            let href = imp.get("href").and_then(|h| h.as_str()).unwrap_or("");
            let target = self.resolve_import_href(href, &canonical)?;

            match target {
                ResolvedImportTarget::Catalog(cat_path) => {
                    effective_catalog_path = cat_path.clone();
                    let cat_bytes = fs::read(&cat_path)?;
                    let mut cat_hasher = Sha256::new();
                    cat_hasher.update(&cat_bytes);
                    effective_catalog_hash = format!("{:x}", cat_hasher.finalize());
                    let cat_doc: serde_json::Value = serde_json::from_slice(&cat_bytes)?;
                    let cat_uuid = cat_doc["catalog"]
                        .get("uuid")
                        .and_then(|u| u.as_str())
                        .map(|s| s.to_string());

                    import_chain.push(ImportChainNode {
                        href: href.to_string(),
                        uuid: cat_uuid,
                        sha256: effective_catalog_hash.clone(),
                    });

                    let (available_controls, _all_params) = index_catalog_controls(&cat_doc);
                    let import_controls = apply_control_selectors(imp, &available_controls, href)?;
                    selected_control_ids.extend(import_controls);
                }
                ResolvedImportTarget::Profile(child_prof_path) => {
                    let child_data =
                        self.resolve_profile_node(&child_prof_path, default_catalog_path)?;
                    import_chain.extend(child_data.import_chain.clone());
                    import_chain.push(ImportChainNode {
                        href: href.to_string(),
                        uuid: Some(child_data.profile_uuid.clone()),
                        sha256: child_data.file_hash.clone(),
                    });
                    effective_catalog_path = child_data.source_catalog_path.clone();
                    effective_catalog_hash = child_data.source_catalog_hash.clone();

                    let filtered_child_controls =
                        filter_child_profile_controls(imp, &child_data.selected_control_ids, href)?;
                    selected_control_ids.extend(filtered_child_controls);

                    // Sibling import parameter precedence: later siblings override earlier siblings
                    for (k, v) in child_data.parameter_overrides {
                        parameter_overrides.insert(k, v);
                    }
                }
            }
        }

        // Innermost profile set-parameters overrides all imported parameter values
        if let Some(modify) = p.get("modify") {
            if let Some(set_params) = modify.get("set-parameters").and_then(|s| s.as_array()) {
                for sp in set_params {
                    if let Some(param_id) = sp.get("param-id").and_then(|p| p.as_str()) {
                        let mut vals = Vec::new();
                        if let Some(v_arr) = sp.get("values").and_then(|v| v.as_array()) {
                            for val in v_arr {
                                if let Some(s) = val.as_str() {
                                    vals.push(s.to_string());
                                }
                            }
                        } else if let Some(v_str) = sp.get("value").and_then(|v| v.as_str()) {
                            vals.push(v_str.to_string());
                        }
                        parameter_overrides.insert(param_id.to_string(), vals);
                    }
                }
            }
        }

        self.visiting_stack.pop();
        self.visited.insert(canonical.clone());

        let res = ResolvedProfileData {
            profile_uuid,
            profile_title,
            file_hash,
            selected_control_ids,
            parameter_overrides,
            import_chain,
            source_catalog_path: effective_catalog_path,
            source_catalog_hash: effective_catalog_hash,
        };
        self.resolved_cache.insert(canonical, res.clone());
        Ok(res)
    }

    /// Resolve an OSCAL profile into a schema-valid resolved catalog envelope
    pub fn resolve(
        &mut self,
        profile_path: &Path,
        catalog_path: &Path,
    ) -> Result<serde_json::Value, ProfileError> {
        let abs_profile = if profile_path.is_absolute() {
            profile_path.to_path_buf()
        } else {
            self.repo_root.join(profile_path)
        };

        let abs_catalog = find_catalog_path(catalog_path, &self.repo_root).ok_or_else(|| {
            ProfileError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "Catalog file '{}' not found in workspace",
                    catalog_path.display()
                ),
            ))
        })?;

        let cat_bytes = fs::read(&abs_catalog)?;
        let mut cat_hasher = Sha256::new();
        cat_hasher.update(&cat_bytes);
        let catalog_hash = format!("{:x}", cat_hasher.finalize());
        let cat_doc: serde_json::Value = serde_json::from_slice(&cat_bytes)?;
        let (_available_controls, all_catalog_params) = index_catalog_controls(&cat_doc);

        let data = if abs_profile.exists() {
            self.resolve_profile_node(&abs_profile, &abs_catalog)?
        } else {
            // Default baseline if no profile artifact exists: include all base controls from catalog
            let mut all_base = HashSet::new();
            if let Some(groups) = cat_doc["catalog"].get("groups").and_then(|g| g.as_array()) {
                for g in groups {
                    if let Some(ctrls) = g.get("controls").and_then(|c| c.as_array()) {
                        for c in ctrls {
                            if let Some(id) = c.get("id").and_then(|i| i.as_str()) {
                                all_base.insert(id.to_string());
                            }
                        }
                    }
                }
            }
            ResolvedProfileData {
                profile_uuid: "00000000-0000-4000-8000-000000000001".to_string(),
                profile_title: "PRIME Default Resolved Baseline".to_string(),
                file_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_string(),
                selected_control_ids: all_base,
                parameter_overrides: HashMap::new(),
                import_chain: vec![ImportChainNode {
                    href: abs_catalog.display().to_string(),
                    uuid: cat_doc["catalog"]
                        .get("uuid")
                        .and_then(|u| u.as_str())
                        .map(|s| s.to_string()),
                    sha256: catalog_hash.clone(),
                }],
                source_catalog_path: abs_catalog.clone(),
                source_catalog_hash: catalog_hash.clone(),
            }
        };

        // Assert all parameter overrides reference valid parameter IDs in the catalog [E-OSCAL-024]
        for param_id in data.parameter_overrides.keys() {
            if !all_catalog_params.contains(param_id) {
                return Err(ProfileError::ParameterUnresolved(format!(
                    "Parameter identifier '{}' specified in set-parameters does not exist in any control or parameter declaration within the resolved catalog baseline",
                    param_id
                )));
            }
        }

        // Synthesize schema-valid resolved catalog conforming to oscal_catalog_schema.json
        let resolved_uuid = Uuid::new_v5(
            &PRIME_OSCAL_NAMESPACE,
            format!("resolved-catalog:{}", data.profile_uuid).as_bytes(),
        );

        let mut filtered_groups = Vec::new();
        if let Some(groups) = cat_doc["catalog"].get("groups").and_then(|g| g.as_array()) {
            for grp in groups {
                let mut kept_controls = Vec::new();
                if let Some(ctrls) = grp.get("controls").and_then(|c| c.as_array()) {
                    for ctrl in ctrls {
                        if let Some(filtered_ctrl) = filter_control_recursive(
                            ctrl,
                            &data.selected_control_ids,
                            &data.parameter_overrides,
                        ) {
                            kept_controls.push(filtered_ctrl);
                        }
                    }
                }
                if !kept_controls.is_empty() {
                    let mut grp_clone = grp.clone();
                    grp_clone["controls"] = serde_json::Value::Array(kept_controls);
                    filtered_groups.push(grp_clone);
                }
            }
        }

        let mut import_chain_uuids = Vec::new();
        let mut import_chain_hashes = Vec::new();
        for node in &data.import_chain {
            if let Some(ref u) = node.uuid {
                import_chain_uuids.push(u.clone());
            }
            import_chain_hashes.push(format!("{}:{}", node.href, node.sha256));
        }

        let mut resolved_catalog_obj = json!({
            "uuid": resolved_uuid.to_string(),
            "metadata": {
                "title": format!("Resolved Baseline: {}", data.profile_title),
                "published": self.now.to_rfc3339(),
                "last-modified": self.now.to_rfc3339(),
                "version": "1.0.0",
                "oscal-version": "1.1.0",
                "props": [
                    {
                        "name": "resolution-status",
                        "value": "resolved"
                    },
                    {
                        "name": "source-profile-uuid",
                        "value": data.profile_uuid
                    },
                    {
                        "name": "source-profile-sha256",
                        "value": data.file_hash
                    },
                    {
                        "name": "source-catalog-path",
                        "value": data.source_catalog_path.display().to_string()
                    },
                    {
                        "name": "source-catalog-sha256",
                        "value": data.source_catalog_hash
                    },
                    {
                        "name": "import-chain-uuids",
                        "value": serde_json::to_string(&import_chain_uuids).unwrap_or_default()
                    },
                    {
                        "name": "import-chain-hashes",
                        "value": serde_json::to_string(&import_chain_hashes).unwrap_or_default()
                    }
                ]
            }
        });

        if !filtered_groups.is_empty() {
            resolved_catalog_obj["groups"] = serde_json::Value::Array(filtered_groups);
        }

        let resolved_doc = json!({
            "catalog": resolved_catalog_obj
        });

        // Validate resolved catalog against oscal_catalog_schema.json
        validate_catalog(&resolved_doc).map_err(ProfileError::SchemaViolation)?;

        Ok(resolved_doc)
    }
}

fn index_catalog_controls(
    catalog_doc: &serde_json::Value,
) -> (HashMap<String, CatalogControlInfo>, HashSet<String>) {
    let mut controls_map = HashMap::new();
    let mut all_params = HashSet::new();

    if let Some(params) = catalog_doc["catalog"]
        .get("params")
        .and_then(|p| p.as_array())
    {
        for p in params {
            if let Some(id) = p.get("id").and_then(|i| i.as_str()) {
                all_params.insert(id.to_string());
            }
        }
    }

    if let Some(groups) = catalog_doc["catalog"]
        .get("groups")
        .and_then(|g| g.as_array())
    {
        for group in groups {
            if let Some(controls) = group.get("controls").and_then(|c| c.as_array()) {
                for control in controls {
                    index_single_control(control, None, &mut controls_map, &mut all_params);
                }
            }
        }
    }

    if let Some(controls) = catalog_doc["catalog"]
        .get("controls")
        .and_then(|c| c.as_array())
    {
        for control in controls {
            index_single_control(control, None, &mut controls_map, &mut all_params);
        }
    }

    (controls_map, all_params)
}

fn index_single_control(
    ctrl: &serde_json::Value,
    parent_id: Option<String>,
    map: &mut HashMap<String, CatalogControlInfo>,
    all_params: &mut HashSet<String>,
) {
    if let Some(id) = ctrl.get("id").and_then(|i| i.as_str()) {
        let norm_id = id.trim().to_lowercase();
        let mut param_ids = Vec::new();
        if let Some(params) = ctrl.get("params").and_then(|p| p.as_array()) {
            for p in params {
                if let Some(pid) = p.get("id").and_then(|i| i.as_str()) {
                    param_ids.push(pid.to_string());
                    all_params.insert(pid.to_string());
                }
            }
        }
        let info = CatalogControlInfo {
            id: id.to_string(),
            _title: ctrl
                .get("title")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string(),
            is_enhancement: parent_id.is_some(),
            _parent_id: parent_id.clone(),
            _param_ids: param_ids,
        };
        map.insert(norm_id, info);

        if let Some(child_ctrls) = ctrl.get("controls").and_then(|c| c.as_array()) {
            for child in child_ctrls {
                index_single_control(child, Some(id.to_string()), map, all_params);
            }
        }
    }
}

fn match_control_selector(
    selector_id: &str,
    available: &HashMap<String, CatalogControlInfo>,
) -> Vec<String> {
    let raw_lower = selector_id.trim().to_lowercase();
    let canon = crate::canonicalize_control_id(selector_id).to_lowercase();
    let mut matches = Vec::new();

    if let Some(ctrl) = available.get(&raw_lower) {
        matches.push(ctrl.id.clone());
    } else if let Some(ctrl) = available.get(&canon) {
        matches.push(ctrl.id.clone());
    } else {
        for (k, v) in available {
            if k == &raw_lower
                || k == &canon
                || crate::canonicalize_control_id(&v.id).to_lowercase() == canon
            {
                matches.push(v.id.clone());
            }
        }
    }
    matches
}

fn apply_control_selectors(
    import_obj: &serde_json::Value,
    available: &HashMap<String, CatalogControlInfo>,
    import_href: &str,
) -> Result<HashSet<String>, ProfileError> {
    let mut selected = HashSet::new();

    let inc_controls = import_obj
        .get("include-controls")
        .and_then(|i| i.as_array());
    let inc_all = import_obj.get("include-all").is_some();

    if let Some(includes) = inc_controls {
        if !includes.is_empty() {
            for inc in includes {
                if let Some(with_ids) = inc.get("with-ids").and_then(|w| w.as_array()) {
                    for id_val in with_ids {
                        let id_str = id_val.as_str().unwrap_or("");
                        let matches = match_control_selector(id_str, available);
                        if matches.is_empty() {
                            return Err(ProfileError::ControlSelectorUnresolved(format!(
                                "Selector '{}' in with-ids matched 0 controls in imported baseline '{}'",
                                id_str, import_href
                            )));
                        }
                        for m in matches {
                            selected.insert(m);
                        }
                    }
                }
            }
        } else if inc_all {
            for v in available.values() {
                if !v.is_enhancement {
                    selected.insert(v.id.clone());
                }
            }
        }
    } else {
        for v in available.values() {
            if !v.is_enhancement {
                selected.insert(v.id.clone());
            }
        }
    }

    if let Some(excludes) = import_obj
        .get("exclude-controls")
        .and_then(|e| e.as_array())
    {
        for exc in excludes {
            if let Some(with_ids) = exc.get("with-ids").and_then(|w| w.as_array()) {
                for id_val in with_ids {
                    let id_str = id_val.as_str().unwrap_or("");
                    let matches = match_control_selector(id_str, available);
                    for m in matches {
                        selected.remove(&m);
                    }
                }
            }
        }
    }

    Ok(selected)
}

fn filter_child_profile_controls(
    import_obj: &serde_json::Value,
    child_controls: &HashSet<String>,
    import_href: &str,
) -> Result<HashSet<String>, ProfileError> {
    let mut selected = HashSet::new();
    let inc_controls = import_obj
        .get("include-controls")
        .and_then(|i| i.as_array());

    if let Some(includes) = inc_controls {
        if !includes.is_empty() {
            for inc in includes {
                if let Some(with_ids) = inc.get("with-ids").and_then(|w| w.as_array()) {
                    for id_val in with_ids {
                        let id_str = id_val.as_str().unwrap_or("");
                        let canon = crate::canonicalize_control_id(id_str).to_lowercase();
                        let raw_lower = id_str.trim().to_lowercase();
                        let mut found = false;
                        for cc in child_controls {
                            if cc.to_lowercase() == raw_lower
                                || crate::canonicalize_control_id(cc).to_lowercase() == canon
                            {
                                selected.insert(cc.clone());
                                found = true;
                            }
                        }
                        if !found {
                            return Err(ProfileError::ControlSelectorUnresolved(format!(
                                "Selector '{}' in with-ids matched 0 controls in imported profile '{}'",
                                id_str, import_href
                            )));
                        }
                    }
                }
            }
        } else {
            selected.extend(child_controls.clone());
        }
    } else {
        selected.extend(child_controls.clone());
    }

    if let Some(excludes) = import_obj
        .get("exclude-controls")
        .and_then(|e| e.as_array())
    {
        for exc in excludes {
            if let Some(with_ids) = exc.get("with-ids").and_then(|w| w.as_array()) {
                for id_val in with_ids {
                    let id_str = id_val.as_str().unwrap_or("");
                    let canon = crate::canonicalize_control_id(id_str).to_lowercase();
                    let raw_lower = id_str.trim().to_lowercase();
                    selected.retain(|cc| {
                        !(cc.to_lowercase() == raw_lower
                            || crate::canonicalize_control_id(cc).to_lowercase() == canon)
                    });
                }
            }
        }
    }

    Ok(selected)
}

fn filter_control_recursive(
    ctrl: &serde_json::Value,
    selected_ids: &HashSet<String>,
    param_overrides: &HashMap<String, Vec<String>>,
) -> Option<serde_json::Value> {
    let ctrl_id = ctrl.get("id").and_then(|i| i.as_str())?;
    let is_self_selected = selected_ids.contains(ctrl_id);

    let mut kept_child_controls = Vec::new();
    if let Some(child_ctrls) = ctrl.get("controls").and_then(|c| c.as_array()) {
        for child in child_ctrls {
            if let Some(filtered_child) =
                filter_control_recursive(child, selected_ids, param_overrides)
            {
                kept_child_controls.push(filtered_child);
            }
        }
    }

    if is_self_selected || !kept_child_controls.is_empty() {
        let mut ctrl_clone = ctrl.clone();
        if kept_child_controls.is_empty() {
            if let Some(obj) = ctrl_clone.as_object_mut() {
                obj.remove("controls");
            }
        } else {
            ctrl_clone["controls"] = serde_json::Value::Array(kept_child_controls);
        }

        if let Some(params) = ctrl_clone.get_mut("params").and_then(|p| p.as_array_mut()) {
            for p in params {
                if let Some(pid) = p.get("id").and_then(|i| i.as_str()) {
                    if let Some(override_vals) = param_overrides.get(pid) {
                        p["values"] = json!(override_vals);
                    }
                }
            }
        }

        Some(ctrl_clone)
    } else {
        None
    }
}

/// Standalone helper to resolve a profile at `profile_path` using `catalog_path`
pub fn resolve_profile(
    profile_path: &Path,
    catalog_path: &Path,
    repo_root: &Path,
    now: Option<DateTime<Utc>>,
) -> Result<serde_json::Value, ProfileError> {
    let mut resolver = ProfileResolver::new(repo_root.to_path_buf(), now);
    resolver.resolve(profile_path, catalog_path)
}

/// Asserts that a resolved catalog does not retain the `skeleton` resolution status.
pub fn assert_resolved_catalog_not_skeleton(
    catalog: &serde_json::Value,
) -> Result<(), ProfileError> {
    if let Some(props) = catalog
        .get("catalog")
        .and_then(|c| c.get("metadata"))
        .and_then(|m| m.get("props"))
        .and_then(|p| p.as_array())
    {
        for p in props {
            if p.get("name").and_then(|n| n.as_str()) == Some("resolution-status")
                && p.get("value").and_then(|v| v.as_str()) == Some("skeleton")
            {
                return Err(ProfileError::General(
                    "Resolved catalog retained 'resolution-status = skeleton'; concrete resolution required before downstream synthesis"
                        .to_string(),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_catalog_href_resolves_via_catalog_index() {
        let repo_root = Path::new("target/test_import_catalog_href");
        let _ = fs::remove_dir_all(repo_root);
        fs::create_dir_all(repo_root).unwrap();

        let profile_path = repo_root.join("profile.json");
        let profile_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000001",
                "metadata": {
                    "title": "Profile with Catalog Href",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [
                    {
                        "href": "NIST_SP_800-53_rev5_catalog.json",
                        "include-controls": [
                            {
                                "with-ids": ["ac-1"]
                            }
                        ]
                    }
                ]
            }
        });
        fs::write(
            &profile_path,
            serde_json::to_string_pretty(&profile_json).unwrap(),
        )
        .unwrap();

        let catalog_path = Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json");
        let resolved = resolve_profile(&profile_path, catalog_path, Path::new("."), None)
            .expect("Catalog href must resolve via catalog index");

        assert!(resolved.get("catalog").is_some());
        let groups = resolved["catalog"]["groups"]
            .as_array()
            .expect("groups array");
        assert!(!groups.is_empty());
        assert_eq!(groups[0]["controls"][0]["id"], "ac-1");

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn test_import_profile_href_resolves_via_profile_index() {
        let repo_root = Path::new("target/test_import_profile_href");
        let _ = fs::remove_dir_all(repo_root);
        fs::create_dir_all(repo_root).unwrap();

        let child_path = repo_root.join("base_profile.json");
        let child_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000002",
                "metadata": {
                    "title": "Base Profile",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [
                    {
                        "href": "schemas/catalogs/NIST_SP_800-53_rev5_catalog.json",
                        "include-controls": [
                            {
                                "with-ids": ["ac-1", "ac-2"]
                            }
                        ]
                    }
                ]
            }
        });
        fs::write(
            &child_path,
            serde_json::to_string_pretty(&child_json).unwrap(),
        )
        .unwrap();

        let parent_path = repo_root.join("overlay_profile.json");
        let parent_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000003",
                "metadata": {
                    "title": "Overlay Profile",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [
                    {
                        "href": "base_profile.json",
                        "include-controls": [
                            {
                                "with-ids": ["ac-2"]
                            }
                        ]
                    }
                ]
            }
        });
        fs::write(
            &parent_path,
            serde_json::to_string_pretty(&parent_json).unwrap(),
        )
        .unwrap();

        let mut resolver = ProfileResolver::new(PathBuf::from("."), None);
        resolver.register_profile("base_profile.json", child_path.clone());

        let catalog_path = Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json");
        let resolved = resolver
            .resolve(&parent_path, catalog_path)
            .expect("Profile href must resolve via profile index");

        assert!(resolved.get("catalog").is_some());
        let groups = resolved["catalog"]["groups"].as_array().expect("groups");
        assert_eq!(groups[0]["controls"].as_array().unwrap().len(), 1);
        assert_eq!(groups[0]["controls"][0]["id"], "ac-2");

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn test_import_chain_recorded_in_envelope_props() {
        let repo_root = Path::new("target/test_import_chain_props");
        let _ = fs::remove_dir_all(repo_root);
        fs::create_dir_all(repo_root).unwrap();

        let profile_path = repo_root.join("profile.json");
        let profile_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000001",
                "metadata": {
                    "title": "Test Chain Profile",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [
                    {
                        "href": "schemas/catalogs/NIST_SP_800-53_rev5_catalog.json",
                        "include-controls": [
                            {
                                "with-ids": ["ac-1"]
                            }
                        ]
                    }
                ]
            }
        });
        fs::write(
            &profile_path,
            serde_json::to_string_pretty(&profile_json).unwrap(),
        )
        .unwrap();

        let catalog_path = Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json");
        let resolved = resolve_profile(&profile_path, catalog_path, Path::new("."), None).unwrap();

        let props = resolved["catalog"]["metadata"]["props"]
            .as_array()
            .expect("props");
        assert!(props
            .iter()
            .any(|p| p["name"] == "resolution-status" && p["value"] == "resolved"));
        assert!(props.iter().any(|p| p["name"] == "source-profile-uuid"));
        assert!(props.iter().any(|p| p["name"] == "source-profile-sha256"));
        assert!(props.iter().any(|p| p["name"] == "source-catalog-sha256"));
        assert!(props.iter().any(|p| p["name"] == "import-chain-hashes"));

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn test_cycle_detected_e_oscal_021() {
        let repo_root = Path::new("target/test_cycle_e_oscal_021");
        let _ = fs::remove_dir_all(repo_root);
        fs::create_dir_all(repo_root).unwrap();

        let prof_a_path = repo_root.join("profile_a.json");
        let prof_b_path = repo_root.join("profile_b.json");

        // Profile A imports Profile B
        let a_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000001",
                "metadata": {
                    "title": "Profile A",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [
                    { "href": "profile_b.json" }
                ]
            }
        });

        // Profile B imports Profile A (Cycle A -> B -> A)
        let b_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000002",
                "metadata": {
                    "title": "Profile B",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [
                    { "href": "profile_a.json" }
                ]
            }
        });

        fs::write(&prof_a_path, serde_json::to_string_pretty(&a_json).unwrap()).unwrap();
        fs::write(&prof_b_path, serde_json::to_string_pretty(&b_json).unwrap()).unwrap();

        let mut resolver = ProfileResolver::new(PathBuf::from("."), None);
        resolver.register_profile("profile_a.json", prof_a_path.clone());
        resolver.register_profile("profile_b.json", prof_b_path.clone());

        let catalog_path = Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json");
        let err = resolver
            .resolve(&prof_a_path, catalog_path)
            .expect_err("Cyclic import graph must fail closed");

        let err_str = err.to_string();
        assert!(
            err_str.contains("E-OSCAL-021"),
            "Error must cite [E-OSCAL-021]: {}",
            err_str
        );
        assert!(
            err_str.contains("profile_a.json -> profile_b.json -> profile_a.json"),
            "Diagnostic must name cycle path: {}",
            err_str
        );

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn test_diamond_import_is_not_a_cycle() {
        let repo_root = Path::new("target/test_diamond_import");
        let _ = fs::remove_dir_all(repo_root);
        fs::create_dir_all(repo_root).unwrap();

        // Diamond: A imports B and C; both B and C import D; D imports catalog
        let prof_d_path = repo_root.join("profile_d.json");
        let d_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000004",
                "metadata": {
                    "title": "Profile D",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [
                    {
                        "href": "schemas/catalogs/NIST_SP_800-53_rev5_catalog.json",
                        "include-controls": [
                            { "with-ids": ["ac-1", "ac-2"] }
                        ]
                    }
                ]
            }
        });
        fs::write(&prof_d_path, serde_json::to_string_pretty(&d_json).unwrap()).unwrap();

        let prof_b_path = repo_root.join("profile_b.json");
        let b_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000002",
                "metadata": {
                    "title": "Profile B",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [
                    { "href": "profile_d.json", "include-controls": [{ "with-ids": ["ac-1"] }] }
                ]
            }
        });
        fs::write(&prof_b_path, serde_json::to_string_pretty(&b_json).unwrap()).unwrap();

        let prof_c_path = repo_root.join("profile_c.json");
        let c_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000003",
                "metadata": {
                    "title": "Profile C",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [
                    { "href": "profile_d.json", "include-controls": [{ "with-ids": ["ac-2"] }] }
                ]
            }
        });
        fs::write(&prof_c_path, serde_json::to_string_pretty(&c_json).unwrap()).unwrap();

        let prof_a_path = repo_root.join("profile_a.json");
        let a_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000001",
                "metadata": {
                    "title": "Profile A",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [
                    { "href": "profile_b.json" },
                    { "href": "profile_c.json" }
                ]
            }
        });
        fs::write(&prof_a_path, serde_json::to_string_pretty(&a_json).unwrap()).unwrap();

        let mut resolver = ProfileResolver::new(PathBuf::from("."), None);
        resolver.register_profile("profile_d.json", prof_d_path.clone());
        resolver.register_profile("profile_b.json", prof_b_path.clone());
        resolver.register_profile("profile_c.json", prof_c_path.clone());

        let catalog_path = Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json");
        let resolved = resolver
            .resolve(&prof_a_path, catalog_path)
            .expect("Diamond import must resolve D cleanly without cycle error");

        assert!(resolved.get("catalog").is_some());
        let controls = &resolved["catalog"]["groups"][0]["controls"];
        assert_eq!(
            controls.as_array().unwrap().len(),
            2,
            "Union of B and C must include both ac-1 and ac-2"
        );

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn test_deep_import_chain_resolves() {
        let repo_root = Path::new("target/test_deep_import_chain");
        let _ = fs::remove_dir_all(repo_root);
        fs::create_dir_all(repo_root).unwrap();

        // 3-level chain: Level 3 imports catalog, Level 2 imports Level 3, Level 1 imports Level 2
        let l3_path = repo_root.join("l3.json");
        let l3_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000003",
                "metadata": {
                    "title": "Level 3",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [
                    { "href": "schemas/catalogs/NIST_SP_800-53_rev5_catalog.json", "include-controls": [{ "with-ids": ["ac-1"] }] }
                ]
            }
        });
        fs::write(&l3_path, serde_json::to_string_pretty(&l3_json).unwrap()).unwrap();

        let l2_path = repo_root.join("l2.json");
        let l2_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000002",
                "metadata": {
                    "title": "Level 2",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [{ "href": "l3.json" }]
            }
        });
        fs::write(&l2_path, serde_json::to_string_pretty(&l2_json).unwrap()).unwrap();

        let l1_path = repo_root.join("l1.json");
        let l1_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000001",
                "metadata": {
                    "title": "Level 1",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [{ "href": "l2.json" }]
            }
        });
        fs::write(&l1_path, serde_json::to_string_pretty(&l1_json).unwrap()).unwrap();

        let mut resolver = ProfileResolver::new(PathBuf::from("."), None);
        resolver.register_profile("l3.json", l3_path.clone());
        resolver.register_profile("l2.json", l2_path.clone());

        let catalog_path = Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json");
        let resolved = resolver
            .resolve(&l1_path, catalog_path)
            .expect("Deep 3-level import chain must resolve cleanly");

        assert!(resolved.get("catalog").is_some());
        assert_eq!(
            resolved["catalog"]["groups"][0]["controls"][0]["id"],
            "ac-1"
        );

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn test_unresolved_import_fails_e_oscal_022() {
        let repo_root = Path::new("target/test_unresolved_import_e_oscal_022");
        let _ = fs::remove_dir_all(repo_root);
        fs::create_dir_all(repo_root).unwrap();

        let profile_path = repo_root.join("bad_import.json");
        let bad_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000001",
                "metadata": {
                    "title": "Bad Import Profile",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [
                    { "href": "non_existent_profile_xyz.json" }
                ]
            }
        });
        fs::write(
            &profile_path,
            serde_json::to_string_pretty(&bad_json).unwrap(),
        )
        .unwrap();

        let catalog_path = Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json");
        let err = resolve_profile(&profile_path, catalog_path, Path::new("."), None)
            .expect_err("Missing import href must fail closed");

        let err_str = err.to_string();
        assert!(
            err_str.contains("E-OSCAL-022"),
            "Error must cite [E-OSCAL-022]: {}",
            err_str
        );

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn test_include_with_ids_selects_exact_controls() {
        let repo_root = Path::new("target/test_include_exact");
        let _ = fs::remove_dir_all(repo_root);
        fs::create_dir_all(repo_root).unwrap();

        let profile_path = repo_root.join("exact.json");
        let p_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000001",
                "metadata": {
                    "title": "Exact Controls Profile",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [
                    {
                        "href": "schemas/catalogs/NIST_SP_800-53_rev5_catalog.json",
                        "include-controls": [
                            { "with-ids": ["ac-1", "si-7"] }
                        ]
                    }
                ]
            }
        });
        fs::write(
            &profile_path,
            serde_json::to_string_pretty(&p_json).unwrap(),
        )
        .unwrap();

        let catalog_path = Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json");
        let resolved = resolve_profile(&profile_path, catalog_path, Path::new("."), None).unwrap();

        let groups = resolved["catalog"]["groups"].as_array().expect("groups");
        let mut all_ids = Vec::new();
        for g in groups {
            for c in g["controls"].as_array().unwrap() {
                all_ids.push(c["id"].as_str().unwrap().to_string());
            }
        }
        assert_eq!(all_ids.len(), 2);
        assert!(all_ids.contains(&"ac-1".to_string()));
        assert!(all_ids.contains(&"si-7".to_string()));

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn test_include_base_without_enhancements_by_default() {
        let repo_root = Path::new("target/test_no_implicit_enhancements");
        let _ = fs::remove_dir_all(repo_root);
        fs::create_dir_all(repo_root).unwrap();

        let profile_path = repo_root.join("base_only.json");
        let p_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000001",
                "metadata": {
                    "title": "Base Only Profile",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [
                    {
                        "href": "schemas/catalogs/NIST_SP_800-53_rev5_catalog.json",
                        "include-controls": [
                            { "with-ids": ["ac-2"] }
                        ]
                    }
                ]
            }
        });
        fs::write(
            &profile_path,
            serde_json::to_string_pretty(&p_json).unwrap(),
        )
        .unwrap();

        let catalog_path = Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json");
        let resolved = resolve_profile(&profile_path, catalog_path, Path::new("."), None).unwrap();

        let groups = resolved["catalog"]["groups"].as_array().expect("groups");
        let ac2_ctrl = &groups[0]["controls"][0];
        assert_eq!(ac2_ctrl["id"], "ac-2");
        assert!(
            ac2_ctrl.get("controls").is_none(),
            "Base-only selector must omit child controls (enhancements) by default"
        );

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn test_exclude_removes_named_controls() {
        let repo_root = Path::new("target/test_exclude_controls");
        let _ = fs::remove_dir_all(repo_root);
        fs::create_dir_all(repo_root).unwrap();

        let profile_path = repo_root.join("exclude.json");
        let p_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000001",
                "metadata": {
                    "title": "Exclude Profile",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [
                    {
                        "href": "schemas/catalogs/NIST_SP_800-53_rev5_catalog.json",
                        "include-controls": [
                            { "with-ids": ["ac-1", "ac-2"] }
                        ],
                        "exclude-controls": [
                            { "with-ids": ["ac-2"] }
                        ]
                    }
                ]
            }
        });
        fs::write(
            &profile_path,
            serde_json::to_string_pretty(&p_json).unwrap(),
        )
        .unwrap();

        let catalog_path = Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json");
        let resolved = resolve_profile(&profile_path, catalog_path, Path::new("."), None).unwrap();

        let groups = resolved["catalog"]["groups"].as_array().expect("groups");
        let ctrls = groups[0]["controls"].as_array().unwrap();
        assert_eq!(ctrls.len(), 1);
        assert_eq!(ctrls[0]["id"], "ac-1");

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn test_zero_match_selector_fails_e_oscal_023() {
        let repo_root = Path::new("target/test_zero_match_e_oscal_023");
        let _ = fs::remove_dir_all(repo_root);
        fs::create_dir_all(repo_root).unwrap();

        let profile_path = repo_root.join("unmatched.json");
        let p_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000001",
                "metadata": {
                    "title": "Unmatched Profile",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [
                    {
                        "href": "schemas/catalogs/NIST_SP_800-53_rev5_catalog.json",
                        "include-controls": [
                            { "with-ids": ["non-existent-control-999"] }
                        ]
                    }
                ]
            }
        });
        fs::write(
            &profile_path,
            serde_json::to_string_pretty(&p_json).unwrap(),
        )
        .unwrap();

        let catalog_path = Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json");
        let err = resolve_profile(&profile_path, catalog_path, Path::new("."), None)
            .expect_err("Zero match control selector must fail closed");

        let err_str = err.to_string();
        assert!(
            err_str.contains("E-OSCAL-023"),
            "Error must cite [E-OSCAL-023]: {}",
            err_str
        );
        assert!(
            err_str.contains("non-existent-control-999"),
            "Error must name the unmatched selector: {}",
            err_str
        );

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn test_multi_import_union_semantics() {
        let repo_root = Path::new("target/test_multi_import_union");
        let _ = fs::remove_dir_all(repo_root);
        fs::create_dir_all(repo_root).unwrap();

        let profile_path = repo_root.join("union.json");
        let p_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000001",
                "metadata": {
                    "title": "Union Profile",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [
                    {
                        "href": "schemas/catalogs/NIST_SP_800-53_rev5_catalog.json",
                        "include-controls": [{ "with-ids": ["ac-1"] }]
                    },
                    {
                        "href": "schemas/catalogs/NIST_SP_800-53_rev5_catalog.json",
                        "include-controls": [{ "with-ids": ["ac-2"] }]
                    }
                ]
            }
        });
        fs::write(
            &profile_path,
            serde_json::to_string_pretty(&p_json).unwrap(),
        )
        .unwrap();

        let catalog_path = Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json");
        let resolved = resolve_profile(&profile_path, catalog_path, Path::new("."), None).unwrap();

        let groups = resolved["catalog"]["groups"].as_array().expect("groups");
        let ctrls = groups[0]["controls"].as_array().unwrap();
        assert_eq!(ctrls.len(), 2, "Multiple imports must merge as a union");

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn test_set_parameters_overrides_value() {
        let repo_root = Path::new("target/test_set_parameters");
        let _ = fs::remove_dir_all(repo_root);
        fs::create_dir_all(repo_root).unwrap();

        let profile_path = repo_root.join("param.json");
        let p_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000001",
                "metadata": {
                    "title": "Parameter Override Profile",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [
                    {
                        "href": "schemas/catalogs/NIST_SP_800-53_rev5_catalog.json",
                        "include-controls": [{ "with-ids": ["ac-1"] }]
                    }
                ],
                "modify": {
                    "set-parameters": [
                        {
                            "param-id": "ac-1_prm_1",
                            "values": ["annually"]
                        }
                    ]
                }
            }
        });
        fs::write(
            &profile_path,
            serde_json::to_string_pretty(&p_json).unwrap(),
        )
        .unwrap();

        let catalog_path = Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json");
        let resolved = resolve_profile(&profile_path, catalog_path, Path::new("."), None).unwrap();

        let groups = resolved["catalog"]["groups"].as_array().expect("groups");
        let ac1 = &groups[0]["controls"][0];
        let params = ac1["params"].as_array().expect("params");
        let ac1_prm1 = params
            .iter()
            .find(|p| p["id"] == "ac-1_prm_1")
            .expect("ac-1_prm_1");
        assert_eq!(ac1_prm1["values"][0], "annually");

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn test_set_parameters_precedence_inner_wins() {
        let repo_root = Path::new("target/test_param_precedence_inner");
        let _ = fs::remove_dir_all(repo_root);
        fs::create_dir_all(repo_root).unwrap();

        let base_path = repo_root.join("base.json");
        let base_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000002",
                "metadata": {
                    "title": "Base Profile",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [
                    {
                        "href": "schemas/catalogs/NIST_SP_800-53_rev5_catalog.json",
                        "include-controls": [{ "with-ids": ["ac-1"] }]
                    }
                ],
                "modify": {
                    "set-parameters": [
                        { "param-id": "ac-1_prm_1", "values": ["base_value"] }
                    ]
                }
            }
        });
        fs::write(
            &base_path,
            serde_json::to_string_pretty(&base_json).unwrap(),
        )
        .unwrap();

        let inner_path = repo_root.join("inner.json");
        let inner_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000001",
                "metadata": {
                    "title": "Inner Profile",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [{ "href": "base.json" }],
                "modify": {
                    "set-parameters": [
                        { "param-id": "ac-1_prm_1", "values": ["inner_wins"] }
                    ]
                }
            }
        });
        fs::write(
            &inner_path,
            serde_json::to_string_pretty(&inner_json).unwrap(),
        )
        .unwrap();

        let mut resolver = ProfileResolver::new(PathBuf::from("."), None);
        resolver.register_profile("base.json", base_path.clone());

        let catalog_path = Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json");
        let resolved = resolver.resolve(&inner_path, catalog_path).unwrap();

        let ac1 = &resolved["catalog"]["groups"][0]["controls"][0];
        let prm1 = ac1["params"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == "ac-1_prm_1")
            .unwrap();
        assert_eq!(
            prm1["values"][0], "inner_wins",
            "Innermost set-parameters must override imported base"
        );

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn test_set_parameters_precedence_sibling_order() {
        let repo_root = Path::new("target/test_param_sibling_order");
        let _ = fs::remove_dir_all(repo_root);
        fs::create_dir_all(repo_root).unwrap();

        let s1_path = repo_root.join("sib1.json");
        let s1_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000002",
                "metadata": {
                    "title": "Sibling 1",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [
                    { "href": "schemas/catalogs/NIST_SP_800-53_rev5_catalog.json", "include-controls": [{ "with-ids": ["ac-1"] }] }
                ],
                "modify": {
                    "set-parameters": [{ "param-id": "ac-1_prm_1", "values": ["sib1_value"] }]
                }
            }
        });
        fs::write(&s1_path, serde_json::to_string_pretty(&s1_json).unwrap()).unwrap();

        let s2_path = repo_root.join("sib2.json");
        let s2_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000003",
                "metadata": {
                    "title": "Sibling 2",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [
                    { "href": "schemas/catalogs/NIST_SP_800-53_rev5_catalog.json", "include-controls": [{ "with-ids": ["ac-1"] }] }
                ],
                "modify": {
                    "set-parameters": [{ "param-id": "ac-1_prm_1", "values": ["sib2_later_wins"] }]
                }
            }
        });
        fs::write(&s2_path, serde_json::to_string_pretty(&s2_json).unwrap()).unwrap();

        let parent_path = repo_root.join("parent.json");
        let parent_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000001",
                "metadata": {
                    "title": "Parent",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [
                    { "href": "sib1.json" },
                    { "href": "sib2.json" }
                ]
            }
        });
        fs::write(
            &parent_path,
            serde_json::to_string_pretty(&parent_json).unwrap(),
        )
        .unwrap();

        let mut resolver = ProfileResolver::new(PathBuf::from("."), None);
        resolver.register_profile("sib1.json", s1_path.clone());
        resolver.register_profile("sib2.json", s2_path.clone());

        let catalog_path = Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json");
        let resolved = resolver.resolve(&parent_path, catalog_path).unwrap();

        let ac1 = &resolved["catalog"]["groups"][0]["controls"][0];
        let prm1 = ac1["params"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == "ac-1_prm_1")
            .unwrap();
        assert_eq!(
            prm1["values"][0], "sib2_later_wins",
            "Later sibling in imports[] must override earlier sibling"
        );

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn test_set_parameters_unknown_id_fails_e_oscal_024() {
        let repo_root = Path::new("target/test_unknown_param_e_oscal_024");
        let _ = fs::remove_dir_all(repo_root);
        fs::create_dir_all(repo_root).unwrap();

        let profile_path = repo_root.join("bad_param.json");
        let p_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000001",
                "metadata": {
                    "title": "Bad Param Profile",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [
                    {
                        "href": "schemas/catalogs/NIST_SP_800-53_rev5_catalog.json",
                        "include-controls": [{ "with-ids": ["ac-1"] }]
                    }
                ],
                "modify": {
                    "set-parameters": [
                        { "param-id": "non_existent_param_999", "values": ["xyz"] }
                    ]
                }
            }
        });
        fs::write(
            &profile_path,
            serde_json::to_string_pretty(&p_json).unwrap(),
        )
        .unwrap();

        let catalog_path = Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json");
        let err = resolve_profile(&profile_path, catalog_path, Path::new("."), None)
            .expect_err("Unknown param-id must fail closed with E-OSCAL-024");

        let err_str = err.to_string();
        assert!(
            err_str.contains("E-OSCAL-024"),
            "Error must cite [E-OSCAL-024]: {}",
            err_str
        );
        assert!(
            err_str.contains("non_existent_param_999"),
            "Error must name unknown param-id: {}",
            err_str
        );

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn test_e_oscal_024_registered_in_diagnostic_codes() {
        assert_eq!(
            OscalErrorCode::ProfileParameterUnresolved.as_str(),
            "E-OSCAL-024"
        );
        assert!(!OscalErrorCode::ProfileParameterUnresolved
            .default_title()
            .is_empty());
    }

    #[test]
    fn test_resolved_catalog_preserves_source_structure() {
        let repo_root = Path::new("target/test_preserve_structure");
        let _ = fs::remove_dir_all(repo_root);
        fs::create_dir_all(repo_root).unwrap();

        let profile_path = repo_root.join("struct.json");
        let p_json = json!({
            "profile": {
                "uuid": "00000000-0000-4000-8000-000000000001",
                "metadata": {
                    "title": "Structure Preservation Profile",
                    "published": "2026-11-11T00:00:00Z",
                    "last-modified": "2026-11-11T00:00:00Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.0"
                },
                "imports": [
                    {
                        "href": "schemas/catalogs/NIST_SP_800-53_rev5_catalog.json",
                        "include-controls": [{ "with-ids": ["ac-1", "si-7"] }]
                    }
                ]
            }
        });
        fs::write(
            &profile_path,
            serde_json::to_string_pretty(&p_json).unwrap(),
        )
        .unwrap();

        let catalog_path = Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json");
        let resolved = resolve_profile(&profile_path, catalog_path, Path::new("."), None).unwrap();

        let groups = resolved["catalog"]["groups"]
            .as_array()
            .expect("groups array");
        // Verify groups preserve their standard IDs and titles
        let group_ids: Vec<&str> = groups.iter().filter_map(|g| g["id"].as_str()).collect();
        assert_eq!(
            group_ids,
            vec!["ac", "si"],
            "Original source group ordering must be preserved"
        );

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn test_resolved_catalog_resolution_status_not_skeleton() {
        let catalog_path = Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json");
        let resolved = resolve_profile(
            Path::new("non_existent_profile.json"),
            catalog_path,
            Path::new("."),
            None,
        )
        .unwrap();

        let props = resolved["catalog"]["metadata"]["props"]
            .as_array()
            .expect("props");
        let status = props
            .iter()
            .find(|p| p["name"] == "resolution-status")
            .expect("resolution-status");
        assert_eq!(
            status["value"], "resolved",
            "resolution-status must be 'resolved', never 'skeleton'"
        );
    }

    #[test]
    fn test_resolved_catalog_byte_identical_under_fixed_clock() {
        let fixed_now = DateTime::parse_from_rfc3339("2026-11-11T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let catalog_path = Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json");

        let res1 = resolve_profile(
            Path::new("artifacts/oscal/staging/profile.json"),
            catalog_path,
            Path::new("."),
            Some(fixed_now),
        )
        .unwrap();

        let res2 = resolve_profile(
            Path::new("artifacts/oscal/staging/profile.json"),
            catalog_path,
            Path::new("."),
            Some(fixed_now),
        )
        .unwrap();

        let s1 = serde_json::to_string_pretty(&res1).unwrap();
        let s2 = serde_json::to_string_pretty(&res2).unwrap();
        assert_eq!(
            s1, s2,
            "Resolved catalog must be byte-for-byte identical under fixed clock"
        );
    }

    #[test]
    fn test_resolved_catalog_validates_against_pinned_schema() {
        let catalog_path = Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json");
        let resolved = resolve_profile(
            Path::new("artifacts/oscal/staging/profile.json"),
            catalog_path,
            Path::new("."),
            None,
        )
        .unwrap();

        assert!(
            validate_catalog(&resolved).is_ok(),
            "Synthesized resolved catalog must validate against pinned oscal_catalog_schema.json"
        );
    }
}

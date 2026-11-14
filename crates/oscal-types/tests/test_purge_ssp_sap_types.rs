#[test]
fn test_oscal_types_no_longer_contains_ssp_sap_types() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let src_dir = manifest_dir.join("src");
    let ssp_rs = src_dir.join("ssp.rs");
    let sap_rs = src_dir.join("sap.rs");
    let lib_rs = std::fs::read_to_string(src_dir.join("lib.rs")).expect("lib.rs exists");

    assert!(
        !ssp_rs.exists(),
        "LexLean §31: SSP typify types must be purged from oscal-types: ssp.rs still exists"
    );
    assert!(
        !sap_rs.exists(),
        "LexLean §31: SAP typify types must be purged from oscal-types: sap.rs still exists"
    );
    assert!(
        !lib_rs.contains("pub mod ssp;"),
        "LexLean §31: lib.rs must not declare `pub mod ssp;`"
    );
    assert!(
        !lib_rs.contains("pub mod sap;"),
        "LexLean §31: lib.rs must not declare `pub mod sap;`"
    );
    assert!(
        !lib_rs.contains("OscalSspDocument"),
        "LexLean §31: lib.rs must not declare `OscalSspDocument`"
    );
    assert!(
        !lib_rs.contains("OscalAssessmentPlanDocument"),
        "LexLean §31: lib.rs must not declare `OscalAssessmentPlanDocument`"
    );
}

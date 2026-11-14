Feature: verification

  The verification engine and .pcrate offline verification pipeline: given release artifacts, evidence, and provenance bundles, it enforces file hash integrity, NIST OSCAL schema conformity, and deterministic gate re-derivation.

  @PP-01 @build
  Scenario: The .pcrate hermetic verifier enforces file hash integrity and MANIFEST.SHA256 matching across all release artifacts
    Given a .pcrate bundle with MANIFEST.SHA256 and release files
    When verify_pcrate_dir executes against the bundle
    Then it computes the SHA-256 hash of each file and fails closed with an Invariant 1 violation if any hash diverges

  @PP-02 @build
  Scenario: The .pcrate verifier validates evidence and manifest structures against pinned NIST OSCAL 1.1.0 JSON schemas
    Given a .pcrate bundle containing evidence.json or PCrate.toml
    When verify_pcrate_dir validates the JSON objects against vendored schemas
    Then it fails closed with an Invariant 2 violation if any schema constraint is violated

  @PP-03 @build
  Scenario: The .pcrate verifier deterministically re-derives gate decisions and policy compliance from bundled provenance
    Given a .pcrate bundle with bundled lean-rust.toml policy and gate-decision.json
    When verify_pcrate_dir re-derives coverage, tier satisfaction, and policy thresholds
    Then it fails closed with an Invariant 3 violation if the re-derived outcome diverges from the bundled decision

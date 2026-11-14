# PRIMAL: UOR Template Integrated with PRIME Verification Engine

PRIMAL is a verified UOR (Universal Object Repository) project instance integrating the **PRIME / PIRTM** formal verification and continuous authorization pipeline. It bridges executable Rust software, bounded model checking (Kani), interactive theorem proving in Lean 4 (with zero classical axioms in its core arithmetic fragment), and NIST OSCAL 1.1.0 continuous compliance gating into portable, hermetically verifiable `.pcrate` release bundles.

## Executive Summary
PRIMAL enforces end-to-end formal verification and continuous authorization per the UOR template contract. It combines template-governed project content with PRIME's verification engine (`cargo oscal`), binding NIST OSCAL 1.1.0 components and control objectives directly to machine-checked kernel proofs and bounded model check trajectories.

## Mathematical Overview
- **Zero-Classical-Axiom Peano Substrate**: Core arithmetic and verification primitives (`toNat_mul`, `toPosRat_respects_equiv`, Peano induction) are mechanically verified in Lean 4 with absolute zero dependence on classical axioms (`propext`, `Quot.sound`, `Classical.choice`).
- **Zeno Contractivity & Gain Bounds**: Runtime feedback and unrolling mechanisms enforce $\kappa \le 1/\Phi^2 \approx 0.382$ (where $\Phi$ is the golden ratio), ensuring contractivity and stability across recursive fixpoint trajectories.
- **Canonical Representation & Manifestation Format (CRMF)**: Expressions and prime registries are serialized into canonical JSON and cryptographically sealed via 32-byte SHA-256 digests (`seal_hex`), guaranteeing cross-implementation integrity between Rust front-ends and Lean kernels.

## Implications
- **Zero-Ambiguity Compliance**: Eliminates subjective runtime audits by binding NIST OSCAL 1.1.0 components and control objectives directly to machine-checked kernel proofs and bounded model check trajectories.
- **Hermetic Offline Auditability**: Downstream auditors and gates can verify complete release authorization bundles (`.pcrate`) entirely offline via six strict structural and cryptographic invariants without trusting online services or ephemeral build environments.

---

## Verification & `.pcrate` Pipeline (Stages 0–5)

PRIMAL executes verification through the `cargo oscal` subcommand:

```bash
cargo install --locked cargo-oscal
cargo oscal setup         # provisions pinned toolchain binaries
cargo oscal build         # executes gate verification & evidence generation
cargo oscal package       # packages trestle batch -> .pcrate bundle
cargo oscal verify-pcrate # hermetic offline verification (6 invariants)
```

### Key Verification Invariants
- **Stage 0 (`oscal-engine` SI-7)**: Elevated to `symbolic` tier via Kani harness `verify_manifest_rejects_mismatch`.
- **Stage 1 (`pirtm-lean.pcrate`)**: Zero-axiom Peano induction kernel verification (`formal_kernel` tier).
- **Stage 2 (`pirtm-frontend.pcrate`)**: Corpus-bounded parse completeness and static AST agnosticism via pinned `source/ast_pairs/`.
- **Stage 3 (CRMF Contracts)**: Deterministic canonical serialization (`canonical_json`, `seal_hex`) and tamper-evident PirtmEnvelope integrity checks.
- **Stage 4 (`Envelope.lean`)**: Kernel-level rejection of uncontractive fixpoints (e.g. $\mu X. X$ rejected with `Error.notContractive`) through direct CRMF envelope decoding.
- **Stage 5 (`pirtm-engine.pcrate`)**: Composite meta-bundle verification consuming `consumed/pirtm-lean.pcrate` and `consumed/pirtm-frontend.pcrate`, asserting all 6 invariants offline.

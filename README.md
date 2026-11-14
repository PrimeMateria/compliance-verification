# PRIME: Formal Verification & Mathematical Engineering Adapters

This directory contains standalone copies and distribution bundles of the adapters and integration tools bridging **Rust**, **Kani**, **Lean 4**, and **LaTeX**.

## Executive Summary
PRIME (Platform for Robust Integration and Mathematical Enforcement) / PIRTM (Proof Integration & Runtime Traceability Model) is an end-to-end formal verification and continuous authorization pipeline. It bridges executable Rust software, bounded model checking (Kani), interactive theorem proving in Lean 4 (with zero classical axioms in its core arithmetic fragment), and NIST OSCAL 1.1.0 continuous compliance gating into portable, hermetically verifiable `.pcrate` release bundles.

## Mathematical Overview
- **Zero-Classical-Axiom Peano Substrate**: Core arithmetic and verification primitives (`toNat_mul`, `toPosRat_respects_equiv`, Peano induction) are mechanically verified in Lean 4 with absolute zero dependence on classical axioms (`propext`, `Quot.sound`, `Classical.choice`).
- **Zeno Contractivity & Gain Bounds**: Runtime feedback and unrolling mechanisms enforce $\kappa \le 1/\Phi^2 \approx 0.382$ (where $\Phi$ is the golden ratio), ensuring contractivity and stability across recursive fixpoint trajectories.
- **Canonical Representation & Manifestation Format (CRMF)**: Expressions and prime registries are serialized into canonical JSON and cryptographically sealed via 32-byte SHA-256 digests (`seal_hex`), guaranteeing cross-implementation integrity between Rust front-ends and Lean kernels.

## Implications
- **Zero-Ambiguity Compliance**: Eliminates subjective runtime audits by binding NIST OSCAL 1.1.0 components and control objectives directly to machine-checked kernel proofs and bounded model check trajectories.
- **Hermetic Offline Auditability**: Downstream auditors and gates can verify complete release authorization bundles (`.pcrate`) entirely offline via six strict structural and cryptographic invariants without trusting online services or ephemeral build environments.

---

## Directory Layout

```
PRIME/
├── env.sh              # Environment setup script (source env.sh)
├── bin/                # Standalone executables and CLI adapters
│   ├── aeneas          # Aeneas: LLBC to Lean 4 translator
│   ├── charon          # Charon: Rust compiler driver (extracts Rust MIR to LLBC)
│   ├── cargo-hax       # Hax translation toolchain (Rust -> Lean 4, F*, Coq)
│   ├── cargo-lean-rust # Lean-Rust proof obligation extraction & Kani checking
│   ├── kani            # Kani Rust Verifier (standalone)
│   ├── cargo-kani      # Kani Cargo plugin (cargo kani)
│   ├── leanblueprint   # Lean 4 LaTeX blueprint & dependency graph generator
│   ├── latexminted     # Minted v3+ Python backend driver
│   └── pygmentize      # Pygments syntax highlighter with Lean4 & Rust lexers
├── latex/              # LaTeX style packages
│   ├── lean/
│   │   ├── lean.sty    # Package defining default colors & Lean listings language
│   │   └── lstlean.tex # Lean community listings specification
│   └── rust/
│       └── listings-rust.sty # Rust listings language specification
├── kani/               # Full prebuilt Kani engine bundle (v0.68.0)
│   └── kani-0.68.0/    # CBMC model checker, CaDiCaL SAT solver, kani-compiler
├── hax/                # Hax external tools bundle
│   └── tools/          # Pinned Aeneas (build-2b9e3ea) & Charon (nightly-2026.10.31)
├── python/             # Python packages & offline wheels
│   └── wheels/         # 23 self-contained wheels (leanblueprint, plastex, latexminted, pygments, etc.)
└── perl5/              # Perl 5 core library modules (File::Copy, File::Find, sigtrap, etc.)
```

---

## Quick Start

To add the PRIME binaries, LaTeX styles, and Perl modules to your current shell session:

```bash
source /run/media/multiplic/966af583-5f3e-4edb-8a46-237a11167a07/home/citizen/Projects/PRIME/env.sh
```

---

## Tool Overview & Workflows

### 1. Rust $\longleftrightarrow$ Kani (Automated Model Checking)
Verify memory safety, panic freedom, and user-defined contract properties:

```bash
# In your Rust crate:
cargo kani

# Or on a single Rust source file:
kani path/to/file.rs
```

### 2. Rust $\longleftrightarrow$ Lean 4 (Functional Translation via Hax / Charon / Aeneas)
Extract safe Rust code into functional Lean 4 models wrapped in the `Result` monad for interactive theorem proving:

```bash
# Using Hax:
cargo hax into lean

# Or using the direct Charon -> Aeneas pipeline:
charon cargo --preset=aeneas --dest-file output.llbc
aeneas -backend lean output.llbc

# Or using cargo-lean-rust:
cargo lean-rust init
cargo lean-rust extract
cargo lean-rust check
```

### 3. Lean 4 $\longleftrightarrow$ LaTeX (Blueprints & Dependency Graphs)
Create formal mathematical roadmaps linking LaTeX lemmas/theorems directly to Lean 4 declarations:

```bash
leanblueprint new
leanblueprint pdf
leanblueprint web
```

### 4. LaTeX Typesetting (Lean 4 & Rust / Kani Highlighting)

#### Option A: `minted` (Pygments-based)
```latex
\documentclass{article}
\usepackage{minted}

\begin{document}
\begin{minted}{lean4}
def factorial : Nat -> Nat
  | 0 => 1
  | n + 1 => (n + 1) * factorial n
\end{minted}

\begin{minted}{rust}
#[kani::proof]
fn verify_factorial() {
    let x: u32 = kani::any();
    kani::assume(x <= 10);
    assert!(x * 2 >= x);
}
\end{minted}
\end{document}
```
*Compile with:* `pdflatex -shell-escape document.tex`

#### Option B: `listings` (Local styles)
```latex
\documentclass{article}
\usepackage{lean}
\usepackage{listings-rust}

\begin{document}
\begin{lstlisting}[language=lean]
theorem add_comm (x y : Nat) : x + y = y + x := by omega
\end{lstlisting}

\begin{lstlisting}[language=Rust]
fn test_func() {
    let x = 42;
}
\end{lstlisting}
\end{document}
```
*Compile with:* `pdflatex document.tex` (when `env.sh` is sourced, `TEXINPUTS` automatically finds `lean.sty` and `listings-rust.sty`).

---

## Offline Python Installation

If setting up a fresh virtual environment or container without Internet access, install all Python adapters directly from the local wheels cache:

```bash
pip install --no-index --find-links="$PRIME_DIR/python/wheels" leanblueprint latexminted pygments
```
---

## PRIME / PIRTM Verification Architecture & `.pcrate` Pipeline (Stages 0–5)

PRIME implements a complete, zero-classical-axiom verification and authorization pipeline consumed via the `cargo oscal` subcommand:

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

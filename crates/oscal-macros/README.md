# oscal-macros

## Executive Summary
`oscal-macros` provides procedural macros (such as `#[oscal_control]`) enabling developers to annotate Rust code items, functions, and modules directly with compliance control bindings and verification metadata.

## Mathematical Overview
Let code syntax trees be denoted by $\mathcal{T}$. The procedural macro transformation is a syntax-directed mapping:
$$\mathcal{M}: \mathcal{T}_{\text{input}} \to \mathcal{T}_{\text{output}}$$
which embeds metadata annotations into static inventory tables via the `inventory` crate:
$$\text{Inventory} \leftarrow \text{Inventory} \cup \{(\text{ItemIdent}, \text{ControlID}, \text{Tier})\}$$
This guarantees that control declarations are statically bound to AST nodes at compile time.

## Implications
- **Declarative Compliance**: Directly associates source-level security invariants with code blocks without runtime overhead.
- **Static Inventory Collection**: Automatically aggregates control mappings for downstream evidence synthesis and gate evaluation.
- **Ergonomic Authoring**: Simplifies compliance documentation directly within the codebase.

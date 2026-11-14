pub mod codes;

use annotate_snippets::{Level, Renderer, Snippet};
pub use codes::OscalErrorCode;

pub struct DiagnosticEmitter {
    renderer: Renderer,
}

impl Default for DiagnosticEmitter {
    fn default() -> Self {
        Self {
            renderer: Renderer::styled(),
        }
    }
}

impl DiagnosticEmitter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Renders a Lean 4 unproven `sorry` axiom error [E-OSCAL-004]
    pub fn emit_lean_sorry_error(
        &self,
        source: &str,
        origin: &str,
        line_start: usize,
        attr_span: std::ops::Range<usize>,
        fn_span: std::ops::Range<usize>,
        control_id: &str,
        theorem_name: &str,
        remediation_help: &str,
    ) -> String {
        let title = format!(
            "{} [{}]",
            OscalErrorCode::LeanSorryAxiomPresent.default_title(),
            OscalErrorCode::LeanSorryAxiomPresent.as_str()
        );
        let ctrl_label = format!("required by NIST SP 800-53 Control {}", control_id);
        let note_label = format!("proof theorem '{}' references sorryAx", theorem_name);

        let message = Level::Error
            .title(&title)
            .snippet(
                Snippet::source(source)
                    .line_start(line_start)
                    .origin(origin)
                    .annotation(Level::Error.span(attr_span).label(&ctrl_label))
                    .annotation(Level::Note.span(fn_span).label(&note_label)),
            )
            .footer(Level::Help.title(remediation_help));

        format!("{}", self.renderer.render(message))
    }

    /// Renders a Kani assertion failure error [E-OSCAL-002]
    pub fn emit_kani_failure_error(
        &self,
        source: &str,
        origin: &str,
        line_start: usize,
        fail_span: std::ops::Range<usize>,
        control_id: &str,
        description: &str,
        counterexample_summary: &str,
    ) -> String {
        let title = format!(
            "{} [{}]",
            OscalErrorCode::KaniAssertionFailure.default_title(),
            OscalErrorCode::KaniAssertionFailure.as_str()
        );
        let ctrl_label = format!("NIST Control {}: assertion failed", control_id);

        let message = Level::Error
            .title(&title)
            .snippet(
                Snippet::source(source)
                    .line_start(line_start)
                    .origin(origin)
                    .annotation(Level::Error.span(fail_span).label(&ctrl_label)),
            )
            .footer(Level::Note.title(description))
            .footer(Level::Help.title(counterexample_summary));

        format!("{}", self.renderer.render(message))
    }
}

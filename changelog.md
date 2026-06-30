### 0.0.3
- internally change from [lsp-types](https://docs.rs/lsp-types/0.95.1/lsp_types/) to [gen-lsp-types](https://docs.rs/gen-lsp-types/0.9.0/gen_lsp_types/) for a more spec-compliant and fixing small things, following [rust-analyzer's lead in this change](https://github.com/rust-lang/rust-analyzer/pull/22115).
  As a nice side-effect of upgrading to spec version 3.18, diagnostics may now get rendered as markdown (neither [in vscode](https://github.com/microsoft/vscode/issues/54272) or gram/zed, though :()

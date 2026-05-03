struct GrenUnofficialZedExtension();

impl zed_extension_api::Extension for GrenUnofficialZedExtension {
    fn new() -> Self {
        GrenUnofficialZedExtension()
    }
    fn language_server_command(
        &mut self,
        _: &zed_extension_api::LanguageServerId,
        worktree: &zed_extension_api::Worktree,
    ) -> zed_extension_api::Result<zed_extension_api::Command> {
        if let Some(path) = worktree.which("gren-language-server-unofficial") {
            Ok(zed_extension_api::Command::new(path))
        } else {
            Err(
                "executable gren-language-server-unofficial not found in the PATH environment"
                    .into(),
            )
        }
    }
}

zed_extension_api::register_extension!(GrenUnofficialZedExtension);

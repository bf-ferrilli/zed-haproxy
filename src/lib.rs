use zed_extension_api as zed;

struct HaproxyExtension;

impl zed::Extension for HaproxyExtension {
    fn new() -> Self {
        Self
    }

    fn language_server_command(
        &mut self,
        _language_server_id: &zed::LanguageServerId,
        _worktree: &zed::Worktree,
    ) -> zed::Result<zed::Command> {
        Ok(zed::Command {
            command: "".to_string(),
            args: vec![],
            env: Default::default(),
        })
    }
}

zed::register_extension!(HaproxyExtension);

//! Shell detection, and rendering environment variables as commands for each
//! supported shell.

/// A shell the credentials can be exported to.
// `PowerShell` is a proper product name, not redundant naming against `Shell`.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Shell {
    #[default]
    Bash,
    Zsh,
    Sh,
    Fish,
    Cmd,
    PowerShell,
}

impl Shell {
    pub const ALL: [Shell; 6] = [
        Shell::Bash,
        Shell::Zsh,
        Shell::Sh,
        Shell::Fish,
        Shell::Cmd,
        Shell::PowerShell,
    ];

    /// The name used on the command line, e.g. `--format powershell`.
    pub fn name(self) -> &'static str {
        match self {
            Shell::Bash => "bash",
            Shell::Zsh => "zsh",
            Shell::Sh => "sh",
            Shell::Fish => "fish",
            Shell::Cmd => "cmd",
            Shell::PowerShell => "powershell",
        }
    }

    /// Detect the shell from its executable path, such as `$SHELL`. Matching is
    /// on the file name, case-insensitively and ignoring `.exe`; anything
    /// unrecognised gets bash syntax.
    pub fn detect(program: &str) -> Self {
        let file_name = program
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        match file_name.strip_suffix(".exe").unwrap_or(&file_name) {
            "zsh" => Shell::Zsh,
            "sh" => Shell::Sh,
            "fish" => Shell::Fish,
            "cmd" => Shell::Cmd,
            "powershell" | "pwsh" => Shell::PowerShell,
            _ => Shell::Bash,
        }
    }

    /// A script that sets `vars` in the current session and, given a label,
    /// changes the prompt to show it.
    pub fn export_script(self, vars: &[(&str, String)], prompt_label: Option<&str>) -> String {
        let mut lines: Vec<String> = vars
            .iter()
            .map(|(name, value)| self.set_var(name, value))
            .collect();
        if let Some(label) = prompt_label {
            lines.push(self.set_prompt(label));
        }
        lines.iter().map(|line| format!("{line}\n")).collect()
    }

    /// The prompt for a shell started with session credentials, as an
    /// environment variable. Fish and PowerShell prompts are functions, which
    /// cannot be passed through the environment.
    pub fn prompt_var(self, label: &str) -> Option<(&'static str, String)> {
        match self {
            Shell::Bash | Shell::Sh => Some(("PS1", format!("{label} \\$ "))),
            Shell::Zsh => Some(("PS1", format!("{label} %# "))),
            // `$G` is cmd's escape for `>`.
            Shell::Cmd => Some(("PROMPT", format!("{label}$G "))),
            Shell::Fish | Shell::PowerShell => None,
        }
    }

    fn set_var(self, name: &str, value: &str) -> String {
        match self {
            Shell::Bash | Shell::Zsh | Shell::Sh => format!("export {name}={}", posix_quote(value)),
            Shell::Fish => format!("set -gx {name} {}", fish_quote(value)),
            Shell::Cmd => format!("set \"{name}={}\"", value.replace('"', "\"\"")),
            Shell::PowerShell => format!("$env:{name} = {}", powershell_quote(value)),
        }
    }

    fn set_prompt(self, label: &str) -> String {
        if let Some((name, value)) = self.prompt_var(label) {
            return self.set_var(name, &value);
        }
        let prompt = format!("{label}> ");
        if self == Shell::Fish {
            format!("function fish_prompt; echo -n {}; end", fish_quote(&prompt))
        } else {
            format!("function global:prompt {{ {} }}", powershell_quote(&prompt))
        }
    }
}

/// Single-quote for POSIX shells, where nothing inside single quotes is special;
/// an embedded `'` closes the quote, adds an escaped `'`, and reopens it.
fn posix_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// Single-quote for fish, where `\\` and `\'` are the only escapes.
fn fish_quote(value: &str) -> String {
    format!("'{}'", value.replace('\\', r"\\").replace('\'', r"\'"))
}

/// Single-quote for PowerShell, where a quote is escaped by doubling it.
/// PowerShell also treats the typographic single quotes as quote characters.
fn powershell_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for c in value.chars() {
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
            quoted.push(c);
        }
        quoted.push(c);
    }
    quoted.push('\'');
    quoted
}

/// An interactive shell to start with session credentials in its environment.
// No `Debug`: `env` holds the secrets.
#[derive(Clone)]
pub struct ShellLaunch {
    pub program: String,
    pub env: Vec<(&'static str, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars() -> Vec<(&'static str, String)> {
        vec![
            ("AWS_ACCESS_KEY_ID", "test_key".to_owned()),
            ("AWS_SECRET_ACCESS_KEY", "test_secret".to_owned()),
            ("AWS_SESSION_TOKEN", "test_token".to_owned()),
        ]
    }

    const LABEL: &str = "AWS:alice@123456789012";

    #[test]
    fn test_detect_unix_paths() {
        assert_eq!(Shell::detect("/bin/bash"), Shell::Bash);
        assert_eq!(Shell::detect("/usr/local/bin/bash"), Shell::Bash);
        assert_eq!(Shell::detect("/bin/zsh"), Shell::Zsh);
        assert_eq!(Shell::detect("/opt/homebrew/bin/zsh"), Shell::Zsh);
        assert_eq!(Shell::detect("/bin/sh"), Shell::Sh);
        assert_eq!(Shell::detect("/usr/local/bin/fish"), Shell::Fish);
        assert_eq!(Shell::detect("/opt/homebrew/bin/fish"), Shell::Fish);
    }

    #[test]
    fn test_detect_bare_names() {
        assert_eq!(Shell::detect("bash"), Shell::Bash);
        assert_eq!(Shell::detect("zsh"), Shell::Zsh);
        assert_eq!(Shell::detect("fish"), Shell::Fish);
        assert_eq!(Shell::detect("pwsh"), Shell::PowerShell);
    }

    #[test]
    fn test_detect_windows_paths() {
        assert_eq!(Shell::detect("cmd.exe"), Shell::Cmd);
        assert_eq!(Shell::detect("C:\\Windows\\System32\\cmd.exe"), Shell::Cmd);
        assert_eq!(Shell::detect("C:\\WINDOWS\\SYSTEM32\\CMD.EXE"), Shell::Cmd);
        assert_eq!(
            Shell::detect("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            Shell::PowerShell
        );
        assert_eq!(
            Shell::detect("C:\\Program Files\\PowerShell\\7\\pwsh.exe"),
            Shell::PowerShell
        );
        assert_eq!(Shell::detect("Powershell.Exe"), Shell::PowerShell);
    }

    #[test]
    fn test_detect_is_case_insensitive() {
        // Case-insensitive filesystems (macOS, Windows) accept any casing.
        assert_eq!(Shell::detect("/USR/BIN/ZSH"), Shell::Zsh);
        assert_eq!(Shell::detect("/BIN/FISH"), Shell::Fish);
    }

    #[test]
    fn test_detect_unknown_defaults_to_bash() {
        assert_eq!(Shell::detect(""), Shell::Bash);
        assert_eq!(Shell::detect("   "), Shell::Bash);
        assert_eq!(Shell::detect("/usr/bin/python"), Shell::Bash);
        // Only the file name counts, not substrings of it.
        assert_eq!(Shell::detect("/opt/zsh-tools/bin/tcsh"), Shell::Bash);
        assert_eq!(Shell::detect("something_cmd.exe"), Shell::Bash);
    }

    #[test]
    fn test_name_round_trips_through_detect() {
        for shell in Shell::ALL {
            assert_eq!(Shell::detect(shell.name()), shell);
        }
    }

    #[test]
    fn test_bash_export() {
        let script = Shell::Bash.export_script(&vars(), Some(LABEL));
        assert_eq!(
            script,
            "export AWS_ACCESS_KEY_ID='test_key'\n\
             export AWS_SECRET_ACCESS_KEY='test_secret'\n\
             export AWS_SESSION_TOKEN='test_token'\n\
             export PS1='AWS:alice@123456789012 \\$ '\n"
        );
        assert_eq!(Shell::Sh.export_script(&vars(), Some(LABEL)), script);
    }

    #[test]
    fn test_zsh_export_uses_zsh_prompt_escape() {
        let script = Shell::Zsh.export_script(&vars(), Some(LABEL));
        assert!(script.starts_with("export AWS_ACCESS_KEY_ID='test_key'\n"));
        assert!(script.ends_with("export PS1='AWS:alice@123456789012 %# '\n"));
    }

    #[test]
    fn test_fish_export() {
        let script = Shell::Fish.export_script(&vars(), Some(LABEL));
        assert_eq!(
            script,
            "set -gx AWS_ACCESS_KEY_ID 'test_key'\n\
             set -gx AWS_SECRET_ACCESS_KEY 'test_secret'\n\
             set -gx AWS_SESSION_TOKEN 'test_token'\n\
             function fish_prompt; echo -n 'AWS:alice@123456789012> '; end\n"
        );
    }

    #[test]
    fn test_cmd_export() {
        let script = Shell::Cmd.export_script(&vars(), Some(LABEL));
        assert_eq!(
            script,
            "set \"AWS_ACCESS_KEY_ID=test_key\"\n\
             set \"AWS_SECRET_ACCESS_KEY=test_secret\"\n\
             set \"AWS_SESSION_TOKEN=test_token\"\n\
             set \"PROMPT=AWS:alice@123456789012$G \"\n"
        );
    }

    #[test]
    fn test_powershell_export_sets_environment_variables() {
        // `$env:` makes the values visible to child processes such as the AWS
        // CLI; `Set-Variable` would only create PowerShell variables.
        let script = Shell::PowerShell.export_script(&vars(), Some(LABEL));
        assert_eq!(
            script,
            "$env:AWS_ACCESS_KEY_ID = 'test_key'\n\
             $env:AWS_SECRET_ACCESS_KEY = 'test_secret'\n\
             $env:AWS_SESSION_TOKEN = 'test_token'\n\
             function global:prompt { 'AWS:alice@123456789012> ' }\n"
        );
    }

    #[test]
    fn test_export_without_prompt() {
        for shell in Shell::ALL {
            let script = shell.export_script(&vars(), None);
            assert_eq!(script.lines().count(), 3, "{shell:?}: {script}");
            assert!(!script.contains("prompt") && !script.contains("PS1"));
        }
    }

    #[test]
    fn test_export_empty_values() {
        for shell in Shell::ALL {
            let script = shell.export_script(&[("EMPTY", String::new())], Some(""));
            assert_eq!(script.lines().count(), 2, "{shell:?}: {script}");
        }
    }

    #[test]
    fn test_prompt_var() {
        assert_eq!(
            Shell::Bash.prompt_var(LABEL),
            Some(("PS1", "AWS:alice@123456789012 \\$ ".to_owned()))
        );
        assert_eq!(
            Shell::Cmd.prompt_var(LABEL),
            Some(("PROMPT", "AWS:alice@123456789012$G ".to_owned()))
        );
        assert_eq!(Shell::Fish.prompt_var(LABEL), None);
        assert_eq!(Shell::PowerShell.prompt_var(LABEL), None);
    }

    #[test]
    fn test_posix_quote() {
        assert_eq!(posix_quote("plain"), "'plain'");
        assert_eq!(posix_quote(""), "''");
        assert_eq!(posix_quote("it's"), r"'it'\''s'");
        // Double quotes, `$` and backslashes are literal inside single quotes.
        assert_eq!(posix_quote(r#"a"b$c\d"#), r#"'a"b$c\d'"#);
    }

    #[test]
    fn test_fish_quote() {
        assert_eq!(fish_quote("plain"), "'plain'");
        assert_eq!(fish_quote("it's"), r"'it\'s'");
        assert_eq!(fish_quote(r"back\slash"), r"'back\\slash'");
        assert_eq!(fish_quote(r#"a"b$c"#), r#"'a"b$c'"#);
    }

    #[test]
    fn test_powershell_quote() {
        assert_eq!(powershell_quote("plain"), "'plain'");
        assert_eq!(powershell_quote("it's"), "'it''s'");
        assert_eq!(powershell_quote("it\u{2019}s"), "'it\u{2019}\u{2019}s'");
        // `$`, backticks and double quotes are literal inside single quotes.
        assert_eq!(powershell_quote("a\"b$c`d"), "'a\"b$c`d'");
    }

    #[test]
    fn test_cmd_doubles_quotes() {
        let script = Shell::Cmd.export_script(&[("V", "key\"with\"quotes".to_owned())], None);
        assert_eq!(script, "set \"V=key\"\"with\"\"quotes\"\n");
    }

    /// Evaluate the export script in a real `sh` and read the values back, to
    /// prove that quoting keeps hostile values literal.
    #[cfg(unix)]
    #[test]
    fn test_posix_export_round_trips_through_sh() {
        let hostile = [
            (
                "V1",
                r#"it's "quoted" $HOME `id` $(id) \n ; & | > *"#.to_owned(),
            ),
            ("V2", "'".to_owned()),
            ("V3", String::new()),
        ];
        let script = Shell::Sh.export_script(&hostile, None);
        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("{script}printf '%s|%s|%s' \"$V1\" \"$V2\" \"$V3\""))
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("{}|'|", hostile[0].1)
        );
    }
}

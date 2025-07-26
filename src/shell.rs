#[derive(Default, PartialEq, Debug)]
pub enum Shell {
    #[default]
    Bash,
    Sh,
    Zsh,
    Fish,
    Cmd,
    PowerShell,
}

impl Shell {
    fn escape_unix_quotes(value: &str) -> String {
        value.replace('\'', "'\\''").replace('"', "\\\"")
    }

    fn escape_cmd_quotes(value: &str) -> String {
        value.replace('"', "\"\"")
    }

    fn escape_powershell_quotes(value: &str) -> String {
        value
            .replace('`', "``")
            .replace('"', "`\"")
            .replace('$', "`$")
    }

    pub fn export(
        self,
        stdout: &mut dyn std::io::Write,
        id: &str,
        secret: &str,
        token: &str,
        ps: &str,
    ) -> Result<(), std::io::Error> {
        match self {
            Shell::Bash | Shell::Sh | Shell::Zsh => {
                let escaped_id = Self::escape_unix_quotes(id);
                let escaped_secret = Self::escape_unix_quotes(secret);
                let escaped_token = Self::escape_unix_quotes(token);
                let escaped_ps = Self::escape_unix_quotes(ps);

                writeln!(stdout, "export AWS_ACCESS_KEY_ID='{escaped_id}'")?;
                writeln!(stdout, "export AWS_SECRET_ACCESS_KEY='{escaped_secret}'")?;
                writeln!(stdout, "export AWS_SESSION_TOKEN='{escaped_token}'")?;
                writeln!(stdout, "export PS1='{escaped_ps}'")?;
            }
            Shell::Fish => {
                let escaped_id = Self::escape_unix_quotes(id);
                let escaped_secret = Self::escape_unix_quotes(secret);
                let escaped_token = Self::escape_unix_quotes(token);
                let escaped_ps = Self::escape_unix_quotes(ps);

                writeln!(stdout, "set -x AWS_ACCESS_KEY_ID \"{escaped_id}\"")?;
                writeln!(stdout, "set -x AWS_SECRET_ACCESS_KEY \"{escaped_secret}\"")?;
                writeln!(stdout, "set -x AWS_SESSION_TOKEN \"{escaped_token}\"")?;
                writeln!(stdout, "set -x PS1 \"{escaped_ps}\"")?;
            }
            Shell::Cmd => {
                let escaped_id = Self::escape_cmd_quotes(id);
                let escaped_secret = Self::escape_cmd_quotes(secret);
                let escaped_token = Self::escape_cmd_quotes(token);
                let escaped_ps = Self::escape_cmd_quotes(ps);

                writeln!(stdout, "set \"AWS_ACCESS_KEY_ID={escaped_id}\"")?;
                writeln!(stdout, "set \"AWS_SECRET_ACCESS_KEY={escaped_secret}\"")?;
                writeln!(stdout, "set \"AWS_SESSION_TOKEN={escaped_token}\"")?;
                writeln!(stdout, "set \"PROMPT={escaped_ps}\"")?;
            }
            Shell::PowerShell => {
                let escaped_id = Self::escape_powershell_quotes(id);
                let escaped_secret = Self::escape_powershell_quotes(secret);
                let escaped_token = Self::escape_powershell_quotes(token);
                let escaped_ps = Self::escape_powershell_quotes(ps);

                writeln!(
                    stdout,
                    "Set-Variable -Name \"AWS_ACCESS_KEY_ID\" -Value \"{escaped_id}\""
                )?;
                writeln!(
                    stdout,
                    "Set-Variable -Name \"AWS_SECRET_ACCESS_KEY\" -Value \"{escaped_secret}\""
                )?;
                writeln!(
                    stdout,
                    "Set-Variable -Name \"AWS_SESSION_TOKEN\" -Value \"{escaped_token}\""
                )?;
                writeln!(stdout, "function prompt {{ \"{escaped_ps}\" }}")?;
            }
        }
        Ok(())
    }
}

impl<'a> From<&'a str> for Shell {
    fn from(s: &'a str) -> Self {
        match s {
            s if s.ends_with("/bin/bash") => Shell::Bash,
            s if s.ends_with("/bin/zsh") => Shell::Zsh,
            s if s.ends_with("/bin/sh") => Shell::Sh,
            s if s.ends_with("/bin/fish") => Shell::Fish,
            s => {
                let s_lower = s.to_ascii_lowercase();
                match s_lower.as_str() {
                    s if s.ends_with("cmd.exe") => Shell::Cmd,
                    s if s.ends_with("powershell.exe") || s.ends_with("pwsh.exe") => {
                        Shell::PowerShell
                    }
                    _ => Default::default(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_from_bash_paths() {
        assert_eq!(Shell::from("/bin/bash"), Shell::Bash);
        assert_eq!(Shell::from("/usr/bin/bash"), Shell::Bash);
        assert_eq!(Shell::from("/usr/local/bin/bash"), Shell::Bash);
    }

    #[test]
    fn test_shell_from_zsh_paths() {
        assert_eq!(Shell::from("/bin/zsh"), Shell::Zsh);
        assert_eq!(Shell::from("/usr/bin/zsh"), Shell::Zsh);
        assert_eq!(Shell::from("/usr/local/bin/zsh"), Shell::Zsh);
    }

    #[test]
    fn test_shell_from_sh_path() {
        assert_eq!(Shell::from("/bin/sh"), Shell::Sh);
    }

    #[test]
    fn test_shell_from_fish_paths() {
        assert_eq!(Shell::from("/bin/fish"), Shell::Fish);
        assert_eq!(Shell::from("/usr/local/bin/fish"), Shell::Fish);
    }

    #[test]
    fn test_shell_from_cmd_paths() {
        assert_eq!(Shell::from("cmd.exe"), Shell::Cmd);
        assert_eq!(Shell::from("C:\\Windows\\System32\\cmd.exe"), Shell::Cmd);
        assert_eq!(Shell::from("CMD.EXE"), Shell::Cmd);
    }

    #[test]
    fn test_shell_from_powershell_paths() {
        assert_eq!(Shell::from("powershell.exe"), Shell::PowerShell);
        assert_eq!(
            Shell::from("C:\\Windows\\System32\\powershell.exe"),
            Shell::PowerShell
        );
        assert_eq!(Shell::from("POWERSHELL.EXE"), Shell::PowerShell);
        assert_eq!(Shell::from("pwsh.exe"), Shell::PowerShell);
        assert_eq!(
            Shell::from("C:\\Program Files\\PowerShell\\7\\pwsh.exe"),
            Shell::PowerShell
        );
    }

    #[test]
    fn test_shell_from_unknown_defaults_to_bash() {
        assert_eq!(Shell::from("unknown"), Shell::Bash);
        assert_eq!(Shell::from("/some/unknown/shell"), Shell::Bash);
        assert_eq!(Shell::from(""), Shell::Bash);
    }

    #[test]
    fn test_shell_default() {
        let default_shell = Shell::default();
        assert_eq!(default_shell, Shell::Bash);
    }

    #[test]
    fn test_bash_export() {
        let shell = Shell::Bash;
        let mut output = Vec::new();

        shell
            .export(
                &mut output,
                "test_key",
                "test_secret",
                "test_token",
                "test_prompt",
            )
            .unwrap();

        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("export AWS_ACCESS_KEY_ID='test_key'"));
        assert!(output_str.contains("export AWS_SECRET_ACCESS_KEY='test_secret'"));
        assert!(output_str.contains("export AWS_SESSION_TOKEN='test_token'"));
        assert!(output_str.contains("export PS1='test_prompt'"));
    }

    #[test]
    fn test_fish_export() {
        let shell = Shell::Fish;
        let mut output = Vec::new();

        shell
            .export(
                &mut output,
                "test_key",
                "test_secret",
                "test_token",
                "test_prompt",
            )
            .unwrap();

        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("set -x AWS_ACCESS_KEY_ID \"test_key\""));
        assert!(output_str.contains("set -x AWS_SECRET_ACCESS_KEY \"test_secret\""));
        assert!(output_str.contains("set -x AWS_SESSION_TOKEN \"test_token\""));
        assert!(output_str.contains("set -x PS1 \"test_prompt\""));
    }

    #[test]
    fn test_cmd_export() {
        let shell = Shell::Cmd;
        let mut output = Vec::new();

        shell
            .export(
                &mut output,
                "test_key",
                "test_secret",
                "test_token",
                "test_prompt",
            )
            .unwrap();

        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("set \"AWS_ACCESS_KEY_ID=test_key\""));
        assert!(output_str.contains("set \"AWS_SECRET_ACCESS_KEY=test_secret\""));
        assert!(output_str.contains("set \"AWS_SESSION_TOKEN=test_token\""));
        assert!(output_str.contains("set \"PROMPT=test_prompt\""));
    }

    #[test]
    fn test_powershell_export() {
        let shell = Shell::PowerShell;
        let mut output = Vec::new();

        shell
            .export(
                &mut output,
                "test_key",
                "test_secret",
                "test_token",
                "test_prompt",
            )
            .unwrap();

        let output_str = String::from_utf8(output).unwrap();
        assert!(
            output_str.contains("Set-Variable -Name \"AWS_ACCESS_KEY_ID\" -Value \"test_key\"")
        );
        assert!(
            output_str
                .contains("Set-Variable -Name \"AWS_SECRET_ACCESS_KEY\" -Value \"test_secret\"")
        );
        assert!(
            output_str.contains("Set-Variable -Name \"AWS_SESSION_TOKEN\" -Value \"test_token\"")
        );
        assert!(output_str.contains("function prompt { \"test_prompt\" }"));
    }

    #[test]
    fn test_shell_export_with_special_characters() {
        let shell = Shell::Bash;
        let mut output = Vec::new();
        shell
            .export(
                &mut output,
                "key_with_$pecial_chars",
                "secret'with\"quotes",
                "token with spaces",
                "prompt;with;semicolons",
            )
            .unwrap();
    }

    #[test]
    fn test_shell_export_with_empty_values() {
        let shell = Shell::Bash;
        let mut output = Vec::new();
        shell.export(&mut output, "", "", "", "").unwrap();
    }

    #[test]
    fn test_all_shell_variants_export() {
        let shells = [
            Shell::Bash,
            Shell::Sh,
            Shell::Zsh,
            Shell::Fish,
            Shell::Cmd,
            Shell::PowerShell,
        ];

        for shell in shells {
            let mut output = Vec::new();
            shell
                .export(
                    &mut output,
                    "test_key",
                    "test_secret",
                    "test_token",
                    "test_prompt",
                )
                .unwrap();
        }
    }

    #[test]
    fn test_shell_from_partial_paths() {
        assert_eq!(Shell::from("bash"), Shell::Bash);
        assert_eq!(Shell::from("something_cmd.exe"), Shell::Cmd);
        assert_eq!(Shell::from("my_powershell.exe"), Shell::PowerShell);
    }

    #[test]
    fn test_case_sensitivity() {
        // Unix paths are case sensitive, so uppercase should default to Bash
        assert_eq!(Shell::from("/BIN/BASH"), Shell::Bash); // defaults to Bash
        assert_eq!(Shell::from("/USR/BIN/ZSH"), Shell::Bash); // defaults to Bash  
        // Windows paths are case insensitive
        assert_eq!(Shell::from("CMD.EXE"), Shell::Cmd);
        assert_eq!(Shell::from("POWERSHELL.EXE"), Shell::PowerShell);
    }

    #[test]
    fn test_shell_export_format_bash() {
        let shell = Shell::Bash;
        let mut output = Vec::new();
        shell
            .export(
                &mut output,
                "AKIATEST123456",
                "secretkey123",
                "sessiontoken456",
                "AWS:test@123456789 \\$ ",
            )
            .unwrap();
    }

    #[test]
    fn test_shell_export_format_fish() {
        let shell = Shell::Fish;
        let mut output = Vec::new();
        shell
            .export(
                &mut output,
                "AKIATEST123456",
                "secretkey123",
                "sessiontoken456",
                "AWS:test@123456789 \\$ ",
            )
            .unwrap();
    }

    #[test]
    fn test_shell_export_format_cmd() {
        let shell = Shell::Cmd;
        let mut output = Vec::new();
        shell
            .export(
                &mut output,
                "AKIATEST123456",
                "secretkey123",
                "sessiontoken456",
                "AWS:test@123456789 \\$ ",
            )
            .unwrap();
    }

    #[test]
    fn test_shell_export_format_powershell() {
        let shell = Shell::PowerShell;
        let mut output = Vec::new();
        shell
            .export(
                &mut output,
                "AKIATEST123456",
                "secretkey123",
                "sessiontoken456",
                "AWS:test@123456789 \\$ ",
            )
            .unwrap();
    }

    #[test]
    fn test_shell_from_homebrew_paths() {
        assert_eq!(Shell::from("/opt/homebrew/bin/bash"), Shell::Bash);
        assert_eq!(Shell::from("/opt/homebrew/bin/zsh"), Shell::Zsh);
        assert_eq!(Shell::from("/opt/homebrew/bin/fish"), Shell::Fish);
    }

    #[test]
    fn test_shell_from_windows_paths() {
        assert_eq!(Shell::from("C:\\Windows\\System32\\cmd.exe"), Shell::Cmd);
        assert_eq!(Shell::from("C:\\WINDOWS\\SYSTEM32\\CMD.EXE"), Shell::Cmd);
        assert_eq!(
            Shell::from("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            Shell::PowerShell
        );
        assert_eq!(
            Shell::from("C:\\Program Files\\PowerShell\\7\\pwsh.exe"),
            Shell::PowerShell
        );
    }

    #[test]
    fn test_shell_from_mixed_case() {
        // Unix paths are case sensitive, so mixed case defaults to Bash
        assert_eq!(Shell::from("/Usr/Bin/Bash"), Shell::Bash); // defaults to Bash
        assert_eq!(Shell::from("/USR/LOCAl/BIN/ZSH"), Shell::Bash); // defaults to Bash
        // Windows executables are case insensitive
        assert_eq!(Shell::from("Powershell.Exe"), Shell::PowerShell);
        assert_eq!(Shell::from("PWSH.EXE"), Shell::PowerShell);
    }

    #[test]
    fn test_shell_from_edge_cases() {
        assert_eq!(Shell::from(""), Shell::Bash);
        assert_eq!(Shell::from("   "), Shell::Bash);
        assert_eq!(Shell::from("notashell"), Shell::Bash);
        assert_eq!(Shell::from("/usr/bin/python"), Shell::Bash);
    }

    #[test]
    fn test_shell_export_handles_quotes() {
        let shells = [Shell::Bash, Shell::Fish, Shell::Cmd, Shell::PowerShell];

        for shell in shells {
            let mut output = Vec::new();
            shell
                .export(
                    &mut output,
                    "key_with_quotes",
                    "secret'with\"mixed'quotes",
                    "token\"with'quotes",
                    "prompt'with\"quotes",
                )
                .unwrap();
        }
    }

    #[test]
    fn test_shell_export_handles_special_chars() {
        let shells = [Shell::Bash, Shell::Fish, Shell::Cmd, Shell::PowerShell];

        for shell in shells {
            let mut output = Vec::new();
            shell
                .export(
                    &mut output,
                    "key$with&special*chars",
                    "secret|with;special<chars>",
                    "token(with)special[chars]",
                    "prompt{with}special%chars",
                )
                .unwrap();
        }
    }

    #[test]
    fn test_shell_default_trait() {
        let default = Shell::default();
        assert_eq!(default, Shell::Bash);
    }

    #[test]
    fn test_escape_unix_quotes() {
        assert_eq!(Shell::escape_unix_quotes("test'value"), "test'\\''value");
        assert_eq!(Shell::escape_unix_quotes("test\"value"), "test\\\"value");
        assert_eq!(
            Shell::escape_unix_quotes("test'with\"quotes"),
            "test'\\''with\\\"quotes"
        );
        assert_eq!(Shell::escape_unix_quotes("testvalue"), "testvalue");
        assert_eq!(Shell::escape_unix_quotes(""), "");
        assert_eq!(
            Shell::escape_unix_quotes("'test'\"value\""),
            "'\\''test'\\''\\\"value\\\""
        );
    }

    #[test]
    fn test_escape_cmd_quotes() {
        assert_eq!(Shell::escape_cmd_quotes("test\"value"), "test\"\"value");
        assert_eq!(
            Shell::escape_cmd_quotes("test\"with\"quotes"),
            "test\"\"with\"\"quotes"
        );
        assert_eq!(Shell::escape_cmd_quotes("testvalue"), "testvalue");
        assert_eq!(Shell::escape_cmd_quotes(""), "");
        assert_eq!(
            Shell::escape_cmd_quotes("test\"\"value"),
            "test\"\"\"\"value"
        );
        assert_eq!(Shell::escape_cmd_quotes("\"test\""), "\"\"test\"\"");
    }

    #[test]
    fn test_cmd_export_with_quotes() {
        let shell = Shell::Cmd;
        let mut output = Vec::new();

        shell
            .export(
                &mut output,
                "key\"with\"quotes",
                "secret\"value",
                "token\"test",
                "prompt",
            )
            .unwrap();

        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("set \"AWS_ACCESS_KEY_ID=key\"\"with\"\"quotes\""));
        assert!(output_str.contains("set \"AWS_SECRET_ACCESS_KEY=secret\"\"value\""));
        assert!(output_str.contains("set \"AWS_SESSION_TOKEN=token\"\"test\""));
    }

    #[test]
    fn test_escape_powershell_quotes() {
        assert_eq!(
            Shell::escape_powershell_quotes("test\"value"),
            "test`\"value"
        );
        assert_eq!(
            Shell::escape_powershell_quotes("test$variable"),
            "test`$variable"
        );
        assert_eq!(Shell::escape_powershell_quotes("test`value"), "test``value");

        assert_eq!(
            Shell::escape_powershell_quotes("test\"with$var`escape"),
            "test`\"with`$var``escape"
        );
        assert_eq!(Shell::escape_powershell_quotes("testvalue"), "testvalue");
        assert_eq!(Shell::escape_powershell_quotes(""), "");
        assert_eq!(
            Shell::escape_powershell_quotes("$test\"value$more\"data"),
            "`$test`\"value`$more`\"data"
        );
        assert_eq!(
            Shell::escape_powershell_quotes("test\"\"$value"),
            "test`\"`\"`$value"
        );
    }

    #[test]
    fn test_powershell_export_with_quotes() {
        let shell = Shell::PowerShell;
        let mut output = Vec::new();

        shell
            .export(
                &mut output,
                "key\"with$quotes",
                "secret`value",
                "token$test\"data",
                "prompt",
            )
            .unwrap();

        let output_str = String::from_utf8(output).unwrap();
        assert!(
            output_str
                .contains("Set-Variable -Name \"AWS_ACCESS_KEY_ID\" -Value \"key`\"with`$quotes\"")
        );
        assert!(
            output_str
                .contains("Set-Variable -Name \"AWS_SECRET_ACCESS_KEY\" -Value \"secret``value\"")
        );
        assert!(
            output_str
                .contains("Set-Variable -Name \"AWS_SESSION_TOKEN\" -Value \"token`$test`\"data\"")
        );
    }
}

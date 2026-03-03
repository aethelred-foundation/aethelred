//! Shell completion generation for the Aethelred CLI.
//!
//! Generates completion scripts for bash, zsh, fish, elvish, and PowerShell.
//!
//! Usage:
//!   aethelred completions bash > ~/.bash_completion.d/aethelred
//!   aethelred completions zsh > /usr/local/share/zsh/site-functions/_aethelred
//!   aethelred completions fish > ~/.config/fish/completions/aethelred.fish

use clap::{Command, CommandFactory};
use clap_complete::{generate, Shell};
use std::io;

/// Generate shell completion scripts.
///
/// This module provides the `completions` subcommand that generates
/// auto-completion scripts for various shells. The generated script
/// enables tab-completion for all commands, subcommands, flags, and options.
pub fn generate_completions(shell: Shell, cmd: &mut Command) {
    generate(shell, cmd, "aethelred", &mut io::stdout());
}

/// Parse shell name from string argument.
pub fn parse_shell(shell_name: &str) -> Result<Shell, String> {
    match shell_name.to_lowercase().as_str() {
        "bash" => Ok(Shell::Bash),
        "zsh" => Ok(Shell::Zsh),
        "fish" => Ok(Shell::Fish),
        "elvish" => Ok(Shell::Elvish),
        "powershell" | "ps" => Ok(Shell::PowerShell),
        _ => Err(format!(
            "Unsupported shell '{}'. Supported: bash, zsh, fish, elvish, powershell",
            shell_name
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_shell_bash() {
        assert_eq!(parse_shell("bash").unwrap(), Shell::Bash);
    }

    #[test]
    fn test_parse_shell_zsh() {
        assert_eq!(parse_shell("zsh").unwrap(), Shell::Zsh);
    }

    #[test]
    fn test_parse_shell_fish() {
        assert_eq!(parse_shell("fish").unwrap(), Shell::Fish);
    }

    #[test]
    fn test_parse_shell_powershell() {
        assert_eq!(parse_shell("powershell").unwrap(), Shell::PowerShell);
        assert_eq!(parse_shell("ps").unwrap(), Shell::PowerShell);
    }

    #[test]
    fn test_parse_shell_case_insensitive() {
        assert_eq!(parse_shell("BASH").unwrap(), Shell::Bash);
        assert_eq!(parse_shell("Zsh").unwrap(), Shell::Zsh);
    }

    #[test]
    fn test_parse_shell_invalid() {
        assert!(parse_shell("invalid").is_err());
    }
}

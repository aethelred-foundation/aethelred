# Shell Completions

The `aethelred` CLI can generate tab-completion scripts for **Bash**, **Zsh**, **Fish**, **Elvish**, and **PowerShell**. Completions cover all commands, subcommands, flags, and options.

## Generating Completions

```bash
aethelred completions <SHELL>
```

Supported shell values: `bash`, `zsh`, `fish`, `elvish`, `powershell` (or `ps`).

## Bash

```bash
# Generate and install
aethelred completions bash > ~/.bash_completion.d/aethelred

# Or write to the system-wide location
aethelred completions bash | sudo tee /etc/bash_completion.d/aethelred > /dev/null

# Reload in the current session
source ~/.bash_completion.d/aethelred
```

If `~/.bash_completion.d/` does not exist, create it and source it from `~/.bashrc`:

```bash
mkdir -p ~/.bash_completion.d
echo 'for f in ~/.bash_completion.d/*; do source "$f"; done' >> ~/.bashrc
```

## Zsh

```bash
# Generate and install to the Zsh site-functions directory
aethelred completions zsh > /usr/local/share/zsh/site-functions/_aethelred

# Or use a user-local path (add to fpath in ~/.zshrc first)
mkdir -p ~/.zsh/completions
aethelred completions zsh > ~/.zsh/completions/_aethelred
```

Add the user-local directory to your `~/.zshrc` if not already present:

```bash
# Add to ~/.zshrc BEFORE compinit
fpath=(~/.zsh/completions $fpath)
autoload -Uz compinit && compinit
```

Reload with `source ~/.zshrc` or open a new terminal.

## Fish

```bash
# Generate and install
aethelred completions fish > ~/.config/fish/completions/aethelred.fish
```

Fish picks up new completion files automatically -- no reload necessary.

## Elvish

```bash
# Generate and write to the Elvish completions directory
aethelred completions elvish > ~/.config/elvish/lib/aethelred.elv
```

Then add to your `~/.config/elvish/rc.elv`:

```bash
use aethelred
```

## PowerShell

```powershell
# Generate and write to your PowerShell profile
aethelred completions powershell >> $PROFILE

# Or save to a separate file and dot-source it
aethelred completions powershell > "$HOME\Documents\PowerShell\aethelred.ps1"
```

Add the dot-source line to your `$PROFILE` if using a separate file:

```powershell
. "$HOME\Documents\PowerShell\aethelred.ps1"
```

Reload with `. $PROFILE` or restart PowerShell.

## Verifying Completions

After installation, type `aethelred ` followed by Tab to see available commands:

```
$ aethelred <TAB>
account       bench         completions   config        deploy
dev           hardware      init          interactive   job
model         network       node          query         seal
tx            validator     version
```

Subcommands and flags complete as well:

```
$ aethelred seal <TAB>
create   export   get      list     verify

$ aethelred --<TAB>
--config    --help      --json      --network   --no-color  --output    --verbose   --version
```

## Updating Completions

Re-run the generation command after upgrading the CLI to pick up new commands or flags:

```bash
# Example for Zsh
aethelred completions zsh > /usr/local/share/zsh/site-functions/_aethelred
```

## Further Reading

- [Installation](/cli/installation) - Install or upgrade the CLI
- [Commands Reference](/cli/commands) - Full command documentation
- [Configuration](/cli/configuration) - Config file and environment variables

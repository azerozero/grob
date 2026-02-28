use clap::CommandFactory;
use clap_complete::{generate, Shell};

pub fn cmd_setup_completions<C: CommandFactory>() -> anyhow::Result<()> {
    let shell_str = std::env::var("SHELL").unwrap_or_default();
    let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());

    if shell_str.ends_with("zsh") {
        let zfunc_dir = format!("{}/.zfunc", home);
        std::fs::create_dir_all(&zfunc_dir)?;
        let dest = format!("{}/_grob", zfunc_dir);
        let mut file = std::fs::File::create(&dest)?;
        let mut cmd = C::command();
        generate(Shell::Zsh, &mut cmd, "grob", &mut file);
        println!("Installed zsh completions to {}", dest);
        println!(
            "Add to ~/.zshrc if not already present:\n  fpath=(~/.zfunc $fpath)\n  autoload -Uz compinit && compinit"
        );
    } else if shell_str.ends_with("bash") {
        let dest = format!("{}/.local/share/bash-completion/completions/grob", home);
        if let Some(parent) = std::path::Path::new(&dest).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::File::create(&dest)?;
        let mut cmd = C::command();
        generate(Shell::Bash, &mut cmd, "grob", &mut file);
        println!("Installed bash completions to {}", dest);
    } else if shell_str.ends_with("fish") {
        let dest = format!("{}/.config/fish/completions/grob.fish", home);
        if let Some(parent) = std::path::Path::new(&dest).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::File::create(&dest)?;
        let mut cmd = C::command();
        generate(Shell::Fish, &mut cmd, "grob", &mut file);
        println!("Installed fish completions to {}", dest);
    } else {
        eprintln!(
            "Could not detect shell from $SHELL ({}). Use `grob completions <shell>` instead.",
            shell_str
        );
        std::process::exit(1);
    }
    Ok(())
}

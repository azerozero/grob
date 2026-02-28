use clap::CommandFactory;
use clap_complete::{generate, Shell};

pub fn cmd_completions<C: CommandFactory>(shell: Shell) {
    let mut cmd = C::command();
    generate(shell, &mut cmd, "grob", &mut std::io::stdout());
    match shell {
        Shell::Zsh => eprintln!("\n# Add to ~/.zshrc:\n# eval \"$(grob completions zsh)\""),
        Shell::Bash => {
            eprintln!("\n# Add to ~/.bashrc:\n# eval \"$(grob completions bash)\"")
        }
        Shell::Fish => eprintln!("\n# Run: grob completions fish | source"),
        _ => {}
    }
}

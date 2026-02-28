pub fn cmd_init() -> anyhow::Result<()> {
    let target = std::env::current_dir()?.join(".grob.toml");
    if target.exists() {
        eprintln!("⚠️  .grob.toml already exists in this directory");
        return Ok(());
    }

    let template = r#"# Per-project Grob configuration overlay
# Values here override the global ~/.grob/config.toml

# Override the default router model for this project
# [router]
# default = "my-project-model"
# think = "my-think-model"
# background = "my-bg-model"
# websearch = "my-ws-model"

# Override budget for this project
# [budget]
# monthly_limit_usd = 50.0

# Add project-specific prompt rules
# [[router.prompt_rules]]
# pattern = "(?i)deploy"
# model = "fast-model"
# strip_match = false

# Override preset
# [presets]
# active = "cheap"
"#;
    std::fs::write(&target, template)?;
    println!("✅ Created .grob.toml in {}", target.display());
    println!("   Edit it to customize Grob for this project.");
    Ok(())
}

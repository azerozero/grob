use cucumber::{given, then, when};
use tokio::process::Command;

use crate::world::E2eWorld;

/// CLI registry: maps CLI name to (binary, prompt_flag, base_url_env).
/// Returns (binary, prompt_flag, base_url_env, url_suffix).
fn cli_config(name: &str) -> (&'static str, &'static str, &'static str, &'static str) {
    match name {
        // Claude Code: ANTHROPIC_BASE_URL without /v1 (it appends /v1/messages).
        "claude" => ("claude", "-p", "ANTHROPIC_BASE_URL", ""),
        // Codex: OPENAI_BASE_URL with /v1 suffix.
        "codex" => ("codex", "-q", "OPENAI_BASE_URL", "/v1"),
        "llm" => ("llm", "", "OPENAI_BASE_URL", "/v1"),
        "aider" => ("aider", "--message", "OPENAI_API_BASE", "/v1"),
        other => panic!("unknown LLM CLI: {other} — add it to cli_config()"),
    }
}

#[given(regex = r#"the LLM CLI "(.+)" is configured"#)]
async fn configure_cli(world: &mut E2eWorld, name: String) {
    let (bin, flag, _, _) = cli_config(&name);
    // Verify binary exists.
    let check = Command::new("which")
        .arg(bin)
        .output()
        .await
        .expect("failed to run `which`");
    if !check.status.success() {
        // Skip gracefully if CLI not installed.
        panic!("{name} CLI not found in PATH — install it or skip this scenario");
    }
    world.cli_name = name;
    world.cli_prompt_flag = flag.to_string();
}

#[when(regex = r#"I ask "(.+)""#)]
async fn ask_question(world: &mut E2eWorld, prompt: String) {
    let (bin, _, base_url_env, url_suffix) = cli_config(&world.cli_name);
    let grob_url = format!("http://{}{}", world.grob_host, url_suffix);

    let mut cmd = Command::new(bin);
    cmd.env(base_url_env, &grob_url)
        // Use grob's static API key for authentication.
        .env("ANTHROPIC_API_KEY", "grob-siege-master-key")
        .env("OPENAI_API_KEY", "grob-siege-master-key")
        // Disable interactive features for CI.
        .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1");

    if !world.cli_prompt_flag.is_empty() {
        cmd.arg(&world.cli_prompt_flag);
    }
    cmd.arg(&prompt);

    let output = cmd.output().await.expect("failed to run CLI");
    world.last_exit_code = output.status.code().unwrap_or(-1);
    world.last_stdout = String::from_utf8_lossy(&output.stdout).to_string();
    world.last_stderr = String::from_utf8_lossy(&output.stderr).to_string();
}

#[then(regex = r"the exit code is (\d+)")]
async fn check_exit_code(world: &mut E2eWorld, expected: i32) {
    assert_eq!(
        world.last_exit_code, expected,
        "exit code mismatch.\nstdout: {}\nstderr: {}",
        world.last_stdout, world.last_stderr
    );
}

#[then("the output is not empty")]
async fn output_not_empty(world: &mut E2eWorld) {
    assert!(
        !world.last_stdout.trim().is_empty(),
        "CLI output was empty.\nstderr: {}",
        world.last_stderr
    );
}

#[then(regex = r#"the output contains "(.+)""#)]
async fn output_contains(world: &mut E2eWorld, expected: String) {
    assert!(
        world.last_stdout.contains(&expected),
        "output does not contain '{expected}'.\nstdout: {}",
        world.last_stdout
    );
}

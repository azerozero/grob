//! Rust drives syntax-only compilers; example code is never executed or imported.

use super::{markdown, read_doc};
use std::process::Stdio;
use tokio::{
    io::AsyncWriteExt,
    process::Command,
    time::{timeout, Duration},
};

async fn check(language: &str, source: &str) -> Result<(), String> {
    if source.trim().is_empty() {
        return Err("empty example".into());
    }
    let (program, args): (&str, &[&str]) = match language {
        "python" => (
            "python3",
            &[
                "-I",
                "-S",
                "-c",
                "import sys; compile(sys.stdin.read(), '<documentation>', 'exec')",
            ],
        ),
        "javascript" => ("node", &["--check", "--input-type=module"]),
        "bash" => ("bash", &["--noprofile", "--norc", "-n"]),
        _ => return Err(format!("unsupported language: {language}")),
    };
    timeout(Duration::from_secs(15), async {
        let mut child = Command::new(program)
            .args(args)
            .env_remove("NODE_OPTIONS")
            .env_remove("BASH_ENV")
            .env_remove("ENV")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| format!("{program}: {error}"))?;
        let mut input = child.stdin.take().expect("piped stdin");
        input
            .write_all(source.as_bytes())
            .await
            .map_err(|error| error.to_string())?;
        drop(input);
        let output = child
            .wait_with_output()
            .await
            .map_err(|error| error.to_string())?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "{program}: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    })
    .await
    .map_err(|_| format!("{program}: syntax check timed out"))?
}

#[tokio::test]
#[ignore = "requires Python, Node and Bash; required Documentation examples CI job runs this"]
async fn published_sdk_and_shell_examples_compile() {
    for (path, languages) in [
        ("docs/examples/sdk-python.md", &["python", "bash"][..]),
        ("docs/examples/sdk-node.md", &["javascript", "bash"][..]),
        ("docs/tutorials/getting-started.md", &["bash"][..]),
        ("docs/how-to/providers.md", &["bash"][..]),
    ] {
        let blocks = markdown::blocks(&read_doc(path)).expect("closed code fences");
        for language in languages {
            let examples: Vec<_> = blocks
                .iter()
                .filter(|block| block.language == *language)
                .collect();
            assert!(!examples.is_empty(), "{path}: no {language} example");
            for block in examples {
                check(language, &block.source)
                    .await
                    .unwrap_or_else(|error| panic!("{path}:{}: {error}", block.line));
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires Python, Node and Bash; required Documentation examples CI job runs this"]
async fn syntax_checks_reject_non_compilable_examples_without_running_them() {
    for invalid in ["return 1", "break", "continue", "await f()"] {
        assert!(
            check("python", invalid).await.is_err(),
            "accepted {invalid}"
        );
    }
    assert!(check("javascript", "const =;").await.is_err());
    assert!(check("bash", "if then").await.is_err());
    assert!(check("python", "").await.is_err());
    check("python", "raise RuntimeError('must not execute')")
        .await
        .unwrap();
    check("javascript", "throw new Error('must not execute');")
        .await
        .unwrap();
    check("bash", "exit 73").await.unwrap();
}

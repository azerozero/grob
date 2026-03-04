//! CLI command: `grob harness record` / `grob harness replay`.

use crate::cli::args::HarnessAction;
use crate::cli::AppConfig;
use crate::features::harness::{load_tape, Driver, DriverConfig, MockBackend, MockConfig};
use std::path::PathBuf;

/// Dispatches harness subcommands.
pub async fn cmd_harness(config: &AppConfig, action: HarnessAction) -> anyhow::Result<()> {
    match action {
        HarnessAction::Record { output } => cmd_record(config, output).await,
        HarnessAction::Replay {
            tape,
            target,
            concurrency,
            qps,
            mock_port,
            mock_latency_ms,
            error_rate,
            duration,
        } => {
            let mock_config = MockConfig {
                port: mock_port,
                latency_ms: mock_latency_ms,
                error_rate,
            };
            let driver_config = DriverConfig {
                target_url: target,
                concurrency,
                qps,
                total: 0,
                duration_secs: duration,
            };
            cmd_replay(tape, mock_config, driver_config).await
        }
    }
}

/// Starts grob with the tape recorder middleware enabled.
async fn cmd_record(_config: &AppConfig, output: String) -> anyhow::Result<()> {
    let path = PathBuf::from(&output);
    println!("Recording traffic to: {}", path.display());
    println!(
        "Start grob with GROB_HARNESS_RECORD={} to enable recording.",
        output
    );
    println!("Press Ctrl+C to stop recording.");
    println!();
    println!("Example:");
    println!("  GROB_HARNESS_RECORD={} grob start", output);
    println!();
    println!(
        "The tape recorder middleware will be injected automatically when \
         GROB_HARNESS_RECORD is set and grob is compiled with --features harness."
    );

    Ok(())
}

/// Loads a tape, starts mock backend, replays traffic through grob.
async fn cmd_replay(
    tape_path: PathBuf,
    mock_config: MockConfig,
    driver_config: DriverConfig,
) -> anyhow::Result<()> {
    let entries = load_tape(&tape_path).await?;
    if entries.is_empty() {
        anyhow::bail!("Tape file is empty: {}", tape_path.display());
    }

    println!(
        "Loaded {} tape entries from {}",
        entries.len(),
        tape_path.display()
    );

    // Start mock backend.
    let mock = MockBackend::start(&entries, mock_config).await?;
    let mock_url = mock.base_url();

    println!();
    println!("Mock backend running on {}", mock_url);
    println!();
    println!("Configure grob providers to use the mock backend:");
    println!("  Set base_url = \"{}\" on your provider configs", mock_url);
    println!("  Or: GROB_MOCK_BACKEND={} grob start", mock_url);
    println!();

    let qps_label = if driver_config.qps == 0.0 {
        "unlimited".to_string()
    } else {
        format!("{:.1}", driver_config.qps)
    };
    println!(
        "Replaying {} entries → {} (concurrency={}, qps={})",
        entries.len(),
        driver_config.target_url,
        driver_config.concurrency,
        qps_label,
    );
    println!();

    let driver = Driver::new(entries, driver_config);
    let report = driver.run().await;

    print!("{}", report);

    mock.shutdown().await;

    Ok(())
}

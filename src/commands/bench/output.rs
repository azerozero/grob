//! Terminal output rendering for benchmark results.
//!
//! Provides table formatting, bar charts, and JSON serialisation for the
//! `grob bench` command. All functions are pure — they receive data and
//! write to stdout; no I/O side-effects beyond printing.

use std::time::Duration;

use crate::commands::bench::stats::{format_rps, format_us, Stats};

// ── Bar chart ────────────────────────────────────────────────────────────────

/// Renders a Unicode block bar chart for the given proportion (0.0..=1.0).
pub(super) fn render_bar(proportion: f64, width: usize) -> String {
    let filled = (proportion * width as f64).round() as usize;
    let filled = filled.min(width);
    let empty = width - filled;
    format!("{}{}", "\u{2588}".repeat(filled), "\u{2591}".repeat(empty))
}

// ── Scenario table ───────────────────────────────────────────────────────────

/// Prints the scenario table header (Scenario, P50, P95, P99/RPS, Overhead) and a separator line.
pub(super) fn print_scenario_header(is_concurrent: bool, effective_concurrency: usize) {
    if is_concurrent {
        println!(
            "  {:<22} {:>9} {:>9} {:>9} {:>10} {:>10}",
            "Scenario",
            "P50",
            "P95",
            "RPS",
            format!("c={}", effective_concurrency),
            "Overhead"
        );
    } else {
        println!(
            "  {:<22} {:>9} {:>9} {:>9} {:>10}",
            "Scenario", "P50", "P95", "P99", "Overhead"
        );
    }
    println!(
        "  {}",
        "\u{2500}".repeat(if is_concurrent { 73 } else { 63 })
    );
}

/// Prints one benchmark scenario row (p50/p99 latency, overhead vs. baseline, and optional RPS).
pub(super) fn print_scenario_row(
    name: &str,
    stats: &Stats,
    overhead_us: Option<f64>,
    rps: Option<f64>,
    is_concurrent: bool,
) {
    let overhead_str = match overhead_us {
        Some(us) => format!("+{}", format_us(Duration::from_secs_f64(us / 1_000_000.0))),
        None => "\u{2014}".to_string(),
    };

    if is_concurrent {
        let rps_str = rps
            .map(format_rps)
            .unwrap_or_else(|| "\u{2014}".to_string());
        println!(
            "  {:<22} {:>9} {:>9} {:>9} {:>10} {:>10}",
            name,
            format_us(stats.p50),
            format_us(stats.p95),
            format_us(stats.p99),
            rps_str,
            overhead_str,
        );
    } else {
        println!(
            "  {:<22} {:>9} {:>9} {:>9} {:>10}",
            name,
            format_us(stats.p50),
            format_us(stats.p95),
            format_us(stats.p99),
            overhead_str,
        );
    }
}

// ── Multi-payload matrix ─────────────────────────────────────────────────────

/// Prints a payload×scenario matrix table (P50 per cell).
pub(super) fn print_matrix_table(size_labels: &[&str], rows: &[(String, Vec<Stats>)]) {
    let col_width = 12;
    print!("  {:<22}", "Scenario");
    for label in size_labels {
        print!(" {:>width$}", label, width = col_width);
    }
    println!();
    let total_width = 22 + size_labels.len() * (col_width + 1);
    println!("  {}", "\u{2500}".repeat(total_width));
    for (name, stats_per_size) in rows {
        print!("  {:<22}", name);
        for stats in stats_per_size {
            print!(" {:>width$}", format_us(stats.p50), width = col_width);
        }
        println!();
    }
}

// ── Escalation table ─────────────────────────────────────────────────────────

/// One rendered row for the escalation staircase.
pub(super) struct EscalationRow {
    pub(super) label: String,
    pub(super) p50: Duration,
    pub(super) rps: Option<f64>,
    pub(super) overhead: Option<Duration>,
}

/// Prints the escalation staircase table with a bar chart column.
pub(super) fn print_escalation_table(rows: &[EscalationRow]) {
    let max_overhead_us = rows
        .iter()
        .filter_map(|r| r.overhead)
        .map(|d| d.as_secs_f64() * 1_000_000.0)
        .fold(0.0_f64, f64::max);

    const BAR_WIDTH: usize = 8;

    println!(
        "  {:<28} {:>9} {:>9} {:>10}  {:>10}",
        "Feature Escalation", "P50", "RPS", "", "Overhead"
    );
    println!("  {}", "\u{2500}".repeat(70));

    for row in rows {
        let p50_str = format_us(row.p50);
        let rps_str = row
            .rps
            .map(format_rps)
            .unwrap_or_else(|| "\u{2014}".to_string());

        let (bar_str, overhead_str) = match row.overhead {
            Some(oh) => {
                let oh_us = oh.as_secs_f64() * 1_000_000.0;
                let proportion = if max_overhead_us > 0.0 {
                    oh_us / max_overhead_us
                } else {
                    0.0
                };
                let bar = render_bar(proportion, BAR_WIDTH);
                let label = format!(
                    "+{}",
                    format_us(Duration::from_secs_f64(oh_us / 1_000_000.0))
                );
                (bar, label)
            }
            None => (" ".repeat(BAR_WIDTH), "\u{2014}".to_string()),
        };

        println!(
            "  {:<28} {:>9} {:>9}    {}  {:>10}",
            row.label, p50_str, rps_str, bar_str, overhead_str,
        );
    }
}

/// Prints the per-feature overhead breakdown with bar charts.
pub(super) fn print_overhead_breakdown(
    feature_costs: &[(&str, Duration)],
    total_overhead: Duration,
) {
    println!();
    println!("  Overhead breakdown:");

    let total_overhead_us = total_overhead.as_secs_f64() * 1_000_000.0;
    let max_feature_us = feature_costs
        .iter()
        .map(|(_, d)| d.as_secs_f64() * 1_000_000.0)
        .fold(0.0_f64, f64::max);

    const BREAKDOWN_BAR_WIDTH: usize = 40;

    for (name, cost) in feature_costs {
        let cost_us = cost.as_secs_f64() * 1_000_000.0;
        let pct = if total_overhead_us > 0.0 {
            (cost_us / total_overhead_us * 100.0).round() as u32
        } else {
            0
        };
        let proportion = if max_feature_us > 0.0 {
            cost_us / max_feature_us
        } else {
            0.0
        };
        let bar = render_bar(proportion, BREAKDOWN_BAR_WIDTH);
        let clean_name = name.strip_prefix("+ ").unwrap_or(name);
        println!(
            "    {:<18} {}  {:>3}%  {}",
            clean_name,
            bar,
            pct,
            format_us(Duration::from_secs_f64(cost_us / 1_000_000.0)),
        );
    }
}

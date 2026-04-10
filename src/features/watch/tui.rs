//! Terminal UI for `grob watch` — live traffic inspector.
//!
//! Connects to the SSE endpoint and renders a ratatui dashboard
//! with provider health, live request stream, and DLP alerts.

use crate::features::watch::events::WatchEvent;
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};
use std::io::stdout;
use std::time::Duration;

/// Maximum events kept in the scrollback buffer.
const MAX_EVENTS: usize = 200;

/// TUI application state.
struct App {
    events: Vec<WatchEvent>,
    paused: bool,
    should_quit: bool,
    dlp_count: DlpCounters,
    provider_stats: std::collections::HashMap<String, ProviderStats>,
}

struct DlpCounters {
    secrets: u32,
    pii: u32,
    injections: u32,
}

struct ProviderStats {
    last_latency_ms: u64,
    success_count: u64,
    error_count: u64,
}

impl ProviderStats {
    fn success_rate(&self) -> f64 {
        let total = self.success_count + self.error_count;
        if total == 0 {
            return 100.0;
        }
        (self.success_count as f64 / total as f64) * 100.0
    }
}

impl App {
    fn new() -> Self {
        Self {
            events: Vec::new(),
            paused: false,
            should_quit: false,
            dlp_count: DlpCounters {
                secrets: 0,
                pii: 0,
                injections: 0,
            },
            provider_stats: std::collections::HashMap::new(),
        }
    }

    fn push_event(&mut self, event: WatchEvent) {
        if self.paused {
            return;
        }

        // Update counters.
        match &event {
            WatchEvent::RequestEnd {
                provider,
                latency_ms,
                ..
            } => {
                let stats = self
                    .provider_stats
                    .entry(provider.clone())
                    .or_insert_with(|| ProviderStats {
                        last_latency_ms: 0,
                        success_count: 0,
                        error_count: 0,
                    });
                stats.last_latency_ms = *latency_ms;
                stats.success_count += 1;
            }
            WatchEvent::RequestError { provider, .. } => {
                let stats = self
                    .provider_stats
                    .entry(provider.clone())
                    .or_insert_with(|| ProviderStats {
                        last_latency_ms: 0,
                        success_count: 0,
                        error_count: 0,
                    });
                stats.error_count += 1;
            }
            WatchEvent::DlpAction { rule_type, .. } => {
                if rule_type.contains("secret") || rule_type.contains("api_key") {
                    self.dlp_count.secrets += 1;
                } else if rule_type.contains("pii") || rule_type.contains("email") {
                    self.dlp_count.pii += 1;
                } else if rule_type.contains("injection") {
                    self.dlp_count.injections += 1;
                }
            }
            _ => {}
        }

        self.events.push(event);
        if self.events.len() > MAX_EVENTS {
            self.events.remove(0);
        }
    }

    fn handle_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('p') => self.paused = !self.paused,
            _ => {}
        }
    }
}

/// Runs the TUI, connecting to the given grob SSE endpoint.
///
/// # Errors
///
/// Returns an error if the terminal cannot be initialized, the SSE
/// connection fails, or the remote returns a non-success status.
pub async fn run(base_url: &str) -> Result<()> {
    let events_url = format!("{}/api/events", base_url);

    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let mut terminal = ratatui::init();

    let mut app = App::new();

    // Connect to SSE endpoint.
    let client = reqwest::Client::new();
    let response = client
        .get(&events_url)
        .header("Accept", "text/event-stream")
        .send()
        .await?;

    if !response.status().is_success() {
        disable_raw_mode()?;
        stdout().execute(LeaveAlternateScreen)?;
        anyhow::bail!(
            "Failed to connect to {} (status {}). Is grob running?",
            events_url,
            response.status()
        );
    }

    let mut stream = response.bytes_stream();
    let mut buf = String::new();

    loop {
        // Draw.
        terminal.draw(|f| draw(&app, f))?;

        // Poll for terminal events (non-blocking, 50ms timeout).
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.handle_key(key.code);
                }
            }
        }

        if app.should_quit {
            break;
        }

        // Poll for SSE data (non-blocking).
        use futures::StreamExt;
        use tokio::time::timeout;
        match timeout(Duration::from_millis(10), stream.next()).await {
            Ok(Some(Ok(chunk))) => {
                if let Ok(text) = std::str::from_utf8(&chunk) {
                    buf.push_str(text);
                    // Parse complete SSE messages.
                    while let Some(pos) = buf.find("\n\n") {
                        let message = buf[..pos].to_string();
                        buf.drain(..pos + 2);
                        if let Some(data) = message.strip_prefix("data: ").or_else(|| {
                            message
                                .lines()
                                .find(|l| l.starts_with("data: "))
                                .and_then(|l| l.strip_prefix("data: "))
                        }) {
                            if let Ok(event) = serde_json::from_str::<WatchEvent>(data) {
                                app.push_event(event);
                            }
                        }
                    }
                }
            }
            Ok(Some(Err(_))) | Ok(None) => {
                // Stream ended or errored.
                break;
            }
            Err(_) => {
                // Timeout — no data ready, continue loop.
            }
        }
    }

    ratatui::restore();

    Ok(())
}

/// Renders the TUI layout.
fn draw(app: &App, frame: &mut Frame) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // Providers
            Constraint::Min(10),   // Live stream
            Constraint::Length(3), // Alerts
        ])
        .split(frame.area());

    draw_providers(app, frame, chunks[0]);
    draw_live_stream(app, frame, chunks[1]);
    draw_alerts(app, frame, chunks[2]);
}

/// Top panel: provider health indicators.
fn draw_providers(app: &App, frame: &mut Frame, area: ratatui::layout::Rect) {
    let mut spans = Vec::new();

    for (name, stats) in &app.provider_stats {
        let color = if stats.success_rate() > 95.0 {
            Color::Green
        } else if stats.success_rate() > 80.0 {
            Color::Yellow
        } else {
            Color::Red
        };

        spans.push(Span::styled(
            format!(
                "  {} ● {}ms {:.0}%  ",
                name,
                stats.last_latency_ms,
                stats.success_rate()
            ),
            Style::default().fg(color),
        ));
    }

    if spans.is_empty() {
        spans.push(Span::styled(
            "  Waiting for events...",
            Style::default().fg(Color::DarkGray),
        ));
    }

    let para = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .title(" Providers ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(para, area);
}

/// Main panel: live event stream.
fn draw_live_stream(app: &App, frame: &mut Frame, area: ratatui::layout::Rect) {
    let items: Vec<ListItem> = app
        .events
        .iter()
        .rev()
        .take(area.height as usize - 2)
        .map(|e| format_event(e))
        .collect();

    let title = if app.paused {
        " Live [PAUSED] "
    } else {
        " Live "
    };

    let list = List::new(items).block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::White)),
    );
    frame.render_widget(list, area);
}

/// Bottom panel: DLP counters + circuit breaker status.
fn draw_alerts(app: &App, frame: &mut Frame, area: ratatui::layout::Rect) {
    let line = Line::from(vec![
        Span::styled("  DLP: ", Style::default().fg(Color::Yellow)),
        Span::raw(format!("{} secrets", app.dlp_count.secrets)),
        Span::raw(" | "),
        Span::raw(format!("{} PII", app.dlp_count.pii)),
        Span::raw(" | "),
        Span::raw(format!("{} injections", app.dlp_count.injections)),
    ]);

    let para = Paragraph::new(line).block(
        Block::default()
            .title(" Alerts ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow)),
    );
    frame.render_widget(para, area);
}

/// Formats a single event as a colored ListItem.
fn format_event(event: &WatchEvent) -> ListItem<'static> {
    let line = match event {
        WatchEvent::RequestStart {
            model,
            provider,
            input_tokens,
            timestamp,
            ..
        } => Line::from(vec![
            Span::styled(
                format!("  {}  ", timestamp.format("%H:%M:%S")),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled("→ ", Style::default().fg(Color::Cyan)),
            Span::styled(format!("{:<24}", model), Style::default().fg(Color::White)),
            Span::styled(
                format!("{:<16}", provider),
                Style::default().fg(Color::Blue),
            ),
            Span::raw(format!("{} tok", input_tokens)),
        ]),

        WatchEvent::RequestEnd {
            model,
            provider,
            output_tokens,
            latency_ms,
            cost_usd,
            timestamp,
            ..
        } => Line::from(vec![
            Span::styled(
                format!("  {}  ", timestamp.format("%H:%M:%S")),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled("← ", Style::default().fg(Color::Green)),
            Span::styled(format!("{:<24}", model), Style::default().fg(Color::White)),
            Span::styled(
                format!("{:<16}", provider),
                Style::default().fg(Color::Blue),
            ),
            Span::raw(format!(
                "{} tok  {:.1}s  ${:.3}",
                output_tokens,
                *latency_ms as f64 / 1000.0,
                cost_usd
            )),
        ]),

        WatchEvent::RequestError {
            provider,
            error,
            timestamp,
            ..
        } => Line::from(vec![
            Span::styled(
                format!("  {}  ", timestamp.format("%H:%M:%S")),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format!("✗ {}: {}", provider, error),
                Style::default().fg(Color::Red),
            ),
        ]),

        WatchEvent::DlpAction {
            action,
            rule_type,
            detail,
            timestamp,
            ..
        } => Line::from(vec![
            Span::styled(
                format!("  {}  ", timestamp.format("%H:%M:%S")),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format!("DLP {}: {} ({})", action, rule_type, detail),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),

        WatchEvent::Fallback {
            from_provider,
            to_provider,
            reason,
            timestamp,
            ..
        } => Line::from(vec![
            Span::styled(
                format!("  {}  ", timestamp.format("%H:%M:%S")),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format!("FALLBACK {} → {} ({})", from_provider, to_provider, reason),
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),

        WatchEvent::CircuitBreaker {
            provider,
            state,
            timestamp,
        } => Line::from(vec![
            Span::styled(
                format!("  {}  ", timestamp.format("%H:%M:%S")),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format!("CB {} → {}", provider, state),
                Style::default().fg(if state == "open" {
                    Color::Red
                } else {
                    Color::Green
                }),
            ),
        ]),

        WatchEvent::ProviderHealth { .. } => {
            // Absorbed into the top panel, not shown in stream.
            Line::from("")
        }

        WatchEvent::HitApprovalRequest {
            tool_name,
            timestamp,
            ..
        } => Line::from(vec![
            Span::styled(
                format!("  {}  ", timestamp.format("%H:%M:%S")),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format!("HIT awaiting approval: {}", tool_name),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),

        WatchEvent::HitApprovalResponse {
            tool_name,
            approved,
            timestamp,
            ..
        } => Line::from(vec![
            Span::styled(
                format!("  {}  ", timestamp.format("%H:%M:%S")),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format!(
                    "HIT {} {}",
                    if *approved { "approved" } else { "denied" },
                    tool_name
                ),
                Style::default().fg(if *approved { Color::Green } else { Color::Red }),
            ),
        ]),

        WatchEvent::HitFlaggedContent {
            pattern,
            matched_text,
            timestamp,
            ..
        } => Line::from(vec![
            Span::styled(
                format!("  {}  ", timestamp.format("%H:%M:%S")),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format!("HIT flagged [{pattern}]: {matched_text}"),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
    };

    ListItem::new(line)
}

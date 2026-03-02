use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ── Validated newtypes ──────────────────────────────────────────────────────

/// Monthly budget in USD. Rejects negative values at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(transparent)]
pub struct BudgetUsd(f64);

impl BudgetUsd {
    /// Creates a new `BudgetUsd`, returning an error if negative.
    pub fn new(value: f64) -> Result<Self, String> {
        if value < 0.0 {
            Err(format!("budget_usd must be non-negative, got {}", value))
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the inner USD value.
    pub fn value(self) -> f64 {
        self.0
    }
}

impl Default for BudgetUsd {
    fn default() -> Self {
        Self(0.0)
    }
}

impl<'de> Deserialize<'de> for BudgetUsd {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = f64::deserialize(deserializer)?;
        BudgetUsd::new(v).map_err(serde::de::Error::custom)
    }
}

/// TCP port number. Rejects 0 at parse time, defaults to 13456.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Port(u16);

impl Port {
    /// Creates a new `Port`, returning an error if 0.
    pub fn new(value: u16) -> Result<Self, String> {
        if value == 0 {
            Err("port must be non-zero".to_string())
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the inner port number.
    pub fn value(self) -> u16 {
        self.0
    }
}

impl Default for Port {
    fn default() -> Self {
        Self(13456)
    }
}

impl From<Port> for u16 {
    fn from(p: Port) -> u16 {
        p.0
    }
}

impl std::fmt::Display for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<BudgetUsd> for f64 {
    fn from(b: BudgetUsd) -> f64 {
        b.0
    }
}

impl std::fmt::Display for BudgetUsd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<BodySizeLimit> for usize {
    fn from(b: BodySizeLimit) -> usize {
        b.0
    }
}

impl std::fmt::Display for BodySizeLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'de> Deserialize<'de> for Port {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = u16::deserialize(deserializer)?;
        Port::new(v).map_err(serde::de::Error::custom)
    }
}

/// Request body size limit in bytes. Rejects 0 at parse time, defaults to 10 MiB.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(transparent)]
pub struct BodySizeLimit(usize);

impl BodySizeLimit {
    /// Creates a new `BodySizeLimit`, returning an error if 0.
    pub fn new(value: usize) -> Result<Self, String> {
        if value == 0 {
            Err("max_body_size must be non-zero".to_string())
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the inner byte count.
    pub fn value(self) -> usize {
        self.0
    }
}

impl Default for BodySizeLimit {
    fn default() -> Self {
        Self(10 * 1024 * 1024) // 10 MiB
    }
}

impl<'de> Deserialize<'de> for BodySizeLimit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = usize::deserialize(deserializer)?;
        BodySizeLimit::new(v).map_err(serde::de::Error::custom)
    }
}

/// Where the configuration comes from: local file or remote URL
#[derive(Debug, Clone)]
pub enum ConfigSource {
    File(PathBuf),
    Url(String),
}

impl std::fmt::Display for ConfigSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigSource::File(p) => write!(f, "{}", p.display()),
            ConfigSource::Url(u) => write!(f, "{}", u),
        }
    }
}

//! Bounded, format-aware echo removal. Protocol delimiters are never secret values.

use super::{filter::EchoFilter, CredentialError, Result};
use zeroize::{Zeroize, Zeroizing};

const DOCUMENT_LIMIT: usize = 2 * 1024 * 1024;
const EVENT_LIMIT: usize = 64 * 1024;

enum Format {
    Json,
    Events,
    Text,
    Form,
}

pub(crate) struct ResponseFilter {
    secrets: EchoFilter,
    format: Format,
    pending: Zeroizing<Vec<u8>>,
    line: Zeroizing<Vec<u8>>,
    after_cr: bool,
    first_line: bool,
    emitted_suffix: Zeroizing<Vec<u8>>,
}

impl ResponseFilter {
    pub(crate) fn new(content_type: &str, secrets: EchoFilter) -> Result<Self> {
        let format = match content_type {
            "application/json" => Format::Json,
            "text/event-stream" => Format::Events,
            "text/plain" => Format::Text,
            "application/x-www-form-urlencoded" => Format::Form,
            _ => return Err(CredentialError::Denied),
        };
        Ok(Self {
            secrets,
            format,
            pending: Zeroizing::new(Vec::new()),
            line: Zeroizing::new(Vec::new()),
            after_cr: false,
            first_line: true,
            emitted_suffix: Zeroizing::new(Vec::new()),
        })
    }

    pub(crate) fn push(&mut self, bytes: &[u8], finish: bool) -> Result<Vec<u8>> {
        match self.format {
            Format::Text => {
                let clean = self.secrets.push(bytes, finish);
                // Replacements can form a different secret together with surrounding
                // text. Check that boundary before releasing any bytes from this push.
                self.emitted_suffix.extend_from_slice(&clean);
                if self.secrets.contains(&self.emitted_suffix) {
                    return Err(CredentialError::Denied);
                }
                let keep = self.secrets.max_len().saturating_sub(1);
                let suffix =
                    self.emitted_suffix[self.emitted_suffix.len().saturating_sub(keep)..].to_vec();
                self.emitted_suffix.zeroize();
                *self.emitted_suffix = suffix;
                Ok(clean)
            }
            Format::Events => self.events(bytes, finish),
            Format::Json | Format::Form => {
                if self.pending.len().saturating_add(bytes.len()) > DOCUMENT_LIMIT {
                    return Err(CredentialError::Denied);
                }
                self.pending.extend_from_slice(bytes);
                if !finish || self.pending.is_empty() {
                    return Ok(Vec::new());
                }
                let result = match self.format {
                    Format::Json => self.json(&self.pending),
                    _ => self.form(),
                };
                self.pending.zeroize();
                result
            }
        }
    }

    fn json(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let mut value =
            JsonSecret(serde_json::from_slice(bytes).map_err(|_| CredentialError::Denied)?);
        self.scrub(&mut value.0)?;
        serde_json::to_vec(&value.0).map_err(|_| CredentialError::Denied)
    }

    fn scrub(&self, value: &mut serde_json::Value) -> Result<()> {
        use serde_json::Value;
        match value {
            Value::String(s) => {
                if self.secrets.contains(s.as_bytes()) {
                    let clean = self.secrets.scalar(s);
                    s.zeroize();
                    *s = clean;
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.scrub(item)?;
                }
            }
            Value::Object(items) => {
                for (key, value) in items {
                    // Renaming keys can silently merge fields. Refuse such a document.
                    if self.secrets.contains(key.as_bytes()) {
                        return Err(CredentialError::Denied);
                    }
                    self.scrub(value)?;
                }
            }
            scalar => {
                let encoded = Zeroizing::new(scalar.to_string());
                if self.secrets.contains(encoded.as_bytes()) {
                    *scalar = Value::String(self.secrets.scalar(&encoded));
                }
            }
        }
        Ok(())
    }

    fn form(&self) -> Result<Vec<u8>> {
        let input = std::str::from_utf8(&self.pending).map_err(|_| CredentialError::Denied)?;
        let mut output = url::form_urlencoded::Serializer::new(String::new());
        for (name, value) in url::form_urlencoded::parse(input.as_bytes()) {
            let name = Zeroizing::new(name.into_owned());
            let value = Zeroizing::new(value.into_owned());
            if self.secrets.contains(name.as_bytes()) {
                return Err(CredentialError::Denied);
            }
            output.append_pair(&name, &self.secrets.scalar(&value));
        }
        Ok(output.finish().into_bytes())
    }

    fn events(&mut self, bytes: &[u8], finish: bool) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for &byte in bytes {
            if self.after_cr && byte == b'\n' {
                self.after_cr = false;
                continue;
            }
            self.after_cr = byte == b'\r';
            if byte == b'\n' || byte == b'\r' {
                if self.first_line {
                    // The first line already spans input chunks; strip only the stream's BOM.
                    if self.line.starts_with(b"\xef\xbb\xbf") {
                        self.line.drain(..3);
                    }
                    self.first_line = false;
                }
                if self.line.is_empty() {
                    out.extend(self.event()?);
                    self.pending.zeroize();
                } else {
                    self.pending.extend_from_slice(&self.line);
                    self.pending.push(b'\n');
                    self.line.zeroize();
                }
            } else {
                self.line.push(byte);
            }
            if self.pending.len() + self.line.len() > EVENT_LIMIT {
                return Err(CredentialError::Denied);
            }
        }
        if finish {
            // SSE dispatches only completed events, never an unterminated final event.
            self.pending.zeroize();
            self.line.zeroize();
        }
        Ok(out)
    }

    fn event(&self) -> Result<Vec<u8>> {
        let input = std::str::from_utf8(&self.pending).map_err(|_| CredentialError::Denied)?;
        let mut data = Zeroizing::new(String::new());
        let mut out = String::new();
        let mut has_data = false;
        for line in input.lines() {
            let (field, value) = line.split_once(':').unwrap_or((line, ""));
            let value = value.strip_prefix(' ').unwrap_or(value);
            match field {
                "data" => {
                    if has_data {
                        data.push('\n');
                    }
                    data.push_str(value);
                    has_data = true;
                }
                "event" | "id" | "" => {
                    out.push_str(field);
                    out.push_str(": ");
                    out.push_str(&self.secrets.scalar(value));
                    out.push('\n');
                }
                "retry"
                    if value.bytes().all(|b| b.is_ascii_digit())
                        && !self.secrets.contains(value.as_bytes()) =>
                {
                    out.push_str("retry: ");
                    out.push_str(value);
                    out.push('\n');
                }
                _ => {} // Unknown SSE fields have no semantics and need not expose echoes.
            }
        }
        if has_data {
            // SSE data is not necessarily JSON (e.g. [DONE]). Decode JSON when valid
            // so unicode escapes cannot hide an echo, otherwise preserve text semantics.
            let clean = if let Ok(parsed) = serde_json::from_str(&data) {
                let mut value = JsonSecret(parsed);
                self.scrub(&mut value.0)?;
                serde_json::to_string(&value.0).map_err(|_| CredentialError::Denied)?
            } else {
                self.secrets.scalar(&data)
            };
            for line in clean.split('\n') {
                out.push_str("data: ");
                out.push_str(line);
                out.push('\n');
            }
        }
        if !out.is_empty() {
            out.push('\n');
        }
        Ok(out.into_bytes())
    }
}

struct JsonSecret(serde_json::Value);
impl Drop for JsonSecret {
    fn drop(&mut self) {
        fn clear(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::String(s) => s.zeroize(),
                serde_json::Value::Array(a) => a.iter_mut().for_each(clear),
                serde_json::Value::Object(o) => {
                    for (mut key, mut value) in std::mem::take(o) {
                        key.zeroize();
                        clear(&mut value);
                    }
                }
                _ => {}
            }
        }
        clear(&mut self.0);
    }
}

#[cfg(test)]
mod tests;

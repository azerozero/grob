//! Builtin prompt injection patterns for 28 languages + universal obfuscation.
//!
//! This is a pure data module — all pattern definitions are extracted here
//! to keep the detection engine in `prompt_injection.rs` focused on logic.
//!
//! Language-specific patterns live in [`languages`], while shared types,
//! the compiler, and the universal patterns remain here.

mod languages;

use regex::Regex;

/// Compiled injection pattern with a human-readable name.
pub(super) struct CompiledPattern {
    pub name: String,
    pub regex: Regex,
}

pub(super) type LanguageBuilder = (&'static str, fn() -> Vec<CompiledPattern>);

/// All supported language pattern builders.
pub(super) const LANGUAGE_BUILDERS: &[LanguageBuilder] = &[
    ("en", languages::builtin_en_patterns),
    ("fr", languages::builtin_fr_patterns),
    ("de", languages::builtin_de_patterns),
    ("es", languages::builtin_es_patterns),
    ("it", languages::builtin_it_patterns),
    ("pt", languages::builtin_pt_patterns),
    ("nl", languages::builtin_nl_patterns),
    ("pl", languages::builtin_pl_patterns),
    ("ro", languages::builtin_ro_patterns),
    ("hu", languages::builtin_hu_patterns),
    ("cs", languages::builtin_cs_patterns),
    ("el", languages::builtin_el_patterns),
    ("bg", languages::builtin_bg_patterns),
    ("sv", languages::builtin_sv_patterns),
    ("da", languages::builtin_da_patterns),
    ("fi", languages::builtin_fi_patterns),
    ("ru", languages::builtin_ru_patterns),
    ("uk", languages::builtin_uk_patterns),
    ("tr", languages::builtin_tr_patterns),
    ("ar", languages::builtin_ar_patterns),
    ("zh", languages::builtin_zh_patterns),
    ("ja", languages::builtin_ja_patterns),
    ("ko", languages::builtin_ko_patterns),
    ("hi", languages::builtin_hi_patterns),
    ("th", languages::builtin_th_patterns),
    ("vi", languages::builtin_vi_patterns),
    ("id", languages::builtin_id_patterns),
    ("eo", languages::builtin_eo_patterns),
];

/// Universal obfuscation patterns (always active regardless of language config).
pub(super) fn builtin_universal_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        ("univ_base64_ignore", r"(?i)(?:aWdub3Jl|SWdub3Jl)"),
        ("univ_base64_system_prompt", r"(?i)c3lzdGVtIHByb21wdA"),
        (
            "univ_hidden_instruction",
            r"(?i)<\s*(hidden|invisible|system)\s*>.*?(instruction|prompt|ignore)",
        ),
        ("univ_rot13_ignore", r"(?i)\bvtaber\b"),
        ("univ_jailbreak", r"(?i)\bjailbreak\b"),
        ("univ_dan_mode", r"(?i)\bDAN\s+mode\b"),
        (
            "univ_developer_mode",
            r"(?i)\bdeveloper\s+mode\s+(enabled|activated)\b",
        ),
        (
            "univ_hidden_in_code",
            r"(?i)```\s*(system|instruction|ignore\s+previous)",
        ),
        (
            "univ_delimiter_injection",
            r"(?i)-{5,}\s*(system|new\s+instruction|override)",
        ),
        ("univ_tag_chars", r"[\u{E0020}-\u{E007E}]{4,}"),
    ])
}

fn compile_patterns(patterns: Vec<(&str, &str)>) -> Vec<CompiledPattern> {
    patterns
        .into_iter()
        .filter_map(|(name, pat)| {
            Regex::new(pat).ok().map(|regex| CompiledPattern {
                name: name.to_string(),
                regex,
            })
        })
        .collect()
}

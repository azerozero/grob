//! Fenced examples and their closest preceding heading; code never contains headings.

#[derive(Debug)]
pub(super) struct Block {
    pub language: String,
    pub source: String,
    pub heading: String,
    pub line: usize,
}

pub(super) fn blocks(markdown: &str) -> Result<Vec<Block>, String> {
    let mut blocks = Vec::new();
    let mut heading = String::new();
    let mut open: Option<(char, usize, usize, Block)> = None;
    for (index, line) in markdown.lines().enumerate() {
        let trimmed = line.trim_start();
        let indent = &line[..line.len() - trimmed.len()];
        let fence_allowed = indent.len() <= 3 && indent.bytes().all(|b| b == b' ');
        if let Some((character, length, opening_indent, block)) = open.as_mut() {
            let run = trimmed.chars().take_while(|c| c == character).count();
            if fence_allowed && run >= *length && trimmed[run..].trim().is_empty() {
                blocks.push(open.take().expect("open fence").3);
            } else {
                let remove = line
                    .bytes()
                    .take(*opening_indent)
                    .take_while(|b| *b == b' ')
                    .count();
                block.source.push_str(&line[remove..]);
                block.source.push('\n');
            }
            continue;
        }
        // CommonMark fences and ATX headings permit up to three leading spaces.
        if !fence_allowed {
            continue;
        }
        if let Some(character @ ('`' | '~')) = trimmed.chars().next() {
            let length = trimmed.chars().take_while(|c| *c == character).count();
            if length >= 3 {
                open = Some((
                    character,
                    length,
                    indent.len(),
                    Block {
                        language: trimmed[length..]
                            .split_whitespace()
                            .next()
                            .unwrap_or_default()
                            .to_owned(),
                        source: String::new(),
                        heading: heading.clone(),
                        line: index + 2,
                    },
                ));
                continue;
            }
        }
        let hashes = trimmed.chars().take_while(|c| *c == '#').count();
        if (1..=6).contains(&hashes) && trimmed[hashes..].starts_with(' ') {
            heading = trimmed.to_owned();
        }
    }
    if let Some((_, _, _, block)) = open {
        return Err(format!("line {}: unclosed code fence", block.line));
    }
    Ok(blocks)
}

#[test]
fn indentation_matches_rendered_code() {
    let parsed = blocks("   ```python\n   print(1)\n   ```\n").unwrap();
    assert_eq!(parsed[0].source, "print(1)\n");
    let parsed = blocks("```python\npass\n    ```\nreturn 1\n```\n").unwrap();
    assert_eq!(parsed[0].source, "pass\n    ```\nreturn 1\n");
    assert!(blocks("```python\npass\n\t```\n").is_err());
}

#[test]
fn comments_and_fake_headings_inside_code_stay_in_the_example() {
    let source = "## TLS\r\n```toml\r\n[server.tls]\r\n# comment\r\n## not a heading\r\nenabled = true\r\n```\r\n## Next\r\n```bash\r\ntrue\r\n```\r\n";
    let parsed = blocks(source).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].heading, "## TLS");
    assert!(parsed[0]
        .source
        .contains("## not a heading\nenabled = true"));
    assert!(toml::from_str::<toml::Value>(&parsed[0].source).is_ok());
    assert_eq!(parsed[1].heading, "## Next");
}

#[test]
fn fences_require_a_matching_character_and_at_least_the_opening_length() {
    let parsed = blocks("## A\n````text\n```\n~~~\n`````\n").unwrap();
    assert_eq!(parsed[0].source, "```\n~~~\n");
    assert!(blocks("```toml\nx=1\n").is_err());
    assert!(blocks("~~~toml\nx=1\n```\n").is_err());
}

# ADR-0005: Anthropic-native provider trait abstraction

## Status

Accepted

## Context and Problem Statement

Grob supports multiple LLM providers (Anthropic, OpenAI, Gemini, DeepSeek, Ollama). How should providers be abstracted to allow uniform routing and fallback?

## Decision Drivers

- Anthropic Messages API is the internal canonical format
- Other providers need format translation (OpenAI chat completions, Gemini, etc.)
- Fallback between providers must be transparent to the caller
- Streaming must be supported uniformly

## Considered Options

- OpenAI-compatible format as the internal standard (most providers support it)
- Anthropic Messages API as the internal standard
- Abstract intermediate format (neither OpenAI nor Anthropic)

## Decision Outcome

Chosen option: "Anthropic Messages API as the internal standard", because grob was built Anthropic-first and the Anthropic format is more expressive (native thinking blocks, tool use, multi-turn). All providers implement the `LlmProvider` trait which accepts Anthropic-format requests and returns Anthropic-format responses. OpenAI compatibility is handled by a translation layer at the HTTP boundary.

### Consequences

- Good, because Anthropic features (thinking, tool use) are first-class citizens
- Good, because single trait with clear contract simplifies routing and fallback
- Good, because OpenAI translation is isolated in `src/server/openai_compat/`
- Bad, because providers that speak OpenAI natively need double translation (OpenAI in -> Anthropic internal -> OpenAI out)

### Confirmation

The `LlmProvider` trait is defined in `src/providers/mod.rs`. All provider implementations (Anthropic, OpenAI, Gemini, DeepSeek, Ollama) implement this trait.

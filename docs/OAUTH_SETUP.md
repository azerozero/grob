# OAuth Authentication Setup

grob now supports OAuth authentication for Claude Pro/Max subscriptions, allowing you to use your Claude subscription without needing an API key!

## Features

- ✅ **Zero Cost**: Max plan users pay $0 for API calls
- ✅ **PKCE Security**: Secure OAuth 2.0 with PKCE (Proof Key for Code Exchange)
- ✅ **Auto Refresh**: Tokens are automatically refreshed when expired
- ✅ **Persistent Storage**: Tokens stored securely in `~/.grob/oauth_tokens.json`

## Quick Start

### 1. Get Authorization URL

```rust
use grob::auth::{OAuthClient, OAuthConfig, TokenStore};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize
    let config = OAuthConfig::anthropic();
    let token_store = TokenStore::default()?;
    let oauth_client = OAuthClient::new(config, token_store);

    // Get authorization URL
    let auth_url = oauth_client.get_authorization_url();

    println!("Go to: {}", auth_url.url);
    println!();
    println!("After authorization, you'll receive a code.");
    println!("Enter the code here:");

    // Read code from user
    let mut code = String::new();
    std::io::stdin().read_line(&mut code)?;
    let code = code.trim();

    // Exchange code for tokens
    let token = oauth_client.exchange_code(
        code,
        &auth_url.verifier.verifier,
        "anthropic-max"  // Provider ID
    ).await?;

    println!("✅ Authentication successful!");
    println!("Access token expires at: {}", token.expires_at);

    Ok(())
}
```

### 2. Configure Provider

Edit `~/.grob/config.toml`:

```toml
[server]
host = "127.0.0.1"
port = 13456

[router]
default = "claude-sonnet"

# OAuth Provider
[[providers]]
name = "claude-max"
provider_type = "anthropic"
auth_type = "oauth"
oauth_provider = "anthropic-max"

[[models]]
name = "claude-sonnet"

[[models.mappings]]
actual_model = "claude-sonnet-4-6"
priority = 1
provider = "claude-max"
```

### 3. Start Server

```bash
grob start
```

## OAuth Configuration Options

### OAuthConfig::anthropic()

For Claude Pro/Max users:
- **Client ID**: `9d1c250a-e61b-44d9-88ed-5944d1962f5e`
- **Auth URL**: `https://claude.ai/oauth/authorize`
- **Token URL**: `https://console.anthropic.com/v1/oauth/token`
- **Scopes**: `org:create_api_key user:profile user:inference`

### OAuthConfig::anthropic_console()

For creating an API key via OAuth (alternative flow):
- Uses console.anthropic.com for authorization
- Creates an API key automatically after OAuth
- Useful if you want a traditional API key workflow

## Token Storage

Tokens are stored in JSON format at `~/.grob/oauth_tokens.json`:

```json
{
  "anthropic-max": {
    "provider_id": "anthropic-max",
    "access_token": "ey...",
    "refresh_token": "rt_...",
    "expires_at": "2025-11-18T15:30:00Z",
    "enterprise_url": null
  }
}
```

File permissions are automatically set to `0600` (owner read/write only) for security.

## API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/oauth/authorize` | POST | Get authorization URL |
| `/api/oauth/exchange` | POST | Exchange authorization code for tokens |
| `/api/oauth/tokens` | GET | List all OAuth tokens |
| `/api/oauth/tokens/refresh` | POST | Refresh a token |
| `/api/oauth/tokens/delete` | POST | Delete a token |

## Usage Example

```rust
use grob::auth::{OAuthClient, OAuthConfig, TokenStore};

let config = OAuthConfig::anthropic();
let token_store = TokenStore::default()?;
let client = OAuthClient::new(config, token_store);

// Get valid token (auto-refreshes if needed)
let access_token = client.get_valid_token("anthropic-max").await?;

// Use in HTTP request
let response = reqwest::Client::new()
    .post("https://api.anthropic.com/v1/messages")
    .header("Authorization", format!("Bearer {}", access_token))
    .header("anthropic-version", "2023-06-01")
    .json(&request_body)
    .send()
    .await?;
```

## Security Notes

1. **Never commit tokens**: The `oauth_tokens.json` file contains sensitive credentials
2. **File permissions**: Always stored with `0600` permissions (Unix)
3. **PKCE**: Uses SHA-256 challenge for additional security
4. **Auto-refresh**: Tokens are refreshed 5 minutes before expiration

## Comparison: API Key vs OAuth

| Feature | API Key | OAuth (Max Plan) |
|---------|---------|------------------|
| Setup   | Simple  | One-time OAuth flow |
| Cost    | Pay per token | $0 (included in subscription) |
| Security| Static key | Rotating tokens + PKCE |
| Sharing | Easy (but unsafe) | Per-user authentication |
| Expiration | Never | Auto-refreshes |

## Troubleshooting

### "Token refresh failed"
- Check your internet connection
- Verify your Max subscription is active
- Re-authenticate: Delete token and run OAuth flow again

### "No token found for provider"
- Run the OAuth authorization flow first
- Check that `oauth_provider` in config matches the provider_id in TokenStore

### "Environment variable not found"
- OAuth doesn't use environment variables
- Make sure `auth_type = "oauth"` is set in provider config

## Related

- [OpenCode Anthropic Auth](https://github.com/sst/opencode-anthropic-auth) - Inspiration for this implementation
- [Anthropic OAuth Docs](https://docs.anthropic.com/claude/reference/oauth)

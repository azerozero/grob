# OAuth Testing Guide

This guide shows how to test the OAuth authentication flow for Claude Pro/Max.

## Quick Test (CLI Example)

### 1. Build the project

```bash
cargo build --examples
```

### 2. Run OAuth login example

```bash
cargo run --example oauth_login
```

This will:
1. Generate an authorization URL
2. Prompt you to visit the URL and authorize
3. Ask for the authorization code
4. Exchange code for access/refresh tokens
5. Save tokens to `~/.grob/oauth_tokens.json`

### Example Output

```
🔐 Claude Max OAuth Authentication

This will authenticate your Claude Pro/Max account
and save the OAuth token for use with grob.

Step 1: Visit the following URL in your browser:

  https://claude.ai/oauth/authorize?code=true&client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e...

Step 2: After authorizing, you'll receive a code.

Enter the authorization code here: abc123def456#state789

Exchanging code for tokens...

✅ Authentication successful!

Token details:
  Provider ID: anthropic-max
  Expires at: 2025-11-18T16:30:00+00:00

Your OAuth token has been saved to:
  ~/.grob/oauth_tokens.json
```

## Testing with API Endpoints

### 1. Start the server

```bash
cargo run -- start
```

### 2. Get authorization URL

```bash
curl -X POST http://localhost:13456/api/oauth/authorize \
  -H "Content-Type: application/json" \
  -d '{"oauth_type": "max"}'
```

Response:
```json
{
  "url": "https://claude.ai/oauth/authorize?...",
  "verifier": "xxxxxxxxxxx",
  "instructions": "Visit the URL above to authorize..."
}
```

### 3. Exchange code for tokens

Visit the URL, authorize, and get the code. Then:

```bash
curl -X POST http://localhost:13456/api/oauth/exchange \
  -H "Content-Type: application/json" \
  -d '{
    "code": "your-code-here#state",
    "verifier": "verifier-from-step-2",
    "provider_id": "anthropic-max"
  }'
```

Response:
```json
{
  "success": true,
  "message": "OAuth authentication successful! Token saved.",
  "provider_id": "anthropic-max",
  "expires_at": "2025-11-18T16:30:00+00:00"
}
```

### 4. List tokens

```bash
curl http://localhost:13456/api/oauth/tokens
```

Response:
```json
[
  {
    "provider_id": "anthropic-max",
    "expires_at": "2025-11-18T16:30:00+00:00",
    "is_expired": false,
    "needs_refresh": false
  }
]
```

### 5. Refresh token

```bash
curl -X POST http://localhost:13456/api/oauth/tokens/refresh \
  -H "Content-Type: application/json" \
  -d '{"provider_id": "anthropic-max"}'
```

### 6. Delete token

```bash
curl -X POST http://localhost:13456/api/oauth/tokens/delete \
  -H "Content-Type: application/json" \
  -d '{"provider_id": "anthropic-max"}'
```

## Using OAuth with Providers

### 1. Configure provider

Edit `config/default.toml`:

```toml
[[providers]]
name = "claude-max"
provider_type = "anthropic"
auth_type = "oauth"  # Use OAuth instead of API key
oauth_provider = "anthropic-max"  # Must match provider_id from exchange
enabled = true
models = []

[[models]]
name = "claude-sonnet-4.5"

[[models.mappings]]
actual_model = "claude-sonnet-4-5-20250929"
priority = 1
provider = "claude-max"
```

### 2. Restart server

```bash
cargo run -- restart
```

### 3. Test with Claude Code

The provider will automatically use the OAuth token from TokenStore and authenticate with Bearer tokens!

**✅ Phase 3 Complete**: OAuth providers now use Bearer token authentication automatically. When you make requests to Claude via an OAuth-configured provider, the system will:
1. Load the token from TokenStore
2. Check if it needs refresh (5 min before expiry)
3. Auto-refresh if needed
4. Use Bearer token in Authorization header
5. Include OAuth beta headers for full compatibility

## Troubleshooting

### Token not found

Check if token exists:
```bash
cat ~/.grob/oauth_tokens.json
```

Should show:
```json
{
  "anthropic-max": {
    "provider_id": "anthropic-max",
    "access_token": "ey...",
    "refresh_token": "rt_...",
    "expires_at": "2025-11-18T16:30:00+00:00",
    "enterprise_url": null
  }
}
```

### Token expired

Tokens automatically refresh 5 minutes before expiry.
To manually refresh:
```bash
curl -X POST http://localhost:13456/api/oauth/tokens/refresh \
  -H "Content-Type: application/json" \
  -d '{"provider_id": "anthropic-max"}'
```

### Authorization failed

Common issues:
1. **Wrong client ID**: We use OpenCode's client ID (`9d1c250a-e61b-44d9-88ed-5944d1962f5e`)
2. **Invalid redirect URI**: Must be `https://console.anthropic.com/oauth/code/callback`
3. **Code already used**: Authorization codes can only be used once
4. **PKCE mismatch**: Ensure you use the same verifier from authorize step

## Next Steps

After successful authentication:

1. ✅ Token saved to `~/.grob/oauth_tokens.json`
2. ✅ Configure provider with `auth_type = "oauth"`
3. ✅ **Phase 3 Complete**: Bearer token injection works automatically!
4. 🚧 **Phase 4**: Add OAuth UI to admin panel (in progress)

## Security Notes

- Tokens stored with `0600` permissions (owner read/write only)
- Never commit `oauth_tokens.json` to version control
- Tokens auto-refresh before expiration
- PKCE ensures secure authorization flow

## API Endpoint Summary

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/oauth/authorize` | POST | Get authorization URL |
| `/api/oauth/exchange` | POST | Exchange code for tokens |
| `/api/oauth/tokens` | GET | List all tokens |
| `/api/oauth/tokens/refresh` | POST | Refresh a token |
| `/api/oauth/tokens/delete` | POST | Delete a token |

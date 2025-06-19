# OAuth 2.0 Authentication for Memento MCP

Memento MCP supports OAuth 2.0 authentication to secure access to the MCP server endpoints. This implementation follows the OAuth 2.0 Authorization Code flow and provides a basic authorization endpoint that accepts any username/password combination for testing and development purposes.

## Table of Contents

- [Overview](#overview)
- [Configuration](#configuration)
- [OAuth Endpoints](#oauth-endpoints)
- [Authentication Flow](#authentication-flow)
- [Using OAuth with MCP](#using-oauth-with-mcp)
- [Examples](#examples)
- [Security Considerations](#security-considerations)

## Overview

The OAuth implementation provides:

- **Authorization Code Flow**: Standard OAuth 2.0 flow for web applications
- **JWT Access Tokens**: Self-contained tokens with user and scope information
- **Scope-based Authorization**: Granular permissions (mcp:read, mcp:write, mcp:tools, mcp:admin)
- **Basic Authorization Endpoint**: Accepts any username/password for testing
- **Token Introspection**: RFC 7662 compliant token validation
- **Server Metadata**: OAuth discovery endpoint

## Configuration

### Environment Variables

Configure OAuth authentication using these environment variables:

```bash
# Enable OAuth authentication
OAUTH_ENABLED=true

# OAuth client credentials (change in production)
OAUTH_CLIENT_ID=memento-mcp-client
OAUTH_CLIENT_SECRET=your-secure-client-secret

# JWT signing secret (change in production)
OAUTH_JWT_SECRET=your-secure-jwt-secret

# OAuth server settings
OAUTH_ISSUER=http://localhost:3000
OAUTH_SCOPES=mcp:read,mcp:write,mcp:tools,mcp:admin
OAUTH_REDIRECT_URIS=http://localhost:3000/oauth/callback

# Token expiration settings (in seconds)
OAUTH_AUTH_CODE_TTL=600        # 10 minutes
OAUTH_ACCESS_TOKEN_TTL=3600    # 1 hour
OAUTH_REFRESH_TOKEN_TTL=604800 # 7 days
```

### Scope Definitions

The OAuth implementation supports these scopes:

- **mcp:read**: Read access to knowledge graph data
- **mcp:write**: Write access to create/update entities and relations
- **mcp:tools**: Access to use MCP tools and functions
- **mcp:admin**: Full administrative access (includes all other scopes)

## OAuth Endpoints

When OAuth is enabled, the following endpoints are available:

### Authorization Endpoint
- **GET/POST** `/oauth/authorize`
- Used to obtain authorization codes
- Displays a simple form for username/password input
- Accepts any username/password combination (basic implementation)

### Token Endpoint
- **POST** `/oauth/token`
- Exchanges authorization codes for access tokens
- Supports `authorization_code` grant type

### Token Introspection Endpoint
- **POST** `/oauth/introspect`
- Validates access tokens (RFC 7662)
- Returns token status and metadata

### Server Metadata Endpoint
- **GET** `/.well-known/oauth-authorization-server`
- OAuth server discovery endpoint (RFC 8414)
- Returns server capabilities and endpoint URLs

## Authentication Flow

### 1. Authorization Request

Start the flow by redirecting users to the authorization endpoint:

```
GET /oauth/authorize?
    client_id=memento-mcp-client&
    redirect_uri=http://localhost:3000/oauth/callback&
    response_type=code&
    scope=mcp:read+mcp:write&
    state=random-state-value
```

### 2. User Authentication

The server displays a simple form where users can enter any username and password. This basic implementation accepts all credentials for testing purposes.

### 3. Authorization Code

After successful authentication, the user is redirected back with an authorization code:

```
http://localhost:3000/oauth/callback?
    code=auth_code_here&
    state=random-state-value
```

### 4. Token Exchange

Exchange the authorization code for an access token:

```bash
curl -X POST http://localhost:3000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=auth_code_here" \
  -d "redirect_uri=http://localhost:3000/oauth/callback" \
  -d "client_id=memento-mcp-client" \
  -d "client_secret=your-secure-client-secret"
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "scope": "mcp:read mcp:write"
}
```

## Using OAuth with MCP

### Authenticated MCP Requests

Include the access token in the Authorization header when making MCP requests:

```bash
curl -X POST http://localhost:3000/mcp \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/list",
    "params": {},
    "id": 1
  }'
```

### Token Introspection

Validate tokens using the introspection endpoint:

```bash
curl -X POST http://localhost:3000/oauth/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -d "client_id=memento-mcp-client" \
  -d "client_secret=your-secure-client-secret"
```

Response:
```json
{
  "active": true,
  "client_id": "memento-mcp-client",
  "username": "user123",
  "scope": "mcp:read mcp:write",
  "exp": 1672531200,
  "iat": 1672527600,
  "token_type": "Bearer"
}
```

## Examples

### Example Configuration

Create an `.env` file with OAuth settings:

```bash
# Enable OAuth
OAUTH_ENABLED=true

# Client credentials
OAUTH_CLIENT_ID=my-mcp-client
OAUTH_CLIENT_SECRET=super-secret-key-change-me
OAUTH_JWT_SECRET=jwt-signing-secret-change-me

# Server settings
OAUTH_ISSUER=http://localhost:3000
OAUTH_SCOPES=mcp:read,mcp:write,mcp:tools

# Token lifetimes
OAUTH_ACCESS_TOKEN_TTL=7200  # 2 hours
```

### Starting the Server with OAuth

```bash
# Set environment variables
export OAUTH_ENABLED=true
export OAUTH_CLIENT_SECRET=your-secret-here

# Start HTTP server
MCP_TRANSPORT_MODE=http npm start
```

### Complete Authentication Example

```bash
# 1. Get authorization form
curl -G http://localhost:3000/oauth/authorize \
  -d client_id=memento-mcp-client \
  -d redirect_uri=http://localhost:3000/oauth/callback \
  -d response_type=code \
  -d scope="mcp:read mcp:write" \
  -d state=abc123

# 2. Submit credentials (replace with actual form submission)
curl -X POST http://localhost:3000/oauth/authorize \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=memento-mcp-client" \
  -d "redirect_uri=http://localhost:3000/oauth/callback" \
  -d "response_type=code" \
  -d "scope=mcp:read mcp:write" \
  -d "state=abc123" \
  -d "username=testuser" \
  -d "password=testpass"

# 3. Extract code from redirect URL and exchange for token
curl -X POST http://localhost:3000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE_FROM_STEP_2" \
  -d "redirect_uri=http://localhost:3000/oauth/callback" \
  -d "client_id=memento-mcp-client" \
  -d "client_secret=your-secret-here"

# 4. Use access token for MCP requests
curl -X POST http://localhost:3000/mcp \
  -H "Authorization: Bearer ACCESS_TOKEN_FROM_STEP_3" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/list",
    "params": {},
    "id": 1
  }'
```

## Security Considerations

### Basic Implementation Warning

⚠️ **Important**: The current authorization endpoint accepts any username/password combination. This is designed for testing and development purposes only.

### Production Recommendations

For production use, you should:

1. **Implement Real User Authentication**: Replace the basic authorization endpoint with proper user validation
2. **Use Strong Secrets**: Generate cryptographically secure secrets for client and JWT signing
3. **Configure HTTPS**: Always use HTTPS in production
4. **Validate Redirect URIs**: Ensure redirect URIs are properly validated
5. **Implement Rate Limiting**: Add rate limiting to prevent abuse
6. **Secure Token Storage**: Store tokens securely on the client side
7. **Regular Token Rotation**: Implement refresh token rotation

### Example Production Security Configuration

```bash
# Use strong, randomly generated secrets
OAUTH_CLIENT_SECRET=$(openssl rand -base64 32)
OAUTH_JWT_SECRET=$(openssl rand -base64 32)

# Use HTTPS in production
OAUTH_ISSUER=https://your-domain.com

# Restrict redirect URIs
OAUTH_REDIRECT_URIS=https://your-domain.com/oauth/callback

# Shorter token lifetimes for better security
OAUTH_ACCESS_TOKEN_TTL=1800  # 30 minutes
OAUTH_REFRESH_TOKEN_TTL=86400  # 1 day
```

### Custom User Authentication

To implement real user authentication, modify the `OAuthService.handleAuthorize` method to validate credentials against your user database:

```typescript
// Replace the basic authentication logic with:
const isValidUser = await validateUserCredentials(username, password);
if (!isValidUser) {
  // Redirect with access_denied error
  return;
}
```

## Testing OAuth

The OAuth implementation includes comprehensive tests. Run them with:

```bash
npm test -- oauth-authentication.test.ts
```

Tests cover:
- OAuth configuration
- Authorization endpoint
- Token endpoint
- Token introspection
- Authentication middleware
- Complete OAuth flow
- Error scenarios

---

For more information about the MCP specification and OAuth requirements, see:
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization)
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [OAuth 2.0 Token Introspection RFC 7662](https://tools.ietf.org/html/rfc7662)
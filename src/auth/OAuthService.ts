import { Request, Response } from 'express';
import { OAuthConfig, OAuthClient, OAuthServerMetadata } from './OAuthConfig.js';
import { TokenService } from './TokenService.js';
import { logger } from '../utils/logger.js';

export class OAuthService {
  private tokenService: TokenService;
  private clients = new Map<string, OAuthClient>();

  constructor(private config: OAuthConfig) {
    this.tokenService = new TokenService(config);
    
    // Register default client
    this.registerDefaultClient();
  }

  private registerDefaultClient(): void {
    const defaultClient: OAuthClient = {
      id: this.config.clientId,
      secret: this.config.clientSecret,
      redirectUris: this.config.redirectUris,
      scopes: this.config.scopes,
      name: 'Memento MCP Default Client',
    };
    
    this.clients.set(defaultClient.id, defaultClient);
    logger.info(`Registered OAuth client: ${defaultClient.id}`);
  }

  // Authorization Endpoint - Basic implementation accepting any username/password
  async handleAuthorize(req: Request, res: Response): Promise<void> {
    try {
      const {
        client_id,
        redirect_uri,
        response_type,
        scope,
        state,
        username,
        password,
      } = req.method === 'GET' ? req.query : req.body;

      // Validate required parameters
      if (!client_id || !redirect_uri || !response_type) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing required parameters: client_id, redirect_uri, response_type',
        });
        return;
      }

      // Validate client
      const client = this.clients.get(client_id as string);
      if (!client) {
        res.status(400).json({
          error: 'invalid_client',
          error_description: 'Unknown client identifier',
        });
        return;
      }

      // Validate redirect URI
      if (!client.redirectUris.includes(redirect_uri as string)) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Invalid redirect_uri',
        });
        return;
      }

      // Validate response type
      if (response_type !== 'code') {
        const params = new URLSearchParams({
          error: 'unsupported_response_type',
          error_description: 'Only authorization code flow is supported',
          ...(state && { state: state as string }),
        });
        res.redirect(`${redirect_uri}?${params.toString()}`);
        return;
      }

      // Validate scopes
      const requestedScopes = scope ? (scope as string).split(' ') : ['mcp:read'];
      const validScopes = requestedScopes.filter(s => client.scopes.includes(s));
      
      if (validScopes.length === 0) {
        const params = new URLSearchParams({
          error: 'invalid_scope',
          error_description: 'No valid scopes requested',
          ...(state && { state: state as string }),
        });
        res.redirect(`${redirect_uri}?${params.toString()}`);
        return;
      }

      // If no credentials provided, show authorization form
      if (!username || !password) {
        res.send(this.generateAuthorizationForm({
          client_id: client_id as string,
          redirect_uri: redirect_uri as string,
          response_type: response_type as string,
          scope: validScopes.join(' '),
          state: state as string,
          client_name: client.name,
        }));
        return;
      }

      // Basic authentication - accept any username/password combination
      // In a real implementation, you would validate against a user database
      const userId = username as string;
      
      logger.info(`User authentication attempt: ${userId}`);
      
      // Always accept credentials (as requested - basic implementation)
      if (userId && password) {
        // Generate authorization code
        const authCode = this.tokenService.generateAuthorizationCode(
          client_id as string,
          userId,
          redirect_uri as string,
          validScopes
        );

        // Redirect with authorization code
        const params = new URLSearchParams({
          code: authCode,
          ...(state && { state: state as string }),
        });
        
        logger.info(`Authorization successful for user ${userId}, redirecting to ${redirect_uri}`);
        res.redirect(`${redirect_uri}?${params.toString()}`);
        return;
      }

      // Authentication failed
      const params = new URLSearchParams({
        error: 'access_denied',
        error_description: 'Authentication failed',
        ...(state && { state: state as string }),
      });
      res.redirect(`${redirect_uri}?${params.toString()}`);
    } catch (error) {
      logger.error('Error in authorization endpoint:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error',
      });
    }
  }

  // Token Endpoint
  async handleToken(req: Request, res: Response): Promise<void> {
    try {
      const {
        grant_type,
        code,
        redirect_uri,
        client_id,
        client_secret,
        refresh_token,
      } = req.body;

      // Validate grant type
      if (!grant_type || !['authorization_code', 'refresh_token'].includes(grant_type)) {
        res.status(400).json({
          error: 'unsupported_grant_type',
          error_description: 'Only authorization_code and refresh_token grant types are supported',
        });
        return;
      }

      // Validate client credentials
      if (!client_id || !client_secret) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing client credentials',
        });
        return;
      }

      const client = this.clients.get(client_id);
      if (!client || client.secret !== client_secret) {
        res.status(401).json({
          error: 'invalid_client',
          error_description: 'Invalid client credentials',
        });
        return;
      }

      if (grant_type === 'authorization_code') {
        // Authorization code flow
        if (!code || !redirect_uri) {
          res.status(400).json({
            error: 'invalid_request',
            error_description: 'Missing authorization code or redirect_uri',
          });
          return;
        }

        const authCode = this.tokenService.validateAuthorizationCode(code, client_id, redirect_uri);
        if (!authCode) {
          res.status(400).json({
            error: 'invalid_grant',
            error_description: 'Invalid or expired authorization code',
          });
          return;
        }

        // Generate access token
        const { accessToken, refreshToken } = this.tokenService.generateAccessToken(
          client_id,
          authCode.userId,
          authCode.scopes
        );

        res.json({
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: this.config.accessTokenTtl,
          refresh_token: refreshToken,
          scope: authCode.scopes.join(' '),
        });
      } else if (grant_type === 'refresh_token') {
        // Refresh token flow
        if (!refresh_token) {
          res.status(400).json({
            error: 'invalid_request',
            error_description: 'Missing refresh token',
          });
          return;
        }

        // For simplicity, we'll implement refresh token validation later
        res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Refresh token flow not yet implemented',
        });
      }
    } catch (error) {
      logger.error('Error in token endpoint:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error',
      });
    }
  }

  // Token Introspection Endpoint
  async handleIntrospect(req: Request, res: Response): Promise<void> {
    try {
      const { token, client_id, client_secret } = req.body;

      if (!token) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing token parameter',
        });
        return;
      }

      // Validate client credentials if provided
      if (client_id && client_secret) {
        const client = this.clients.get(client_id);
        if (!client || client.secret !== client_secret) {
          res.status(401).json({
            error: 'invalid_client',
            error_description: 'Invalid client credentials',
          });
          return;
        }
      }

      const introspection = this.tokenService.validateAccessToken(token);
      res.json(introspection);
    } catch (error) {
      logger.error('Error in introspection endpoint:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error',
      });
    }
  }

  // OAuth Server Metadata Endpoint
  async handleServerMetadata(req: Request, res: Response): Promise<void> {
    try {
      const metadata: OAuthServerMetadata = {
        issuer: this.config.issuer,
        authorization_endpoint: `${this.config.issuer}/oauth/authorize`,
        token_endpoint: `${this.config.issuer}/oauth/token`,
        introspection_endpoint: `${this.config.issuer}/oauth/introspect`,
        scopes_supported: this.config.scopes,
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        token_endpoint_auth_methods_supported: ['client_secret_post'],
      };

      res.json(metadata);
    } catch (error) {
      logger.error('Error in server metadata endpoint:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error',
      });
    }
  }

  // Utility method to validate Bearer token from Authorization header
  validateBearerToken(authHeader: string | undefined): { valid: boolean; userId?: string; scopes?: string[] } {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return { valid: false };
    }

    const token = authHeader.substring(7);
    const introspection = this.tokenService.validateAccessToken(token);

    if (!introspection.active) {
      return { valid: false };
    }

    return {
      valid: true,
      userId: introspection.username,
      scopes: introspection.scope?.split(' ') || [],
    };
  }

  private generateAuthorizationForm(params: {
    client_id: string;
    redirect_uri: string;
    response_type: string;
    scope: string;
    state: string;
    client_name: string;
  }): string {
    return `
<!DOCTYPE html>
<html>
<head>
    <title>Authorize Application</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        button { background: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }
        button:hover { background: #005a8b; }
        .app-info { background: #f5f5f5; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
        .scopes { font-size: 0.9em; color: #666; }
    </style>
</head>
<body>
    <div class="app-info">
        <h2>Authorize ${params.client_name}</h2>
        <p>This application is requesting access to your account with the following permissions:</p>
        <div class="scopes"><strong>Scopes:</strong> ${params.scope}</div>
    </div>
    
    <form method="post" action="/oauth/authorize">
        <input type="hidden" name="client_id" value="${params.client_id}">
        <input type="hidden" name="redirect_uri" value="${params.redirect_uri}">
        <input type="hidden" name="response_type" value="${params.response_type}">
        <input type="hidden" name="scope" value="${params.scope}">
        <input type="hidden" name="state" value="${params.state}">
        
        <div class="form-group">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required placeholder="Enter any username">
        </div>
        
        <div class="form-group">
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required placeholder="Enter any password">
        </div>
        
        <button type="submit">Authorize</button>
    </form>
    
    <p style="font-size: 0.8em; color: #666; margin-top: 20px;">
        Note: This is a basic implementation that accepts any username and password combination.
    </p>
</body>
</html>`;
  }
}
import { Request, Response } from 'express';
import { OAuthConfig, OAuthClient, OAuthServerMetadata, ClientRegistrationRequest, ClientRegistrationResponse, ClientRegistrationError } from './OAuthConfig.js';
import { TokenService } from './TokenService.js';
import { logger } from '../utils/logger.js';
import { randomUUID } from 'node:crypto';
import { TemplateRenderer } from './TemplateRenderer.js';

export class OAuthService {
  private tokenService: TokenService;
  private clients = new Map<string, OAuthClient>();
  private templateRenderer: TemplateRenderer;

  constructor(private config: OAuthConfig) {
    this.tokenService = new TokenService(config);
    this.templateRenderer = new TemplateRenderer(config.callbackConfig);
    
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

  /**
   * Handles OAuth authorization requests (GET/POST /oauth/authorize)
   * 
   * This endpoint implements the OAuth 2.0 authorization code flow.
   * It displays an authorization form for GET requests without credentials,
   * and processes authorization for POST requests with credentials.
   * 
   * @param req - Express request object with query/body parameters
   * @param res - Express response object
   * 
   * @example
   * GET /oauth/authorize?client_id=test&redirect_uri=http://localhost/callback&response_type=code&scope=read&state=xyz
   * POST /oauth/authorize with form data including username/password
   */
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

  /**
   * Handles OAuth token exchange requests (POST /oauth/token)
   * 
   * This endpoint exchanges authorization codes for access tokens
   * according to the OAuth 2.0 specification.
   * 
   * @param req - Express request object with form data
   * @param res - Express response object
   * 
   * @example
   * POST /oauth/token with grant_type=authorization_code&code=xyz&client_id=test&client_secret=secret
   */
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

  /**
   * Handles OAuth token introspection requests (POST /oauth/introspect)
   * 
   * This endpoint validates and returns information about access tokens
   * according to RFC 7662.
   * 
   * @param req - Express request object with form data including token
   * @param res - Express response object
   * 
   * @example
   * POST /oauth/introspect with token=access_token&client_id=test&client_secret=secret
   */
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

  /**
   * Handles OAuth server metadata requests (GET /.well-known/oauth-authorization-server)
   * 
   * This endpoint provides OAuth server configuration according to RFC 8414.
   * 
   * @param req - Express request object
   * @param res - Express response object
   * 
   * @example
   * GET /.well-known/oauth-authorization-server
   */
  async handleServerMetadata(req: Request, res: Response): Promise<void> {
    try {
      const metadata: OAuthServerMetadata = {
        issuer: this.config.issuer,
        authorization_endpoint: `${this.config.issuer}/oauth/authorize`,
        token_endpoint: `${this.config.issuer}/oauth/token`,
        introspection_endpoint: `${this.config.issuer}/oauth/introspect`,
        registration_endpoint: `${this.config.issuer}/oauth/register`, // RFC7591
        scopes_supported: this.config.scopes,
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none'],
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

  /**
   * Handles OAuth dynamic client registration requests (RFC 7591)
   * 
   * This endpoint supports POST (create), GET (read), PUT (update), and DELETE operations
   * for dynamic client registration according to RFC 7591.
   * 
   * @param req - Express request object
   * @param res - Express response object
   * 
   * @example
   * POST /oauth/register with client registration metadata
   * GET /oauth/register/:client_id with Authorization: Bearer registration_access_token
   */
  async handleClientRegistration(req: Request, res: Response): Promise<void> {
    try {
      const method = req.method.toLowerCase();
      
      if (method === 'post') {
        return this.handleClientRegistrationCreate(req, res);
      } else if (method === 'get') {
        return this.handleClientRegistrationRead(req, res);
      } else if (method === 'put') {
        return this.handleClientRegistrationUpdate(req, res);
      } else if (method === 'delete') {
        return this.handleClientRegistrationDelete(req, res);
      } else {
        res.status(405).json({
          error: 'invalid_request',
          error_description: 'Method not allowed',
        });
      }
    } catch (error) {
      logger.error('Error in client registration endpoint:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error',
      });
    }
  }

  // Handle client registration creation (POST /oauth/register)
  private async handleClientRegistrationCreate(req: Request, res: Response): Promise<void> {
    const registrationRequest = req.body as ClientRegistrationRequest;

    // Validate required fields
    if (!registrationRequest.redirect_uris || !Array.isArray(registrationRequest.redirect_uris) || registrationRequest.redirect_uris.length === 0) {
      res.status(400).json({
        error: 'invalid_redirect_uri',
        error_description: 'redirect_uris is required and must be a non-empty array',
      } as ClientRegistrationError);
      return;
    }

    // Validate redirect URIs
    for (const uri of registrationRequest.redirect_uris) {
      if (!this.isValidRedirectUri(uri)) {
        res.status(400).json({
          error: 'invalid_redirect_uri',
          error_description: `Invalid redirect URI: ${uri}`,
        } as ClientRegistrationError);
        return;
      }
    }

    // Validate and set defaults for optional fields
    const grantTypes = registrationRequest.grant_types || ['authorization_code'];
    const responseTypes = registrationRequest.response_types || ['code'];
    const tokenEndpointAuthMethod = registrationRequest.token_endpoint_auth_method || 'client_secret_basic';

    // Validate grant types
    const supportedGrantTypes = ['authorization_code', 'refresh_token'];
    const invalidGrantTypes = grantTypes.filter(gt => !supportedGrantTypes.includes(gt));
    if (invalidGrantTypes.length > 0) {
      res.status(400).json({
        error: 'invalid_client_metadata',
        error_description: `Unsupported grant types: ${invalidGrantTypes.join(', ')}`,
      } as ClientRegistrationError);
      return;
    }

    // Validate response types
    const supportedResponseTypes = ['code'];
    const invalidResponseTypes = responseTypes.filter(rt => !supportedResponseTypes.includes(rt));
    if (invalidResponseTypes.length > 0) {
      res.status(400).json({
        error: 'invalid_client_metadata',
        error_description: `Unsupported response types: ${invalidResponseTypes.join(', ')}`,
      } as ClientRegistrationError);
      return;
    }

    // Validate token endpoint auth method
    const supportedAuthMethods = ['client_secret_basic', 'client_secret_post', 'none'];
    if (!supportedAuthMethods.includes(tokenEndpointAuthMethod)) {
      res.status(400).json({
        error: 'invalid_client_metadata',
        error_description: `Unsupported token endpoint auth method: ${tokenEndpointAuthMethod}`,
      } as ClientRegistrationError);
      return;
    }

    // Generate client credentials
    const clientId = `client_${randomUUID()}`;
    const clientSecret = tokenEndpointAuthMethod === 'none' ? undefined : this.generateClientSecret();
    const registrationAccessToken = this.generateRegistrationAccessToken();
    const clientIdIssuedAt = Math.floor(Date.now() / 1000);

    // Parse and validate scopes
    const requestedScopes = registrationRequest.scope ? registrationRequest.scope.split(' ') : ['mcp:read'];
    const validScopes = requestedScopes.filter(scope => this.config.scopes.includes(scope));
    
    if (validScopes.length === 0) {
      res.status(400).json({
        error: 'invalid_client_metadata',
        error_description: 'No valid scopes requested',
      } as ClientRegistrationError);
      return;
    }

    // Create the client
    const client: OAuthClient = {
      id: clientId,
      secret: clientSecret || '',
      redirectUris: registrationRequest.redirect_uris,
      scopes: validScopes,
      name: registrationRequest.client_name || `Dynamic Client ${clientId}`,
      clientName: registrationRequest.client_name,
      clientUri: registrationRequest.client_uri,
      logoUri: registrationRequest.logo_uri,
      contacts: registrationRequest.contacts,
      tosUri: registrationRequest.tos_uri,
      policyUri: registrationRequest.policy_uri,
      jwksUri: registrationRequest.jwks_uri,
      jwks: registrationRequest.jwks,
      tokenEndpointAuthMethod: tokenEndpointAuthMethod,
      grantTypes: grantTypes,
      responseTypes: responseTypes,
      softwareId: registrationRequest.software_id,
      softwareVersion: registrationRequest.software_version,
      clientIdIssuedAt: clientIdIssuedAt,
      clientSecretExpiresAt: 0, // 0 means never expires
      registrationAccessToken: registrationAccessToken,
      registrationClientUri: `${this.config.issuer}/oauth/register/${clientId}`,
    };

    // Store the client
    this.clients.set(clientId, client);
    logger.info(`Dynamically registered OAuth client: ${clientId}`);

    // Create response
    const response: ClientRegistrationResponse = {
      client_id: clientId,
      client_secret: clientSecret,
      registration_access_token: registrationAccessToken,
      registration_client_uri: client.registrationClientUri,
      client_id_issued_at: clientIdIssuedAt,
      client_secret_expires_at: 0,
      redirect_uris: client.redirectUris,
      token_endpoint_auth_method: tokenEndpointAuthMethod,
      grant_types: grantTypes,
      response_types: responseTypes,
      client_name: client.clientName,
      client_uri: client.clientUri,
      logo_uri: client.logoUri,
      scope: validScopes.join(' '),
      contacts: client.contacts,
      tos_uri: client.tosUri,
      policy_uri: client.policyUri,
      jwks_uri: client.jwksUri,
      jwks: client.jwks,
      software_id: client.softwareId,
      software_version: client.softwareVersion,
    };

    res.status(201).json(response);
  }

  // Handle client registration read (GET /oauth/register/:client_id)
  private async handleClientRegistrationRead(req: Request, res: Response): Promise<void> {
    const clientId = req.params.client_id;
    const authHeader = req.headers.authorization;

    if (!clientId) {
      res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing client_id parameter',
      } as ClientRegistrationError);
      return;
    }

    const client = this.clients.get(clientId);
    if (!client) {
      res.status(404).json({
        error: 'invalid_client_id',
        error_description: 'Client not found',
      } as ClientRegistrationError);
      return;
    }

    // Validate registration access token
    if (!this.validateRegistrationAccessToken(authHeader, client.registrationAccessToken)) {
      res.status(401).json({
        error: 'invalid_token',
        error_description: 'Invalid or missing registration access token',
      } as ClientRegistrationError);
      return;
    }

    // Return client information
    const response: ClientRegistrationResponse = {
      client_id: client.id,
      client_secret: client.secret || undefined,
      registration_access_token: client.registrationAccessToken,
      registration_client_uri: client.registrationClientUri,
      client_id_issued_at: client.clientIdIssuedAt,
      client_secret_expires_at: client.clientSecretExpiresAt,
      redirect_uris: client.redirectUris,
      token_endpoint_auth_method: client.tokenEndpointAuthMethod,
      grant_types: client.grantTypes,
      response_types: client.responseTypes,
      client_name: client.clientName,
      client_uri: client.clientUri,
      logo_uri: client.logoUri,
      scope: client.scopes.join(' '),
      contacts: client.contacts,
      tos_uri: client.tosUri,
      policy_uri: client.policyUri,
      jwks_uri: client.jwksUri,
      jwks: client.jwks,
      software_id: client.softwareId,
      software_version: client.softwareVersion,
    };

    res.json(response);
  }

  // Handle client registration update (PUT /oauth/register/:client_id)
  private async handleClientRegistrationUpdate(req: Request, res: Response): Promise<void> {
    res.status(501).json({
      error: 'unsupported_operation',
      error_description: 'Client update operation not yet implemented',
    } as ClientRegistrationError);
  }

  // Handle client registration delete (DELETE /oauth/register/:client_id)
  private async handleClientRegistrationDelete(req: Request, res: Response): Promise<void> {
    const clientId = req.params.client_id;
    const authHeader = req.headers.authorization;

    if (!clientId) {
      res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing client_id parameter',
      } as ClientRegistrationError);
      return;
    }

    const client = this.clients.get(clientId);
    if (!client) {
      res.status(404).json({
        error: 'invalid_client_id',
        error_description: 'Client not found',
      } as ClientRegistrationError);
      return;
    }

    // Validate registration access token
    if (!this.validateRegistrationAccessToken(authHeader, client.registrationAccessToken)) {
      res.status(401).json({
        error: 'invalid_token',
        error_description: 'Invalid or missing registration access token',
      } as ClientRegistrationError);
      return;
    }

    // Delete the client
    this.clients.delete(clientId);
    logger.info(`Deleted dynamically registered OAuth client: ${clientId}`);

    res.status(204).send();
  }

  // Helper methods for RFC7591
  private isValidRedirectUri(uri: string): boolean {
    try {
      const url = new URL(uri);
      // Basic validation - must be HTTPS or localhost/private network HTTP
      if (url.protocol === 'https:') {
        return true;
      }
      
      if (url.protocol === 'http:') {
        // Allow localhost
        if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') {
          return true;
        }
        // Allow private network ranges (RFC 1918)
        const ip = url.hostname;
        if (this.isPrivateIpAddress(ip)) {
          return true;
        }
      }
      
      return false;
    } catch {
      return false;
    }
  }

  private isPrivateIpAddress(ip: string): boolean {
    // Check if IP is in private ranges (RFC 1918)
    const ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    const match = ip.match(ipRegex);
    
    if (!match) return false;
    
    const octets = match.slice(1).map(Number);
    
    // 10.0.0.0/8
    if (octets[0] === 10) return true;
    
    // 172.16.0.0/12
    if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true;
    
    // 192.168.0.0/16
    if (octets[0] === 192 && octets[1] === 168) return true;
    
    return false;
  }

  private generateClientSecret(): string {
    return `cs_${randomUUID()}`;
  }

  private generateRegistrationAccessToken(): string {
    return `rat_${randomUUID()}`;
  }

  private validateRegistrationAccessToken(authHeader: string | undefined, expectedToken: string | undefined): boolean {
    if (!authHeader || !expectedToken) {
      return false;
    }

    if (!authHeader.startsWith('Bearer ')) {
      return false;
    }

    const token = authHeader.substring(7);
    return token === expectedToken;
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

  /**
   * Handles OAuth callback requests (GET /oauth/callback)
   * 
   * This endpoint processes authorization callbacks with either success codes
   * or error responses. It displays a user-friendly page with the authorization
   * code and instructions for token exchange.
   * 
   * @param req - Express request object with query parameters (code, state, error, etc.)
   * @param res - Express response object
   * 
   * @example
   * GET /oauth/callback?code=auth123&state=xyz (success)
   * GET /oauth/callback?error=access_denied&error_description=User denied (error)
   */
  async handleCallback(req: Request, res: Response): Promise<void> {
    try {
      const { code, state, error, error_description } = req.query;

      if (error) {
        res.send(this.generateCallbackErrorPage({
          error: error as string,
          error_description: error_description as string,
          state: state as string,
        }));
        return;
      }

      if (!code) {
        res.status(400).send(this.generateCallbackErrorPage({
          error: 'invalid_request',
          error_description: 'Missing authorization code',
          state: state as string,
        }));
        return;
      }

      res.send(this.generateCallbackSuccessPage({
        code: code as string,
        state: state as string,
        token_endpoint: `${this.config.issuer}/oauth/token`,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        redirect_uri: req.query.redirect_uri as string || this.config.redirectUris[0],
      }));
    } catch (error) {
      logger.error('Error in callback endpoint:', error);
      res.status(500).send(this.generateCallbackErrorPage({
        error: 'server_error',
        error_description: 'Internal server error',
        state: req.query.state as string,
      }));
    }
  }

  private generateCallbackSuccessPage(params: {
    code: string;
    state: string;
    token_endpoint: string;
    client_id: string;
    client_secret: string;
    redirect_uri: string;
  }): string {
    return this.templateRenderer.render('callback-success', {
      CODE: params.code,
      STATE: params.state,
      TOKEN_ENDPOINT: params.token_endpoint,
      CLIENT_ID: params.client_id,
      CLIENT_SECRET: params.client_secret,
      REDIRECT_URI: params.redirect_uri,
    });
  }

  private generateCallbackErrorPage(params: {
    error: string;
    error_description?: string;
    state?: string;
  }): string {
    return this.templateRenderer.render('callback-error', {
      ERROR: params.error,
      ERROR_DESCRIPTION: params.error_description,
      STATE: params.state,
    });
  }

  private generateAuthorizationForm(params: {
    client_id: string;
    redirect_uri: string;
    response_type: string;
    scope: string;
    state: string;
    client_name: string;
  }): string {
    return this.templateRenderer.render('authorization-form', {
      CLIENT_ID: params.client_id,
      REDIRECT_URI: params.redirect_uri,
      RESPONSE_TYPE: params.response_type,
      SCOPE: params.scope,
      STATE: params.state,
      CLIENT_NAME: params.client_name,
    });
  }
}
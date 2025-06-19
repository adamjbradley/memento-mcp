import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import express from 'express';
import { OAuthConfig, OAuthService, AuthMiddleware, getOAuthConfig } from '../auth/index.js';

describe('OAuth Authentication', () => {
  let app: express.Application;
  let oauthService: OAuthService;
  let authMiddleware: AuthMiddleware;
  let oauthConfig: OAuthConfig;

  beforeEach(() => {
    // Setup test configuration
    oauthConfig = {
      enabled: true,
      clientId: 'test-client',
      clientSecret: 'test-secret',
      jwtSecret: 'test-jwt-secret',
      issuer: 'http://localhost:3000',
      authorizationCodeTtl: 600,
      accessTokenTtl: 3600,
      refreshTokenTtl: 7 * 24 * 3600,
      scopes: ['mcp:read', 'mcp:write', 'mcp:tools', 'mcp:admin'],
      redirectUris: ['http://localhost:3000/oauth/callback'],
    };

    oauthService = new OAuthService(oauthConfig);
    authMiddleware = new AuthMiddleware(oauthService, true);

    // Setup Express app for testing
    app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));

    // OAuth endpoints
    app.get('/oauth/authorize', (req, res) => oauthService.handleAuthorize(req, res));
    app.post('/oauth/authorize', (req, res) => oauthService.handleAuthorize(req, res));
    app.post('/oauth/token', (req, res) => oauthService.handleToken(req, res));
    app.post('/oauth/introspect', (req, res) => oauthService.handleIntrospect(req, res));
    app.get('/.well-known/oauth-authorization-server', (req, res) => oauthService.handleServerMetadata(req, res));

    // Protected endpoint for testing
    app.post('/protected', authMiddleware.authenticate(), (req, res) => {
      res.json({ message: 'Access granted', user: (req as any).auth });
    });
  });

  describe('OAuth Configuration', () => {
    it('should load OAuth configuration from environment variables', () => {
      // Mock environment variables
      vi.stubEnv('OAUTH_ENABLED', 'true');
      vi.stubEnv('OAUTH_CLIENT_ID', 'env-client');
      vi.stubEnv('OAUTH_CLIENT_SECRET', 'env-secret');
      vi.stubEnv('OAUTH_JWT_SECRET', 'env-jwt-secret');
      vi.stubEnv('OAUTH_SCOPES', 'mcp:read,mcp:write');

      const config = getOAuthConfig();
      
      expect(config.enabled).toBe(true);
      expect(config.clientId).toBe('env-client');
      expect(config.clientSecret).toBe('env-secret');
      expect(config.jwtSecret).toBe('env-jwt-secret');
      expect(config.scopes).toEqual(['mcp:read', 'mcp:write']);
    });

    it('should use defaults when environment variables are not set', () => {
      vi.stubEnv('OAUTH_ENABLED', 'false');
      
      const config = getOAuthConfig();
      
      expect(config.enabled).toBe(false);
      expect(config.clientId).toBe('memento-mcp-client');
      expect(config.scopes).toEqual(['mcp:read', 'mcp:write', 'mcp:tools', 'mcp:admin']);
    });
  });

  describe('OAuth Server Metadata Endpoint', () => {
    it('should return server metadata', async () => {
      const response = await request(app)
        .get('/.well-known/oauth-authorization-server');

      expect(response.status).toBe(200);
      expect(response.body).toMatchObject({
        issuer: 'http://localhost:3000',
        authorization_endpoint: 'http://localhost:3000/oauth/authorize',
        token_endpoint: 'http://localhost:3000/oauth/token',
        introspection_endpoint: 'http://localhost:3000/oauth/introspect',
        scopes_supported: ['mcp:read', 'mcp:write', 'mcp:tools', 'mcp:admin'],
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
      });
    });
  });

  describe('Authorization Endpoint', () => {
    it('should show authorization form when no credentials provided', async () => {
      const response = await request(app)
        .get('/oauth/authorize')
        .query({
          client_id: 'test-client',
          redirect_uri: 'http://localhost:3000/oauth/callback',
          response_type: 'code',
          scope: 'mcp:read mcp:write',
          state: 'test-state',
        });

      expect(response.status).toBe(200);
      expect(response.text).toContain('Authorize');
      expect(response.text).toContain('test-client');
      expect(response.text).toContain('mcp:read mcp:write');
    });

    it('should reject invalid client_id', async () => {
      const response = await request(app)
        .get('/oauth/authorize')
        .query({
          client_id: 'invalid-client',
          redirect_uri: 'http://localhost:3000/oauth/callback',
          response_type: 'code',
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('invalid_client');
    });

    it('should reject invalid redirect_uri', async () => {
      const response = await request(app)
        .get('/oauth/authorize')
        .query({
          client_id: 'test-client',
          redirect_uri: 'http://evil.com/callback',
          response_type: 'code',
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('invalid_request');
    });

    it('should accept any username/password and redirect with authorization code', async () => {
      const response = await request(app)
        .post('/oauth/authorize')
        .send({
          client_id: 'test-client',
          redirect_uri: 'http://localhost:3000/oauth/callback',
          response_type: 'code',
          scope: 'mcp:read',
          state: 'test-state',
          username: 'any-user',
          password: 'any-password',
        })
        .expect(302);

      expect(response.headers.location).toMatch(/^http:\/\/localhost:3000\/oauth\/callback\?code=.+&state=test-state$/);
    });

    it('should reject missing required parameters', async () => {
      const response = await request(app)
        .get('/oauth/authorize')
        .query({
          client_id: 'test-client',
          // Missing redirect_uri and response_type
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('invalid_request');
    });
  });

  describe('Token Endpoint', () => {
    let authorizationCode: string;

    beforeEach(async () => {
      // Get an authorization code first
      const response = await request(app)
        .post('/oauth/authorize')
        .send({
          client_id: 'test-client',
          redirect_uri: 'http://localhost:3000/oauth/callback',
          response_type: 'code',
          scope: 'mcp:read mcp:write',
          username: 'test-user',
          password: 'test-password',
        });

      const location = response.headers.location;
      const url = new URL(location);
      authorizationCode = url.searchParams.get('code')!;
      expect(authorizationCode).toBeTruthy();
    });

    it('should exchange authorization code for access token', async () => {
      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code: authorizationCode,
          redirect_uri: 'http://localhost:3000/oauth/callback',
          client_id: 'test-client',
          client_secret: 'test-secret',
        });

      expect(response.status).toBe(200);
      expect(response.body).toMatchObject({
        access_token: expect.any(String),
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: expect.any(String),
        scope: 'mcp:read mcp:write',
      });
    });

    it('should reject invalid client credentials', async () => {
      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code: authorizationCode,
          redirect_uri: 'http://localhost:3000/oauth/callback',
          client_id: 'test-client',
          client_secret: 'wrong-secret',
        });

      expect(response.status).toBe(401);
      expect(response.body.error).toBe('invalid_client');
    });

    it('should reject invalid authorization code', async () => {
      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code: 'invalid-code',
          redirect_uri: 'http://localhost:3000/oauth/callback',
          client_id: 'test-client',
          client_secret: 'test-secret',
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('invalid_grant');
    });

    it('should reject unsupported grant type', async () => {
      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'client_credentials',
          client_id: 'test-client',
          client_secret: 'test-secret',
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('unsupported_grant_type');
    });
  });

  describe('Token Introspection Endpoint', () => {
    let accessToken: string;

    beforeEach(async () => {
      // Get an access token first
      const authResponse = await request(app)
        .post('/oauth/authorize')
        .send({
          client_id: 'test-client',
          redirect_uri: 'http://localhost:3000/oauth/callback',
          response_type: 'code',
          scope: 'mcp:read mcp:write',
          username: 'test-user',
          password: 'test-password',
        });

      const location = authResponse.headers.location;
      const url = new URL(location);
      const authorizationCode = url.searchParams.get('code')!;

      const tokenResponse = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code: authorizationCode,
          redirect_uri: 'http://localhost:3000/oauth/callback',
          client_id: 'test-client',
          client_secret: 'test-secret',
        });

      accessToken = tokenResponse.body.access_token;
    });

    it('should introspect valid access token', async () => {
      const response = await request(app)
        .post('/oauth/introspect')
        .send({
          token: accessToken,
          client_id: 'test-client',
          client_secret: 'test-secret',
        });

      expect(response.status).toBe(200);
      expect(response.body).toMatchObject({
        active: true,
        client_id: 'test-client',
        username: 'test-user',
        scope: 'mcp:read mcp:write',
        exp: expect.any(Number),
        iat: expect.any(Number),
        token_type: 'Bearer',
      });
    });

    it('should return inactive for invalid token', async () => {
      const response = await request(app)
        .post('/oauth/introspect')
        .send({
          token: 'invalid-token',
          client_id: 'test-client',
          client_secret: 'test-secret',
        });

      expect(response.status).toBe(200);
      expect(response.body).toEqual({ active: false });
    });

    it('should reject missing token parameter', async () => {
      const response = await request(app)
        .post('/oauth/introspect')
        .send({
          client_id: 'test-client',
          client_secret: 'test-secret',
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('invalid_request');
    });
  });

  describe('Authentication Middleware', () => {
    let accessToken: string;

    beforeEach(async () => {
      // Get an access token first
      const authResponse = await request(app)
        .post('/oauth/authorize')
        .send({
          client_id: 'test-client',
          redirect_uri: 'http://localhost:3000/oauth/callback',
          response_type: 'code',
          scope: 'mcp:read mcp:write mcp:tools',
          username: 'test-user',
          password: 'test-password',
        });

      const location = authResponse.headers.location;
      const url = new URL(location);
      const authorizationCode = url.searchParams.get('code')!;

      const tokenResponse = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code: authorizationCode,
          redirect_uri: 'http://localhost:3000/oauth/callback',
          client_id: 'test-client',
          client_secret: 'test-secret',
        });

      accessToken = tokenResponse.body.access_token;
    });

    it('should allow access with valid Bearer token', async () => {
      const response = await request(app)
        .post('/protected')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ test: 'data' });

      expect(response.status).toBe(200);
      expect(response.body).toMatchObject({
        message: 'Access granted',
        user: {
          userId: 'test-user',
          scopes: ['mcp:read', 'mcp:write', 'mcp:tools'],
        },
      });
    });

    it('should reject request without Authorization header', async () => {
      const response = await request(app)
        .post('/protected')
        .send({ test: 'data' });

      expect(response.status).toBe(401);
      expect(response.body).toMatchObject({
        jsonrpc: '2.0',
        error: {
          code: -32001,
          message: 'Unauthorized',
          data: 'Valid Bearer token required',
        },
      });
    });

    it('should reject request with invalid token', async () => {
      const response = await request(app)
        .post('/protected')
        .set('Authorization', 'Bearer invalid-token')
        .send({ test: 'data' });

      expect(response.status).toBe(401);
      expect(response.body).toMatchObject({
        jsonrpc: '2.0',
        error: {
          code: -32001,
          message: 'Unauthorized',
        },
      });
    });

    it('should reject request with malformed Authorization header', async () => {
      const response = await request(app)
        .post('/protected')
        .set('Authorization', 'NotBearer token')
        .send({ test: 'data' });

      expect(response.status).toBe(401);
    });
  });

  describe('Scope-based Authorization', () => {
    let readOnlyToken: string;
    let adminToken: string;

    beforeEach(async () => {
      // Get read-only token
      const readAuthResponse = await request(app)
        .post('/oauth/authorize')
        .send({
          client_id: 'test-client',
          redirect_uri: 'http://localhost:3000/oauth/callback',
          response_type: 'code',
          scope: 'mcp:read',
          username: 'read-user',
          password: 'password',
        });

      let location = readAuthResponse.headers.location;
      let url = new URL(location);
      let authorizationCode = url.searchParams.get('code')!;

      const readTokenResponse = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code: authorizationCode,
          redirect_uri: 'http://localhost:3000/oauth/callback',
          client_id: 'test-client',
          client_secret: 'test-secret',
        });

      readOnlyToken = readTokenResponse.body.access_token;

      // Get admin token
      const adminAuthResponse = await request(app)
        .post('/oauth/authorize')
        .send({
          client_id: 'test-client',
          redirect_uri: 'http://localhost:3000/oauth/callback',
          response_type: 'code',
          scope: 'mcp:admin',
          username: 'admin-user',
          password: 'password',
        });

      location = adminAuthResponse.headers.location;
      url = new URL(location);
      authorizationCode = url.searchParams.get('code')!;

      const adminTokenResponse = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code: authorizationCode,
          redirect_uri: 'http://localhost:3000/oauth/callback',
          client_id: 'test-client',
          client_secret: 'test-secret',
        });

      adminToken = adminTokenResponse.body.access_token;
    });

    it('should validate scope permissions correctly', () => {
      // Test helper methods with read-only request
      const readReq = { auth: { userId: 'read-user', scopes: ['mcp:read'] } } as any;
      expect(authMiddleware.canRead(readReq)).toBe(true);
      expect(authMiddleware.canWrite(readReq)).toBe(false);
      expect(authMiddleware.canUseTools(readReq)).toBe(false);
      expect(authMiddleware.isAdmin(readReq)).toBe(false);

      // Test helper methods with admin request
      const adminReq = { auth: { userId: 'admin-user', scopes: ['mcp:admin'] } } as any;
      expect(authMiddleware.canRead(adminReq)).toBe(true);
      expect(authMiddleware.canWrite(adminReq)).toBe(true);
      expect(authMiddleware.canUseTools(adminReq)).toBe(true);
      expect(authMiddleware.isAdmin(adminReq)).toBe(true);
    });

    it('should allow access when auth is disabled', () => {
      const disabledAuthMiddleware = new AuthMiddleware(oauthService, false);
      const req = {} as any;
      
      expect(disabledAuthMiddleware.canRead(req)).toBe(true);
      expect(disabledAuthMiddleware.canWrite(req)).toBe(true);
      expect(disabledAuthMiddleware.canUseTools(req)).toBe(true);
      expect(disabledAuthMiddleware.isAdmin(req)).toBe(true);
    });
  });

  describe('End-to-End OAuth Flow', () => {
    it('should complete full OAuth authorization code flow', async () => {
      // 1. Start authorization request
      const authFormResponse = await request(app)
        .get('/oauth/authorize')
        .query({
          client_id: 'test-client',
          redirect_uri: 'http://localhost:3000/oauth/callback',
          response_type: 'code',
          scope: 'mcp:read mcp:write',
          state: 'random-state-123',
        });

      expect(authFormResponse.status).toBe(200);
      expect(authFormResponse.text).toContain('Authorize');

      // 2. Submit credentials
      const authResponse = await request(app)
        .post('/oauth/authorize')
        .send({
          client_id: 'test-client',
          redirect_uri: 'http://localhost:3000/oauth/callback',
          response_type: 'code',
          scope: 'mcp:read mcp:write',
          state: 'random-state-123',
          username: 'test-user',
          password: 'any-password',
        });

      expect(authResponse.status).toBe(302);
      const location = authResponse.headers.location;
      expect(location).toMatch(/code=.+/);
      expect(location).toContain('state=random-state-123');

      // 3. Extract authorization code
      const url = new URL(location);
      const authorizationCode = url.searchParams.get('code')!;
      const returnedState = url.searchParams.get('state');
      expect(authorizationCode).toBeTruthy();
      expect(returnedState).toBe('random-state-123');

      // 4. Exchange code for token
      const tokenResponse = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code: authorizationCode,
          redirect_uri: 'http://localhost:3000/oauth/callback',
          client_id: 'test-client',
          client_secret: 'test-secret',
        });

      expect(tokenResponse.status).toBe(200);
      const { access_token, token_type, expires_in, scope } = tokenResponse.body;
      expect(access_token).toBeTruthy();
      expect(token_type).toBe('Bearer');
      expect(expires_in).toBe(3600);
      expect(scope).toBe('mcp:read mcp:write');

      // 5. Use access token to access protected resource
      const protectedResponse = await request(app)
        .post('/protected')
        .set('Authorization', `Bearer ${access_token}`)
        .send({ test: 'data' });

      expect(protectedResponse.status).toBe(200);
      expect(protectedResponse.body.message).toBe('Access granted');
      expect(protectedResponse.body.user.userId).toBe('test-user');

      // 6. Verify token introspection
      const introspectResponse = await request(app)
        .post('/oauth/introspect')
        .send({
          token: access_token,
          client_id: 'test-client',
          client_secret: 'test-secret',
        });

      expect(introspectResponse.status).toBe(200);
      expect(introspectResponse.body.active).toBe(true);
      expect(introspectResponse.body.username).toBe('test-user');
      expect(introspectResponse.body.scope).toBe('mcp:read mcp:write');
    });
  });
});
import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import { OAuthConfig, OAuthService } from '../index.js';

describe('OAuth Callback Endpoint', () => {
  let app: express.Application;
  let oauthService: OAuthService;
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

    // Setup Express app for testing
    app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));

    // OAuth endpoints
    app.get('/oauth/authorize', (req, res) => oauthService.handleAuthorize(req, res));
    app.post('/oauth/authorize', (req, res) => oauthService.handleAuthorize(req, res));
    app.get('/oauth/callback', (req, res) => oauthService.handleCallback(req, res));
    app.post('/oauth/token', (req, res) => oauthService.handleToken(req, res));
  });

  describe('Success Callback', () => {
    it('should display success page with authorization code', async () => {
      const response = await request(app)
        .get('/oauth/callback')
        .query({
          code: 'test-auth-code-123',
          state: 'test-state-xyz',
        });

      expect(response.status).toBe(200);
      expect(response.text).toContain('Authorization Successful');
      expect(response.text).toContain('test-auth-code-123');
      expect(response.text).toContain('test-state-xyz');
      expect(response.text).toContain('Copy Code');
      expect(response.text).toContain('curl -X POST');
    });

    it('should display success page without state parameter', async () => {
      const response = await request(app)
        .get('/oauth/callback')
        .query({
          code: 'test-auth-code-456',
        });

      expect(response.status).toBe(200);
      expect(response.text).toContain('Authorization Successful');
      expect(response.text).toContain('test-auth-code-456');
      expect(response.text).not.toContain('State Parameter');
    });

    it('should include correct token endpoint in cURL example', async () => {
      const response = await request(app)
        .get('/oauth/callback')
        .query({
          code: 'test-code',
          state: 'test-state',
        });

      expect(response.status).toBe(200);
      expect(response.text).toContain('http://localhost:3000/oauth/token');
      expect(response.text).toContain('test-client');
      expect(response.text).toContain('test-secret');
    });

    it('should use dynamic redirect_uri in cURL example when provided', async () => {
      const customRedirectUri = 'http://localhost:8080/custom/callback';
      
      const response = await request(app)
        .get('/oauth/callback')
        .query({
          code: 'test-code',
          state: 'test-state',
          redirect_uri: customRedirectUri,
        });

      expect(response.status).toBe(200);
      expect(response.text).toContain(customRedirectUri);
      expect(response.text).not.toContain('http://localhost:3000/oauth/callback');
    });

    it('should escape HTML special characters in authorization code', async () => {
      const maliciousCode = '<script>alert("xss")</script>';
      
      const response = await request(app)
        .get('/oauth/callback')
        .query({
          code: maliciousCode,
        });

      expect(response.status).toBe(200);
      expect(response.text).toContain('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;');
      expect(response.text).not.toContain('<script>alert("xss")</script>');
    });

    it('should escape HTML special characters in state parameter', async () => {
      const maliciousState = '<img src=x onerror=alert(1)>';
      
      const response = await request(app)
        .get('/oauth/callback')
        .query({
          code: 'safe-code',
          state: maliciousState,
        });

      expect(response.status).toBe(200);
      expect(response.text).toContain('&lt;img src=x onerror=alert(1)&gt;');
      expect(response.text).not.toContain('<img src=x onerror=alert(1)>');
    });
  });

  describe('Error Callback', () => {
    it('should display error page for access_denied', async () => {
      const response = await request(app)
        .get('/oauth/callback')
        .query({
          error: 'access_denied',
          error_description: 'User denied the request',
          state: 'test-state',
        });

      expect(response.status).toBe(200);
      expect(response.text).toContain('Authorization Failed');
      expect(response.text).toContain('access_denied');
      expect(response.text).toContain('User denied the request');
      expect(response.text).toContain('test-state');
    });

    it('should display error page without description', async () => {
      const response = await request(app)
        .get('/oauth/callback')
        .query({
          error: 'invalid_scope',
        });

      expect(response.status).toBe(200);
      expect(response.text).toContain('Authorization Failed');
      expect(response.text).toContain('invalid_scope');
      expect(response.text).not.toContain('<strong>Description:</strong>');
    });

    it('should display error page without state', async () => {
      const response = await request(app)
        .get('/oauth/callback')
        .query({
          error: 'server_error',
          error_description: 'Internal server error',
        });

      expect(response.status).toBe(200);
      expect(response.text).toContain('Authorization Failed');
      expect(response.text).toContain('server_error');
      expect(response.text).not.toContain('<strong>State:</strong>');
    });

    it('should escape HTML special characters in error parameters', async () => {
      const maliciousError = '<script>alert("hack")</script>';
      const maliciousDescription = '<img src=x onerror=alert(2)>';
      
      const response = await request(app)
        .get('/oauth/callback')
        .query({
          error: maliciousError,
          error_description: maliciousDescription,
        });

      expect(response.status).toBe(200);
      expect(response.text).toContain('&lt;script&gt;alert(&quot;hack&quot;)&lt;/script&gt;');
      expect(response.text).toContain('&lt;img src=x onerror=alert(2)&gt;');
      expect(response.text).not.toContain('<script>alert("hack")</script>');
      expect(response.text).not.toContain('<img src=x onerror=alert(2)>');
    });
  });

  describe('Missing Code Error', () => {
    it('should return 400 error when code parameter is missing', async () => {
      const response = await request(app)
        .get('/oauth/callback')
        .query({
          state: 'test-state',
        });

      expect(response.status).toBe(400);
      expect(response.text).toContain('Authorization Failed');
      expect(response.text).toContain('invalid_request');
      expect(response.text).toContain('Missing authorization code');
    });
  });

  describe('Server Error Handling', () => {
    it('should handle server errors gracefully', async () => {
      // Mock template renderer to throw an error
      const originalRender = (oauthService as any).templateRenderer.render;
      (oauthService as any).templateRenderer.render = () => {
        throw new Error('Template rendering failed');
      };

      const response = await request(app)
        .get('/oauth/callback')
        .query({
          code: 'test-code',
        });

      expect(response.status).toBe(500);
      expect(response.text).toContain('Authorization Failed');
      expect(response.text).toContain('server_error');
      expect(response.text).toContain('Internal server error');

      // Restore original method
      (oauthService as any).templateRenderer.render = originalRender;
    });
  });

  describe('Content Security Policy', () => {
    it('should not include inline JavaScript in success page', async () => {
      const response = await request(app)
        .get('/oauth/callback')
        .query({
          code: 'test-code',
        });

      expect(response.status).toBe(200);
      // Check that JavaScript is in external script tags, not inline
      expect(response.text).toContain('<script>');
      expect(response.text).toContain('function copyToClipboard');
    });

    it('should not include inline styles beyond basic CSS', async () => {
      const response = await request(app)
        .get('/oauth/callback')
        .query({
          code: 'test-code',
        });

      expect(response.status).toBe(200);
      // Check that styles are in style tags, not inline
      expect(response.text).toContain('<style>');
      expect(response.text).toContain('font-family: Arial');
    });
  });

  describe('Full OAuth Flow Integration', () => {
    it('should handle complete flow from authorization to callback', async () => {
      // 1. Start authorization and get code
      const authResponse = await request(app)
        .post('/oauth/authorize')
        .send({
          client_id: 'test-client',
          redirect_uri: 'http://localhost:3000/oauth/callback',
          response_type: 'code',
          scope: 'mcp:read',
          state: 'integration-test-state',
          username: 'test-user',
          password: 'test-password',
        });

      expect(authResponse.status).toBe(302);
      
      const location = authResponse.headers.location;
      const url = new URL(location);
      const authorizationCode = url.searchParams.get('code')!;
      const returnedState = url.searchParams.get('state');
      
      expect(authorizationCode).toBeTruthy();
      expect(returnedState).toBe('integration-test-state');

      // 2. Use the callback endpoint with the real code
      const callbackResponse = await request(app)
        .get('/oauth/callback')
        .query({
          code: authorizationCode,
          state: returnedState,
        });

      expect(callbackResponse.status).toBe(200);
      expect(callbackResponse.text).toContain('Authorization Successful');
      expect(callbackResponse.text).toContain(authorizationCode);
      expect(callbackResponse.text).toContain(returnedState);

      // 3. Verify that the cURL example would work by testing token exchange
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
      expect(tokenResponse.body.access_token).toBeTruthy();
    });
  });
});
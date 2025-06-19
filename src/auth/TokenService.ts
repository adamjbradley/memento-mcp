import { randomUUID } from 'node:crypto';
import { OAuthConfig, AuthorizationCode, AccessToken, TokenIntrospectionResponse } from './OAuthConfig.js';
import { logger } from '../utils/logger.js';

interface JWTHeader {
  alg: 'HS256';
  typ: 'JWT';
}

interface JWTPayload {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  jti: string;
  scope: string;
  client_id: string;
  username?: string;
  token_type: 'access_token' | 'refresh_token';
}

export class TokenService {
  private authCodes = new Map<string, AuthorizationCode>();
  private accessTokens = new Map<string, AccessToken>();

  constructor(private config: OAuthConfig) {}

  // Authorization Code Methods
  generateAuthorizationCode(clientId: string, userId: string, redirectUri: string, scopes: string[]): string {
    const code = this.generateRandomString(32);
    const authCode: AuthorizationCode = {
      code,
      clientId,
      userId,
      redirectUri,
      scopes,
      expiresAt: Date.now() + (this.config.authorizationCodeTtl * 1000),
    };

    this.authCodes.set(code, authCode);
    
    // Clean up expired codes periodically
    this.cleanupExpiredCodes();
    
    logger.debug(`Generated authorization code for client ${clientId}, user ${userId}`);
    return code;
  }

  validateAuthorizationCode(code: string, clientId: string, redirectUri: string): AuthorizationCode | null {
    const authCode = this.authCodes.get(code);
    
    if (!authCode) {
      logger.debug(`Authorization code not found: ${code}`);
      return null;
    }

    if (authCode.expiresAt < Date.now()) {
      logger.debug(`Authorization code expired: ${code}`);
      this.authCodes.delete(code);
      return null;
    }

    if (authCode.clientId !== clientId) {
      logger.debug(`Client ID mismatch for authorization code: ${code}`);
      return null;
    }

    if (authCode.redirectUri !== redirectUri) {
      logger.debug(`Redirect URI mismatch for authorization code: ${code}`);
      return null;
    }

    // Code is valid, remove it (single use)
    this.authCodes.delete(code);
    return authCode;
  }

  // Access Token Methods
  generateAccessToken(clientId: string, userId: string, scopes: string[]): { accessToken: string; refreshToken: string } {
    const jti = randomUUID();
    const now = Math.floor(Date.now() / 1000);
    const exp = now + this.config.accessTokenTtl;

    const payload: JWTPayload = {
      iss: this.config.issuer,
      sub: userId,
      aud: clientId,
      exp,
      iat: now,
      jti,
      scope: scopes.join(' '),
      client_id: clientId,
      username: userId,
      token_type: 'access_token',
    };

    const accessToken = this.createJWT(payload);
    const refreshToken = this.generateRefreshToken(clientId, userId, scopes);

    // Store token info
    const tokenInfo: AccessToken = {
      token: accessToken,
      clientId,
      userId,
      scopes,
      expiresAt: exp * 1000,
      refreshToken,
    };

    this.accessTokens.set(accessToken, tokenInfo);
    
    // Clean up expired tokens periodically
    this.cleanupExpiredTokens();

    logger.debug(`Generated access token for client ${clientId}, user ${userId}`);
    return { accessToken, refreshToken };
  }

  generateRefreshToken(clientId: string, userId: string, scopes: string[]): string {
    const jti = randomUUID();
    const now = Math.floor(Date.now() / 1000);
    const exp = now + this.config.refreshTokenTtl;

    const payload: JWTPayload = {
      iss: this.config.issuer,
      sub: userId,
      aud: clientId,
      exp,
      iat: now,
      jti,
      scope: scopes.join(' '),
      client_id: clientId,
      username: userId,
      token_type: 'refresh_token',
    };

    return this.createJWT(payload);
  }

  validateAccessToken(token: string): TokenIntrospectionResponse {
    try {
      const payload = this.verifyJWT(token);
      
      if (!payload) {
        return { active: false };
      }

      if (payload.token_type !== 'access_token') {
        return { active: false };
      }

      const now = Math.floor(Date.now() / 1000);
      if (payload.exp < now) {
        return { active: false };
      }

      return {
        active: true,
        client_id: payload.client_id,
        username: payload.username,
        scope: payload.scope,
        exp: payload.exp,
        iat: payload.iat,
        token_type: 'Bearer',
      };
    } catch (error) {
      logger.debug(`Error validating access token: ${error}`);
      return { active: false };
    }
  }

  // JWT Methods
  private createJWT(payload: JWTPayload): string {
    const header: JWTHeader = { alg: 'HS256', typ: 'JWT' };
    
    const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
    const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));
    
    const signature = this.createSignature(`${encodedHeader}.${encodedPayload}`);
    
    return `${encodedHeader}.${encodedPayload}.${signature}`;
  }

  private verifyJWT(token: string): JWTPayload | null {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        return null;
      }

      const [encodedHeader, encodedPayload, signature] = parts;
      
      // Verify signature
      const expectedSignature = this.createSignature(`${encodedHeader}.${encodedPayload}`);
      if (signature !== expectedSignature) {
        return null;
      }

      // Decode payload
      const payload = JSON.parse(this.base64UrlDecode(encodedPayload)) as JWTPayload;
      
      return payload;
    } catch (error) {
      logger.debug(`JWT verification error: ${error}`);
      return null;
    }
  }

  private createSignature(data: string): string {
    const crypto = require('node:crypto');
    const hmac = crypto.createHmac('sha256', this.config.jwtSecret);
    hmac.update(data);
    return this.base64UrlEncode(hmac.digest());
  }

  private base64UrlEncode(data: string | Buffer): string {
    const base64 = Buffer.from(data).toString('base64');
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  private base64UrlDecode(data: string): string {
    let base64 = data.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }
    return Buffer.from(base64, 'base64').toString();
  }

  private generateRandomString(length: number): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  private cleanupExpiredCodes(): void {
    const now = Date.now();
    for (const [code, authCode] of this.authCodes.entries()) {
      if (authCode.expiresAt < now) {
        this.authCodes.delete(code);
      }
    }
  }

  private cleanupExpiredTokens(): void {
    const now = Date.now();
    for (const [token, tokenInfo] of this.accessTokens.entries()) {
      if (tokenInfo.expiresAt < now) {
        this.accessTokens.delete(token);
      }
    }
  }
}
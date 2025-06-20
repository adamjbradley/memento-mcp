import { Request, Response, NextFunction } from 'express';
import { OAuthService } from './OAuthService.js';
import { logger } from '../utils/logger.js';

export interface AuthenticatedRequest extends Request {
  auth?: {
    userId: string;
    scopes: string[];
  };
}

export class AuthMiddleware {
  constructor(private oauthService: OAuthService, private enabled: boolean = true) {}

  // Middleware to check authentication
  authenticate() {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
      // If OAuth is not enabled, skip authentication
      if (!this.enabled) {
        logger.debug('OAuth authentication disabled, allowing request');
        next();
        return;
      }

      const authHeader = req.headers.authorization;
      
      // Enhanced debug logging
      logger.debug('Authentication attempt:', {
        method: req.method,
        url: req.url,
        hasAuthHeader: !!authHeader,
        authHeaderStart: authHeader ? authHeader.substring(0, 20) + '...' : 'none',
        userAgent: req.headers['user-agent'],
        allHeaders: Object.keys(req.headers),
      });
      
      const tokenValidation = this.oauthService.validateBearerToken(authHeader);

      if (!tokenValidation.valid) {
        logger.debug('Authentication failed - invalid or missing token', {
          hasAuthHeader: !!authHeader,
          tokenValidation: tokenValidation
        });
        res.status(401).json({
          jsonrpc: '2.0',
          error: {
            code: -32001,
            message: 'Unauthorized',
            data: 'Valid Bearer token required',
          },
          id: null,
        });
        return;
      }

      // Add authentication info to request
      req.auth = {
        userId: tokenValidation.userId!,
        scopes: tokenValidation.scopes!,
      };

      logger.debug(`Request authenticated for user: ${req.auth.userId}, scopes: ${req.auth.scopes.join(', ')}`);
      next();
    };
  }

  // Middleware to check specific scopes
  requireScopes(requiredScopes: string[]) {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
      // If OAuth is not enabled, skip scope checking
      if (!this.enabled) {
        next();
        return;
      }

      if (!req.auth) {
        res.status(401).json({
          jsonrpc: '2.0',
          error: {
            code: -32001,
            message: 'Unauthorized',
            data: 'Authentication required',
          },
          id: null,
        });
        return;
      }

      const hasRequiredScope = requiredScopes.some(scope => req.auth!.scopes.includes(scope));
      
      if (!hasRequiredScope) {
        logger.debug(`Insufficient scopes. Required: ${requiredScopes.join(', ')}, User has: ${req.auth.scopes.join(', ')}`);
        res.status(403).json({
          jsonrpc: '2.0',
          error: {
            code: -32002,
            message: 'Forbidden',
            data: `Required scopes: ${requiredScopes.join(', ')}`,
          },
          id: null,
        });
        return;
      }

      next();
    };
  }

  // Helper method to check if a user has admin scope
  isAdmin(req: AuthenticatedRequest): boolean {
    if (!this.enabled) {
      return true; // If auth is disabled, everyone is admin
    }
    return req.auth?.scopes.includes('mcp:admin') || false;
  }

  // Helper method to check if a user can read
  canRead(req: AuthenticatedRequest): boolean {
    if (!this.enabled) {
      return true;
    }
    return req.auth?.scopes.some(scope => ['mcp:read', 'mcp:admin'].includes(scope)) || false;
  }

  // Helper method to check if a user can write
  canWrite(req: AuthenticatedRequest): boolean {
    if (!this.enabled) {
      return true;
    }
    return req.auth?.scopes.some(scope => ['mcp:write', 'mcp:admin'].includes(scope)) || false;
  }

  // Helper method to check if a user can use tools
  canUseTools(req: AuthenticatedRequest): boolean {
    if (!this.enabled) {
      return true;
    }
    return req.auth?.scopes.some(scope => ['mcp:tools', 'mcp:admin'].includes(scope)) || false;
  }
}
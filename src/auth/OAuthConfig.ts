export interface OAuthConfig {
  enabled: boolean;
  clientId: string;
  clientSecret: string;
  jwtSecret: string;
  issuer: string;
  authorizationCodeTtl: number; // seconds
  accessTokenTtl: number; // seconds
  refreshTokenTtl: number; // seconds
  scopes: string[];
  redirectUris: string[];
  // Callback page configuration
  callbackConfig?: OAuthCallbackConfig;
}

export interface OAuthCallbackConfig {
  customCssUrl?: string; // URL to custom CSS file for styling callback pages
  brandingTitle?: string; // Custom title for authorization pages
  brandingLogo?: string; // URL to custom logo
  supportEmail?: string; // Support contact email
  privacyPolicyUrl?: string; // URL to privacy policy
  termsOfServiceUrl?: string; // URL to terms of service
}

export interface OAuthClient {
  id: string;
  secret: string;
  redirectUris: string[];
  scopes: string[];
  name: string;
  // RFC7591 Dynamic Client Registration metadata
  clientName?: string;
  clientUri?: string;
  logoUri?: string;
  contacts?: string[];
  tosUri?: string;
  policyUri?: string;
  jwksUri?: string;
  jwks?: object;
  tokenEndpointAuthMethod?: string;
  grantTypes?: string[];
  responseTypes?: string[];
  softwareId?: string;
  softwareVersion?: string;
  // Registration metadata
  clientIdIssuedAt?: number;
  clientSecretExpiresAt?: number;
  registrationAccessToken?: string;
  registrationClientUri?: string;
}

export interface AuthorizationCode {
  code: string;
  clientId: string;
  userId: string;
  redirectUri: string;
  scopes: string[];
  expiresAt: number;
  codeChallenge?: string;
  codeChallengeMethod?: string;
}

export interface AccessToken {
  token: string;
  clientId: string;
  userId: string;
  scopes: string[];
  expiresAt: number;
  refreshToken?: string;
}

export interface TokenIntrospectionResponse {
  active: boolean;
  client_id?: string;
  username?: string;
  scope?: string;
  exp?: number;
  iat?: number;
  token_type?: string;
}

export interface OAuthServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  introspection_endpoint: string;
  registration_endpoint?: string; // RFC7591
  scopes_supported: string[];
  response_types_supported: string[];
  grant_types_supported: string[];
  token_endpoint_auth_methods_supported: string[];
}

// RFC7591 Dynamic Client Registration interfaces
export interface ClientRegistrationRequest {
  redirect_uris: string[];
  token_endpoint_auth_method?: string;
  grant_types?: string[];
  response_types?: string[];
  client_name?: string;
  client_uri?: string;
  logo_uri?: string;
  scope?: string;
  contacts?: string[];
  tos_uri?: string;
  policy_uri?: string;
  jwks_uri?: string;
  jwks?: object;
  software_id?: string;
  software_version?: string;
}

export interface ClientRegistrationResponse {
  client_id: string;
  client_secret?: string;
  registration_access_token?: string;
  registration_client_uri?: string;
  client_id_issued_at?: number;
  client_secret_expires_at?: number;
  redirect_uris: string[];
  token_endpoint_auth_method?: string;
  grant_types?: string[];
  response_types?: string[];
  client_name?: string;
  client_uri?: string;
  logo_uri?: string;
  scope?: string;
  contacts?: string[];
  tos_uri?: string;
  policy_uri?: string;
  jwks_uri?: string;
  jwks?: object;
  software_id?: string;
  software_version?: string;
}

export interface ClientRegistrationError {
  error: string;
  error_description?: string;
}

export const DEFAULT_OAUTH_CONFIG: Partial<OAuthConfig> = {
  enabled: false,
  issuer: 'http://localhost:3000',
  authorizationCodeTtl: 600, // 10 minutes
  accessTokenTtl: 3600, // 1 hour
  refreshTokenTtl: 7 * 24 * 3600, // 7 days
  scopes: ['mcp:read', 'mcp:write', 'mcp:tools', 'mcp:admin'],
  redirectUris: ['http://localhost:3000/oauth/callback'],
};

export function getOAuthConfig(): OAuthConfig {
  const config: OAuthConfig = {
    enabled: process.env.OAUTH_ENABLED?.toLowerCase() === 'true',
    clientId: process.env.OAUTH_CLIENT_ID || 'memento-mcp-client',
    clientSecret: process.env.OAUTH_CLIENT_SECRET || 'memento-mcp-secret',
    jwtSecret: process.env.OAUTH_JWT_SECRET || 'default-jwt-secret-change-in-production',
    issuer: process.env.OAUTH_ISSUER || DEFAULT_OAUTH_CONFIG.issuer!,
    authorizationCodeTtl: parseInt(process.env.OAUTH_AUTH_CODE_TTL || String(DEFAULT_OAUTH_CONFIG.authorizationCodeTtl), 10),
    accessTokenTtl: parseInt(process.env.OAUTH_ACCESS_TOKEN_TTL || String(DEFAULT_OAUTH_CONFIG.accessTokenTtl), 10),
    refreshTokenTtl: parseInt(process.env.OAUTH_REFRESH_TOKEN_TTL || String(DEFAULT_OAUTH_CONFIG.refreshTokenTtl), 10),
    scopes: process.env.OAUTH_SCOPES?.split(',').map(s => s.trim()) || DEFAULT_OAUTH_CONFIG.scopes!,
    redirectUris: process.env.OAUTH_REDIRECT_URIS?.split(',').map(s => s.trim()) || DEFAULT_OAUTH_CONFIG.redirectUris!,
  };

  // Add callback configuration if any environment variables are set
  const callbackConfig: OAuthCallbackConfig = {};
  let hasCallbackConfig = false;

  if (process.env.OAUTH_CALLBACK_CUSTOM_CSS_URL) {
    callbackConfig.customCssUrl = process.env.OAUTH_CALLBACK_CUSTOM_CSS_URL;
    hasCallbackConfig = true;
  }
  
  if (process.env.OAUTH_CALLBACK_BRANDING_TITLE) {
    callbackConfig.brandingTitle = process.env.OAUTH_CALLBACK_BRANDING_TITLE;
    hasCallbackConfig = true;
  }
  
  if (process.env.OAUTH_CALLBACK_BRANDING_LOGO) {
    callbackConfig.brandingLogo = process.env.OAUTH_CALLBACK_BRANDING_LOGO;
    hasCallbackConfig = true;
  }
  
  if (process.env.OAUTH_CALLBACK_SUPPORT_EMAIL) {
    callbackConfig.supportEmail = process.env.OAUTH_CALLBACK_SUPPORT_EMAIL;
    hasCallbackConfig = true;
  }
  
  if (process.env.OAUTH_CALLBACK_PRIVACY_POLICY_URL) {
    callbackConfig.privacyPolicyUrl = process.env.OAUTH_CALLBACK_PRIVACY_POLICY_URL;
    hasCallbackConfig = true;
  }
  
  if (process.env.OAUTH_CALLBACK_TERMS_OF_SERVICE_URL) {
    callbackConfig.termsOfServiceUrl = process.env.OAUTH_CALLBACK_TERMS_OF_SERVICE_URL;
    hasCallbackConfig = true;
  }

  if (hasCallbackConfig) {
    config.callbackConfig = callbackConfig;
  }

  return config;
}
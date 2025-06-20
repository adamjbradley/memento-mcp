/**
 * Configuration options for Neo4j
 */
export interface Neo4jConfig {
  /**
   * The Neo4j server URI (e.g., 'bolt://localhost:7687' or 'neo4j+s://instance.databases.neo4j.io')
   */
  uri: string;

  /**
   * Username for authentication
   */
  username: string;

  /**
   * Password for authentication
   */
  password: string;

  /**
   * Encryption setting - automatically determined for Aura connections
   */
  encryption: 'ENCRYPTION_ON' | 'ENCRYPTION_OFF';

  /**
   * Neo4j database name
   */
  database: string;

  /**
   * Name of the vector index
   */
  vectorIndexName: string;

  /**
   * Dimensions for vector embeddings
   */
  vectorDimensions: number;

  /**
   * Similarity function to use for vector search
   */
  similarityFunction: 'cosine' | 'euclidean';

  /**
   * Additional driver configuration options for Aura/cloud connections
   */
  driverConfig?: {
    /**
     * Connection pool size
     */
    maxConnectionPoolSize?: number;
    
    /**
     * Connection timeout in milliseconds
     */
    connectionTimeout?: number;
    
    /**
     * Maximum transaction retry time in milliseconds
     */
    maxTransactionRetryTime?: number;
    
    /**
     * Whether to trust system CA certificates (for Aura)
     */
    encrypted?: boolean;
    
    /**
     * Trust strategy for TLS connections
     */
    trust?: 'TRUST_SYSTEM_CA_SIGNED_CERTIFICATES' | 'TRUST_ALL_CERTIFICATES';
  };
}

/**
 * Default Neo4j configuration
 */
export const DEFAULT_NEO4J_CONFIG: Neo4jConfig = {
  uri: 'bolt://localhost:7687',
  username: 'neo4j',
  password: 'memento_password',
  database: 'neo4j',
  vectorIndexName: 'entity_embeddings',
  vectorDimensions: 1536,
  similarityFunction: 'cosine',
  encryption: 'ENCRYPTION_OFF', // Default to no encryption for local connections
  driverConfig: {
    maxConnectionPoolSize: 100,
    connectionTimeout: 30000, // 30 seconds
    maxTransactionRetryTime: 30000, // 30 seconds
  },
};

/**
 * Determines if a URI is for Neo4j Aura based on its format
 * @param uri The Neo4j URI to check
 * @returns true if the URI appears to be for Aura
 */
export function isAuraConnection(uri: string): boolean {
  // Check for neo4j+s:// protocol or .databases.neo4j.io domain
  return uri.startsWith('neo4j+s://') || 
         uri.includes('.databases.neo4j.io') ||
         uri.includes('neo4j.io');
}

/**
 * Creates an optimized Neo4j configuration for Aura connections
 * @param baseConfig The base configuration
 * @returns Configuration optimized for Aura
 */
export function createAuraConfig(baseConfig: Partial<Neo4jConfig>): Neo4jConfig {
  const config: Neo4jConfig = {
    ...DEFAULT_NEO4J_CONFIG,
    ...baseConfig,
  };

  // If this is an Aura connection, apply Aura-specific settings
  if (isAuraConnection(config.uri)) {
    // For neo4j+s:// URLs, encryption is handled by the URL scheme
    // Don't set encryption/trust in driver config to avoid conflicts
    if (config.uri.startsWith('neo4j+s://') || config.uri.startsWith('bolt+s://')) {
      config.encryption = 'ENCRYPTION_ON';
      config.driverConfig = {
        ...config.driverConfig,
        // Aura-optimized settings for cloud latency (no encryption config)
        maxConnectionPoolSize: 50, // Smaller pool for cloud connections
        connectionTimeout: 60000, // 60 seconds for cloud latency
        maxTransactionRetryTime: 60000, // 60 seconds retry time
        // Don't set encrypted/trust when using +s:// URLs
      };
    } else {
      // For regular neo4j:// URLs, set encryption in driver config
      config.encryption = 'ENCRYPTION_ON';
      config.driverConfig = {
        ...config.driverConfig,
        maxConnectionPoolSize: 50,
        connectionTimeout: 60000,
        maxTransactionRetryTime: 60000,
        encrypted: true,
        trust: 'TRUST_SYSTEM_CA_SIGNED_CERTIFICATES',
      };
    }
  }

  return config;
}

/**
 * Validates a Neo4j configuration and provides helpful error messages
 * @param config The configuration to validate
 * @throws Error with helpful message if configuration is invalid
 */
export function validateNeo4jConfig(config: Neo4jConfig): void {
  if (!config.uri) {
    throw new Error('Neo4j URI is required');
  }

  if (!config.username || !config.password) {
    throw new Error('Neo4j username and password are required');
  }

  // Validate URI format
  const validProtocols = ['bolt://', 'neo4j://', 'neo4j+s://', 'bolt+s://'];
  const hasValidProtocol = validProtocols.some(protocol => config.uri.startsWith(protocol));
  
  if (!hasValidProtocol) {
    throw new Error(
      `Invalid Neo4j URI protocol. Expected one of: ${validProtocols.join(', ')}. ` +
      `Got: ${config.uri}`
    );
  }

  // Aura-specific validations
  if (isAuraConnection(config.uri)) {
    if (!config.uri.startsWith('neo4j+s://') && !config.uri.startsWith('bolt+s://')) {
      throw new Error(
        'Neo4j Aura connections require secure protocols (neo4j+s:// or bolt+s://). ' +
        `Got: ${config.uri.split('://')[0]}://`
      );
    }

    if (config.encryption === 'ENCRYPTION_OFF') {
      throw new Error(
        'Neo4j Aura connections require encryption to be enabled. ' +
        'Set encryption to "ENCRYPTION_ON" or use createAuraConfig() for automatic configuration.'
      );
    }
  }
}

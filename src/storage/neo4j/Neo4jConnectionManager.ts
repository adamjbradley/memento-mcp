import neo4j, { type Driver, type Session, type QueryResult } from 'neo4j-driver';
import { 
  DEFAULT_NEO4J_CONFIG, 
  type Neo4jConfig, 
  createAuraConfig, 
  validateNeo4jConfig, 
  isAuraConnection 
} from './Neo4jConfig.js';
import { logger } from '../../utils/logger.js';

/**
 * Options for configuring a Neo4j connection
 * @deprecated Use Neo4jConfig instead
 */
export interface Neo4jConnectionOptions {
  uri?: string;
  username?: string;
  password?: string;
  database?: string;
  encryption?: 'ENCRYPTION_ON' | 'ENCRYPTION_OFF';
}

/**
 * Manages connections to a Neo4j database
 */
export class Neo4jConnectionManager {
  private driver: Driver;
  private readonly config: Neo4jConfig;

  /**
   * Creates a new Neo4j connection manager
   * @param config Connection configuration
   */
  constructor(config?: Partial<Neo4jConfig> | Neo4jConnectionOptions) {
    // Handle deprecated options and create optimized config
    if (config && 'uri' in config) {
      this.config = createAuraConfig({
        ...DEFAULT_NEO4J_CONFIG,
        ...config,
      });
    } else {
      this.config = createAuraConfig({
        ...DEFAULT_NEO4J_CONFIG,
        ...config,
      });
    }

    // Validate the configuration
    try {
      validateNeo4jConfig(this.config);
    } catch (error) {
      logger.error('Invalid Neo4j configuration:', error);
      throw error;
    }

    // Log connection details (without password)
    logger.info('Initializing Neo4j connection', {
      uri: this.config.uri,
      database: this.config.database,
      encryption: this.config.encryption,
      isAura: isAuraConnection(this.config.uri),
      driverConfig: this.config.driverConfig,
    });

    // Create driver configuration
    const driverConfig: any = {
      // Connection pool settings
      maxConnectionPoolSize: this.config.driverConfig?.maxConnectionPoolSize || 100,
      connectionAcquisitionTimeout: this.config.driverConfig?.connectionTimeout || 30000,
      maxTransactionRetryTime: this.config.driverConfig?.maxTransactionRetryTime || 30000,
    };

    // Configure TLS/encryption settings
    // For neo4j+s:// and bolt+s:// URLs, encryption is handled by the URL scheme
    const isSecureUrl = this.config.uri.startsWith('neo4j+s://') || this.config.uri.startsWith('bolt+s://');
    
    if (isSecureUrl) {
      // Don't set encryption config for secure URLs to avoid conflicts
      logger.info('Using secure URL scheme for Neo4j connection', {
        uri: this.config.uri.split('@')[0] + '@***', // Hide credentials in logs
        message: 'Encryption handled by URL scheme'
      });
    } else if (this.config.encryption === 'ENCRYPTION_ON' || isAuraConnection(this.config.uri)) {
      driverConfig.encrypted = true;
      
      // Use system CA certificates for Aura
      if (this.config.driverConfig?.trust) {
        driverConfig.trust = this.config.driverConfig.trust;
      } else {
        driverConfig.trust = 'TRUST_SYSTEM_CA_SIGNED_CERTIFICATES';
      }
      
      logger.info('Configured TLS encryption for Neo4j connection', {
        encrypted: driverConfig.encrypted,
        trust: driverConfig.trust,
      });
    } else {
      driverConfig.encrypted = false;
      logger.info('Using unencrypted Neo4j connection (local/development)');
    }

    try {
      // Create the driver with appropriate configuration
      this.driver = neo4j.driver(
        this.config.uri,
        neo4j.auth.basic(this.config.username, this.config.password),
        driverConfig
      );

      logger.info('Neo4j driver created successfully', {
        uri: this.config.uri,
        encrypted: driverConfig.encrypted,
      });
    } catch (error) {
      logger.error('Failed to create Neo4j driver:', error);
      
      // Provide helpful error messages for common Aura issues
      if (isAuraConnection(this.config.uri)) {
        if (error instanceof Error && error.message.includes('certificate')) {
          throw new Error(
            'TLS certificate error connecting to Neo4j Aura. ' +
            'Ensure your system has up-to-date CA certificates. ' +
            `Original error: ${error.message}`
          );
        }
        if (error instanceof Error && error.message.includes('authentication')) {
          throw new Error(
            'Authentication failed for Neo4j Aura. ' +
            'Please check your username and password. ' +
            'Note: Aura passwords are case-sensitive and may contain special characters. ' +
            `Original error: ${error.message}`
          );
        }
        throw new Error(
          `Failed to connect to Neo4j Aura: ${error instanceof Error ? error.message : String(error)}. ` +
          'Please check your URI, credentials, and network connectivity.'
        );
      }
      
      throw error;
    }
  }

  /**
   * Gets a Neo4j session for executing queries
   * @returns A Neo4j session
   */
  async getSession(): Promise<Session> {
    return this.driver.session({
      database: this.config.database,
    });
  }

  /**
   * Executes a Cypher query
   * @param query The Cypher query
   * @param parameters Query parameters
   * @returns Query result
   */
  async executeQuery(query: string, parameters: Record<string, unknown>): Promise<QueryResult> {
    const session = await this.getSession();
    try {
      return await session.run(query, parameters);
    } catch (error) {
      // Enhanced error handling for Aura connections
      if (isAuraConnection(this.config.uri)) {
        if (error instanceof Error) {
          // Connection timeout errors
          if (error.message.includes('timeout') || error.message.includes('ECONNRESET')) {
            throw new Error(
              'Connection timeout to Neo4j Aura. This may be due to network latency or firewall restrictions. ' +
              'Consider increasing the connection timeout or checking your network connection. ' +
              `Original error: ${error.message}`
            );
          }

          // SSL/TLS errors
          if (error.message.includes('SSL') || error.message.includes('TLS') || error.message.includes('certificate')) {
            throw new Error(
              'TLS/SSL error connecting to Neo4j Aura. ' +
              'This may indicate a certificate validation issue. ' +
              'Ensure your system has up-to-date CA certificates. ' +
              `Original error: ${error.message}`
            );
          }

          // Authentication errors
          if (error.message.includes('authentication') || error.message.includes('Unauthorized')) {
            throw new Error(
              'Authentication failed for Neo4j Aura. ' +
              'Please verify your username and password are correct. ' +
              'Note: Aura uses case-sensitive credentials. ' +
              `Original error: ${error.message}`
            );
          }

          // Database not found errors
          if (error.message.includes('database') && error.message.includes('not found')) {
            throw new Error(
              'Database not found in Neo4j Aura. ' +
              'Please verify the database name is correct. ' +
              'The default database name is usually "neo4j". ' +
              `Original error: ${error.message}`
            );
          }

          // Service unavailable errors
          if (error.message.includes('ServiceUnavailable') || error.message.includes('503')) {
            throw new Error(
              'Neo4j Aura service is temporarily unavailable. ' +
              'This may be due to maintenance or high load. ' +
              'Please try again in a few moments. ' +
              `Original error: ${error.message}`
            );
          }
        }
      }

      // Re-throw original error if no specific handling applied
      throw error;
    } finally {
      await session.close();
    }
  }

  /**
   * Closes the Neo4j driver connection
   */
  async close(): Promise<void> {
    await this.driver.close();
  }
}

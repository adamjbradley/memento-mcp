import { StorageProviderFactory } from '../storage/StorageProviderFactory.js';
import type { VectorStoreFactoryOptions } from '../storage/VectorStoreFactory.js';
import { isAuraConnection } from '../storage/neo4j/Neo4jConfig.js';
import { logger } from '../utils/logger.js';

/**
 * Determines the storage type based on the environment variable
 * @param _envType Storage type from environment variable (unused)
 * @returns 'neo4j' storage type
 */
export function determineStorageType(_envType: string | undefined): 'neo4j' {
  // Always return neo4j regardless of input
  return 'neo4j';
}

/**
 * Configuration for storage providers
 */
export interface StorageConfig {
  type: 'neo4j';
  options: {
    // Neo4j specific options
    neo4jUri?: string;
    neo4jUsername?: string;
    neo4jPassword?: string;
    neo4jDatabase?: string;
    neo4jVectorIndexName?: string;
    neo4jVectorDimensions?: number;
    neo4jSimilarityFunction?: 'cosine' | 'euclidean';
  };
  vectorStoreOptions?: VectorStoreFactoryOptions;
}

/**
 * Creates a storage configuration object
 * @param storageType Storage type (forced to 'neo4j')
 * @returns Storage provider configuration
 */
export function createStorageConfig(storageType: string | undefined): StorageConfig {
  // Neo4j is always the type
  const type = determineStorageType(storageType);

  const neo4jUri = process.env.NEO4J_URI || 'bolt://localhost:7687';
  const isAura = isAuraConnection(neo4jUri);

  logger.info('Configuring Neo4j storage provider', {
    uri: neo4jUri,
    database: process.env.NEO4J_DATABASE || 'neo4j',
    vectorIndex: process.env.NEO4J_VECTOR_INDEX || 'entity_embeddings',
    isAura,
    connectionType: isAura ? 'Aura (Cloud)' : 'Local/Self-hosted',
  });

  // Base configuration with Neo4j properties
  const config: StorageConfig = {
    type,
    options: {
      // Neo4j connection options from environment variables
      neo4jUri,
      neo4jUsername: process.env.NEO4J_USERNAME || 'neo4j',
      neo4jPassword: process.env.NEO4J_PASSWORD || (isAura ? '' : 'memento_password'),
      neo4jDatabase: process.env.NEO4J_DATABASE || 'neo4j',
      neo4jVectorIndexName: process.env.NEO4J_VECTOR_INDEX || 'entity_embeddings',
      neo4jVectorDimensions: process.env.NEO4J_VECTOR_DIMENSIONS
        ? parseInt(process.env.NEO4J_VECTOR_DIMENSIONS, 10)
        : 1536,
      neo4jSimilarityFunction:
        (process.env.NEO4J_SIMILARITY_FUNCTION as 'cosine' | 'euclidean') || 'cosine',
    },
  };

  // Provide helpful warnings for Aura configurations
  if (isAura) {
    if (!process.env.NEO4J_PASSWORD || process.env.NEO4J_PASSWORD === 'memento_password') {
      logger.warn(
        'Neo4j Aura connection detected but no password provided. ' +
        'Please set NEO4J_PASSWORD environment variable with your Aura instance password.'
      );
    }

    if (neo4jUri.startsWith('bolt://') || neo4jUri.startsWith('neo4j://')) {
      logger.warn(
        'Neo4j Aura connection detected but using unencrypted protocol. ' +
        'Consider using neo4j+s:// for secure connections to Aura.'
      );
    }

    logger.info('Neo4j Aura configuration tips:', {
      message: 'Ensure your URI uses neo4j+s:// protocol for secure connections',
      example: 'neo4j+s://your-instance.databases.neo4j.io',
      credentials: 'Username is typically "neo4j", password is from your Aura instance',
    });
  }

  return config;
}

/**
 * Initializes the storage provider based on environment variables
 * @returns Configured storage provider
 */
export function initializeStorageProvider(): ReturnType<StorageProviderFactory['createProvider']> {
  const factory = new StorageProviderFactory();
  const config = createStorageConfig(process.env.MEMORY_STORAGE_TYPE);

  return factory.createProvider(config);
}

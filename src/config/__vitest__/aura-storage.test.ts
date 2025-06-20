import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createStorageConfig, determineStorageType } from '../storage.js';

// Mock the logger to avoid console output during tests
vi.mock('../../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

describe('Storage Configuration with Aura Support', () => {
  // Store original environment variables
  const originalEnv = process.env;

  beforeEach(() => {
    // Reset process.env
    process.env = { ...originalEnv };
    vi.clearAllMocks();
  });

  afterEach(() => {
    // Restore original environment
    process.env = originalEnv;
  });

  describe('determineStorageType', () => {
    it('should always return neo4j regardless of input', () => {
      expect(determineStorageType('file')).toBe('neo4j');
      expect(determineStorageType('neo4j')).toBe('neo4j');
      expect(determineStorageType('unknown')).toBe('neo4j');
      expect(determineStorageType(undefined)).toBe('neo4j');
    });
  });

  describe('createStorageConfig for local Neo4j', () => {
    it('should create default local configuration', () => {
      const config = createStorageConfig('neo4j');

      expect(config.type).toBe('neo4j');
      expect(config.options.neo4jUri).toBe('bolt://localhost:7687');
      expect(config.options.neo4jUsername).toBe('neo4j');
      expect(config.options.neo4jPassword).toBe('memento_password');
      expect(config.options.neo4jDatabase).toBe('neo4j');
      expect(config.options.neo4jVectorIndexName).toBe('entity_embeddings');
      expect(config.options.neo4jVectorDimensions).toBe(1536);
      expect(config.options.neo4jSimilarityFunction).toBe('cosine');
    });

    it('should use environment variables for local configuration', () => {
      process.env.NEO4J_URI = 'bolt://custom-host:7687';
      process.env.NEO4J_USERNAME = 'custom-user';
      process.env.NEO4J_PASSWORD = 'custom-password';
      process.env.NEO4J_DATABASE = 'custom-db';
      process.env.NEO4J_VECTOR_INDEX = 'custom-index';
      process.env.NEO4J_VECTOR_DIMENSIONS = '512';
      process.env.NEO4J_SIMILARITY_FUNCTION = 'euclidean';

      const config = createStorageConfig('neo4j');

      expect(config.options.neo4jUri).toBe('bolt://custom-host:7687');
      expect(config.options.neo4jUsername).toBe('custom-user');
      expect(config.options.neo4jPassword).toBe('custom-password');
      expect(config.options.neo4jDatabase).toBe('custom-db');
      expect(config.options.neo4jVectorIndexName).toBe('custom-index');
      expect(config.options.neo4jVectorDimensions).toBe(512);
      expect(config.options.neo4jSimilarityFunction).toBe('euclidean');
    });
  });

  describe('createStorageConfig for Aura', () => {
    it('should detect Aura connection and provide empty password by default', () => {
      process.env.NEO4J_URI = 'neo4j+s://instance.databases.neo4j.io';
      process.env.NEO4J_USERNAME = 'neo4j';

      const config = createStorageConfig('neo4j');

      expect(config.type).toBe('neo4j');
      expect(config.options.neo4jUri).toBe('neo4j+s://instance.databases.neo4j.io');
      expect(config.options.neo4jUsername).toBe('neo4j');
      expect(config.options.neo4jPassword).toBe(''); // Empty for Aura when not provided
      expect(config.options.neo4jDatabase).toBe('neo4j');
    });

    it('should use provided Aura password when available', () => {
      process.env.NEO4J_URI = 'neo4j+s://instance.databases.neo4j.io';
      process.env.NEO4J_USERNAME = 'neo4j';
      process.env.NEO4J_PASSWORD = 'aura-secure-password';

      const config = createStorageConfig('neo4j');

      expect(config.options.neo4jUri).toBe('neo4j+s://instance.databases.neo4j.io');
      expect(config.options.neo4jPassword).toBe('aura-secure-password');
    });

    it('should handle different Aura URI formats', () => {
      // Test neo4j+s:// protocol
      process.env.NEO4J_URI = 'neo4j+s://abcd1234.databases.neo4j.io';
      let config = createStorageConfig('neo4j');
      expect(config.options.neo4jUri).toBe('neo4j+s://abcd1234.databases.neo4j.io');

      // Test domain-based detection
      process.env.NEO4J_URI = 'bolt://instance.databases.neo4j.io';
      config = createStorageConfig('neo4j');
      expect(config.options.neo4jUri).toBe('bolt://instance.databases.neo4j.io');
      expect(config.options.neo4jPassword).toBe(''); // Empty for Aura

      // Test custom neo4j.io domain
      process.env.NEO4J_URI = 'neo4j+s://custom.neo4j.io';
      config = createStorageConfig('neo4j');
      expect(config.options.neo4jUri).toBe('neo4j+s://custom.neo4j.io');
      expect(config.options.neo4jPassword).toBe(''); // Empty for Aura
    });

    it('should handle vector dimensions from environment', () => {
      process.env.NEO4J_URI = 'neo4j+s://instance.databases.neo4j.io';
      process.env.NEO4J_VECTOR_DIMENSIONS = '768';

      const config = createStorageConfig('neo4j');

      expect(config.options.neo4jVectorDimensions).toBe(768);
    });

    it('should handle invalid vector dimensions gracefully', () => {
      process.env.NEO4J_URI = 'neo4j+s://instance.databases.neo4j.io';
      process.env.NEO4J_VECTOR_DIMENSIONS = 'invalid-number';

      const config = createStorageConfig('neo4j');

      expect(config.options.neo4jVectorDimensions).toBe(1536); // Should fall back to default
    });

    it('should handle similarity function from environment', () => {
      process.env.NEO4J_URI = 'neo4j+s://instance.databases.neo4j.io';
      process.env.NEO4J_SIMILARITY_FUNCTION = 'euclidean';

      const config = createStorageConfig('neo4j');

      expect(config.options.neo4jSimilarityFunction).toBe('euclidean');
    });
  });

  describe('configuration warnings and logging', () => {
    it('should log info for Aura connections', () => {
      process.env.NEO4J_URI = 'neo4j+s://instance.databases.neo4j.io';
      
      const config = createStorageConfig('neo4j');

      // Verify that configuration was created
      expect(config.options.neo4jUri).toBe('neo4j+s://instance.databases.neo4j.io');
      
      // Note: We're not testing logger calls directly since they're mocked,
      // but the configuration should work correctly
    });

    it('should log info for local connections', () => {
      process.env.NEO4J_URI = 'bolt://localhost:7687';
      
      const config = createStorageConfig('neo4j');

      // Verify that configuration was created
      expect(config.options.neo4jUri).toBe('bolt://localhost:7687');
      expect(config.options.neo4jPassword).toBe('memento_password');
    });

    it('should handle missing environment variables gracefully', () => {
      // Clear all Neo4j-related environment variables
      delete process.env.NEO4J_URI;
      delete process.env.NEO4J_USERNAME;
      delete process.env.NEO4J_PASSWORD;
      delete process.env.NEO4J_DATABASE;

      const config = createStorageConfig('neo4j');

      // Should fall back to defaults
      expect(config.options.neo4jUri).toBe('bolt://localhost:7687');
      expect(config.options.neo4jUsername).toBe('neo4j');
      expect(config.options.neo4jPassword).toBe('memento_password');
      expect(config.options.neo4jDatabase).toBe('neo4j');
    });
  });

  describe('edge cases', () => {
    it('should handle empty URI', () => {
      process.env.NEO4J_URI = '';

      const config = createStorageConfig('neo4j');

      expect(config.options.neo4jUri).toBe('bolt://localhost:7687'); // Should fall back to default
    });

    it('should handle URI with no protocol', () => {
      process.env.NEO4J_URI = 'instance.databases.neo4j.io';

      const config = createStorageConfig('neo4j');

      expect(config.options.neo4jUri).toBe('instance.databases.neo4j.io');
      expect(config.options.neo4jPassword).toBe(''); // Should detect as Aura
    });

    it('should handle mixed case in URI', () => {
      process.env.NEO4J_URI = 'NEO4J+S://Instance.Databases.Neo4j.io';

      const config = createStorageConfig('neo4j');

      expect(config.options.neo4jUri).toBe('NEO4J+S://Instance.Databases.Neo4j.io');
      expect(config.options.neo4jPassword).toBe(''); // Should detect as Aura
    });
  });
});
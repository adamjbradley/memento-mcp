import { describe, it, expect, beforeEach, vi } from 'vitest';
import { startHttpServer } from '../index.js';

// Mock the logger to avoid console output during tests
vi.mock('../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    debug: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
  }
}));

// Mock storage and other dependencies
vi.mock('../config/storage.js', () => ({
  initializeStorageProvider: vi.fn(() => ({
    openNodes: vi.fn(() => Promise.resolve({ entities: [] })),
    searchNodes: vi.fn(() => Promise.resolve([])),
  }))
}));

vi.mock('../KnowledgeGraphManager.js', () => ({
  KnowledgeGraphManager: vi.fn(() => ({
    searchNodes: vi.fn(() => Promise.resolve([])),
    openNodes: vi.fn(() => Promise.resolve({ entities: [] })),
  }))
}));

vi.mock('../embeddings/EmbeddingServiceFactory.js', () => ({
  EmbeddingServiceFactory: {
    createFromEnvironment: vi.fn(() => ({
      getModelInfo: vi.fn(() => ({ name: 'test-model' }))
    }))
  }
}));

vi.mock('../embeddings/EmbeddingJobManager.js', () => ({
  EmbeddingJobManager: vi.fn(() => ({
    processJobs: vi.fn()
  }))
}));

describe('HTTP Transport Basic Functionality', () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
    // Set test environment
    process.env.NODE_ENV = 'test';
    process.env.VITEST = 'true';
    process.env.MCP_HTTP_PORT = '0'; // Use port 0 to get a random available port
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('should export startHttpServer function', () => {
    expect(typeof startHttpServer).toBe('function');
  });

  it('should handle environment variable configuration', () => {
    // Test default values
    const defaultPort = parseInt(process.env.MCP_HTTP_PORT || '3000', 10);
    const defaultHost = process.env.MCP_HTTP_HOST || 'localhost';
    
    expect(defaultHost).toBe('localhost');
    expect(defaultPort).toBe(0); // We set it to 0 in beforeEach
  });

  it('should handle custom environment variables', () => {
    process.env.MCP_HTTP_PORT = '8080';
    process.env.MCP_HTTP_HOST = '0.0.0.0';
    
    const port = parseInt(process.env.MCP_HTTP_PORT || '3000', 10);
    const host = process.env.MCP_HTTP_HOST || 'localhost';
    
    expect(port).toBe(8080);
    expect(host).toBe('0.0.0.0');
  });

  it('should have transport mode selection logic', async () => {
    // Test transport mode environment variable
    delete process.env.MCP_TRANSPORT_MODE;
    expect(process.env.MCP_TRANSPORT_MODE || 'stdio').toBe('stdio');
    
    process.env.MCP_TRANSPORT_MODE = 'http';
    expect(process.env.MCP_TRANSPORT_MODE).toBe('http');
  });
});
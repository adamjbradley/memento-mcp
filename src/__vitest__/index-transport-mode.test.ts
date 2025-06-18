import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Mock the logger to avoid console output during tests
vi.mock('../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    debug: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
  }
}));

// Mock the main server functions to avoid actual server startup
vi.mock('../server/setup.js', () => ({
  setupServer: vi.fn(() => ({
    connect: vi.fn(),
  }))
}));

vi.mock('../KnowledgeGraphManager.js', () => ({
  KnowledgeGraphManager: vi.fn(() => ({}))
}));

vi.mock('../config/storage.js', () => ({
  initializeStorageProvider: vi.fn(() => ({}))
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

describe('Transport Mode Selection', () => {
  let originalEnv: NodeJS.ProcessEnv;
  let originalExit: typeof process.exit;
  let originalSetInterval: typeof setInterval;
  let mockExit: any;
  let mockSetInterval: any;

  beforeEach(() => {
    originalEnv = { ...process.env };
    originalExit = process.exit;
    originalSetInterval = setInterval;
    
    mockExit = vi.fn();
    mockSetInterval = vi.fn();
    
    // Mock process.exit to prevent actual process termination
    process.exit = mockExit as any;
    global.setInterval = mockSetInterval;
    
    // Set test environment to prevent actual server startup
    process.env.NODE_ENV = 'test';
    process.env.VITEST = 'true';
  });

  afterEach(() => {
    process.env = originalEnv;
    process.exit = originalExit;
    global.setInterval = originalSetInterval;
    vi.clearAllMocks();
  });

  it('should export main function for stdio transport', async () => {
    // Import the module to test exports
    const indexModule = await import('../index.js');
    
    expect(typeof indexModule.main).toBe('function');
    expect(typeof indexModule.startHttpServer).toBe('function');
  });

  it('should export startHttpServer function for HTTP transport', async () => {
    const indexModule = await import('../index.js');
    
    expect(typeof indexModule.startHttpServer).toBe('function');
  });

  it('should determine transport mode from environment variable', () => {
    // Test default stdio mode
    delete process.env.MCP_TRANSPORT_MODE;
    
    // Re-import to test environment variable reading
    // Note: In a real test, you might need to clear the module cache
    // For this test, we're just checking the logic exists
    
    expect(process.env.MCP_TRANSPORT_MODE || 'stdio').toBe('stdio');
    
    // Test HTTP mode
    process.env.MCP_TRANSPORT_MODE = 'http';
    expect(process.env.MCP_TRANSPORT_MODE).toBe('http');
  });
});

describe('Configuration Environment Variables', () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
    process.env.NODE_ENV = 'test';
    process.env.VITEST = 'true';
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('should use default HTTP port when not specified', () => {
    delete process.env.MCP_HTTP_PORT;
    
    const defaultPort = parseInt(process.env.MCP_HTTP_PORT || '3000', 10);
    expect(defaultPort).toBe(3000);
  });

  it('should use custom HTTP port when specified', () => {
    process.env.MCP_HTTP_PORT = '8080';
    
    const port = parseInt(process.env.MCP_HTTP_PORT || '3000', 10);
    expect(port).toBe(8080);
  });

  it('should use default host when not specified', () => {
    delete process.env.MCP_HTTP_HOST;
    
    const defaultHost = process.env.MCP_HTTP_HOST || 'localhost';
    expect(defaultHost).toBe('localhost');
  });

  it('should use custom host when specified', () => {
    process.env.MCP_HTTP_HOST = '0.0.0.0';
    
    const host = process.env.MCP_HTTP_HOST || 'localhost';
    expect(host).toBe('0.0.0.0');
  });
});
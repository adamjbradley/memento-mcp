import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { 
  Neo4jConnectionManager, 
  Neo4jConnectionOptions 
} from '../../neo4j/Neo4jConnectionManager.js';
import { 
  isAuraConnection, 
  createAuraConfig, 
  validateNeo4jConfig,
  DEFAULT_NEO4J_CONFIG,
  type Neo4jConfig 
} from '../../neo4j/Neo4jConfig.js';
import neo4j from 'neo4j-driver';

// Mock the logger to avoid console output during tests
vi.mock('../../../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

// Mock the neo4j driver
vi.mock('neo4j-driver', () => {
  const mockRun = vi.fn().mockResolvedValue({ records: [] });
  const mockClose = vi.fn();

  const mockSession = {
    run: mockRun,
    close: mockClose,
  };

  const mockSessionFn = vi.fn().mockReturnValue(mockSession);
  const mockDriverClose = vi.fn();

  const mockDriver = {
    session: mockSessionFn,
    close: mockDriverClose,
  };

  const mockDriverFn = vi.fn().mockReturnValue(mockDriver);

  return {
    default: {
      auth: {
        basic: vi.fn().mockReturnValue('mock-auth'),
      },
      driver: mockDriverFn,
    },
  };
});

describe('Neo4j Aura Configuration', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('isAuraConnection', () => {
    it('should detect neo4j+s:// protocol as Aura', () => {
      expect(isAuraConnection('neo4j+s://instance.databases.neo4j.io')).toBe(true);
    });

    it('should detect .databases.neo4j.io domain as Aura', () => {
      expect(isAuraConnection('bolt://instance.databases.neo4j.io')).toBe(true);
      expect(isAuraConnection('neo4j://instance.databases.neo4j.io')).toBe(true);
    });

    it('should detect neo4j.io domain as Aura', () => {
      expect(isAuraConnection('neo4j+s://custom.neo4j.io')).toBe(true);
    });

    it('should not detect local connections as Aura', () => {
      expect(isAuraConnection('bolt://localhost:7687')).toBe(false);
      expect(isAuraConnection('neo4j://localhost:7687')).toBe(false);
      expect(isAuraConnection('bolt://192.168.1.100:7687')).toBe(false);
    });

    it('should not detect other domains as Aura', () => {
      expect(isAuraConnection('bolt://my-neo4j-server.com:7687')).toBe(false);
      expect(isAuraConnection('neo4j://company.internal:7687')).toBe(false);
    });
  });

  describe('createAuraConfig', () => {
    it('should create default config for local connections', () => {
      const config = createAuraConfig({
        uri: 'bolt://localhost:7687',
        username: 'neo4j',
        password: 'password',
      });

      expect(config.encryption).toBe('ENCRYPTION_OFF');
      expect(config.driverConfig?.encrypted).toBeUndefined();
      expect(config.driverConfig?.trust).toBeUndefined();
    });

    it('should configure TLS for Aura connections', () => {
      const config = createAuraConfig({
        uri: 'neo4j+s://instance.databases.neo4j.io',
        username: 'neo4j',
        password: 'aura-password',
      });

      expect(config.encryption).toBe('ENCRYPTION_ON');
      expect(config.driverConfig?.encrypted).toBe(true);
      expect(config.driverConfig?.trust).toBe('TRUST_SYSTEM_CA_SIGNED_CERTIFICATES');
      expect(config.driverConfig?.maxConnectionPoolSize).toBe(50);
      expect(config.driverConfig?.connectionTimeout).toBe(60000);
      expect(config.driverConfig?.maxTransactionRetryTime).toBe(60000);
    });

    it('should preserve custom driverConfig settings', () => {
      const config = createAuraConfig({
        uri: 'neo4j+s://instance.databases.neo4j.io',
        username: 'neo4j',
        password: 'aura-password',
        driverConfig: {
          maxConnectionPoolSize: 25,
          connectionTimeout: 45000,
        },
      });

      expect(config.driverConfig?.maxConnectionPoolSize).toBe(25);
      expect(config.driverConfig?.connectionTimeout).toBe(45000);
      expect(config.driverConfig?.encrypted).toBe(true);
      expect(config.driverConfig?.trust).toBe('TRUST_SYSTEM_CA_SIGNED_CERTIFICATES');
    });
  });

  describe('validateNeo4jConfig', () => {
    it('should validate local configuration', () => {
      const config: Neo4jConfig = {
        ...DEFAULT_NEO4J_CONFIG,
        uri: 'bolt://localhost:7687',
        username: 'neo4j',
        password: 'password',
      };

      expect(() => validateNeo4jConfig(config)).not.toThrow();
    });

    it('should validate Aura configuration with secure protocol', () => {
      const config: Neo4jConfig = {
        ...DEFAULT_NEO4J_CONFIG,
        uri: 'neo4j+s://instance.databases.neo4j.io',
        username: 'neo4j',
        password: 'aura-password',
        encryption: 'ENCRYPTION_ON',
      };

      expect(() => validateNeo4jConfig(config)).not.toThrow();
    });

    it('should reject missing URI', () => {
      const config: Neo4jConfig = {
        ...DEFAULT_NEO4J_CONFIG,
        uri: '',
        username: 'neo4j',
        password: 'password',
      };

      expect(() => validateNeo4jConfig(config)).toThrow('Neo4j URI is required');
    });

    it('should reject missing credentials', () => {
      const config1: Neo4jConfig = {
        ...DEFAULT_NEO4J_CONFIG,
        uri: 'bolt://localhost:7687',
        username: '',
        password: 'password',
      };

      const config2: Neo4jConfig = {
        ...DEFAULT_NEO4J_CONFIG,
        uri: 'bolt://localhost:7687',
        username: 'neo4j',
        password: '',
      };

      expect(() => validateNeo4jConfig(config1)).toThrow('Neo4j username and password are required');
      expect(() => validateNeo4jConfig(config2)).toThrow('Neo4j username and password are required');
    });

    it('should reject invalid protocols', () => {
      const config: Neo4jConfig = {
        ...DEFAULT_NEO4J_CONFIG,
        uri: 'http://localhost:7687',
        username: 'neo4j',
        password: 'password',
      };

      expect(() => validateNeo4jConfig(config)).toThrow('Invalid Neo4j URI protocol');
    });

    it('should reject Aura connections with insecure protocols', () => {
      const config: Neo4jConfig = {
        ...DEFAULT_NEO4J_CONFIG,
        uri: 'bolt://instance.databases.neo4j.io',
        username: 'neo4j',
        password: 'aura-password',
        encryption: 'ENCRYPTION_ON',
      };

      expect(() => validateNeo4jConfig(config)).toThrow('Neo4j Aura connections require secure protocols');
    });

    it('should reject Aura connections without encryption', () => {
      const config: Neo4jConfig = {
        ...DEFAULT_NEO4J_CONFIG,
        uri: 'neo4j+s://instance.databases.neo4j.io',
        username: 'neo4j',
        password: 'aura-password',
        encryption: 'ENCRYPTION_OFF',
      };

      expect(() => validateNeo4jConfig(config)).toThrow('Neo4j Aura connections require encryption to be enabled');
    });
  });
});

describe('Neo4jConnectionManager with Aura', () => {
  let connectionManager: Neo4jConnectionManager;

  afterEach(async () => {
    if (connectionManager) {
      await connectionManager.close();
    }
  });

  it('should create Aura connection with proper TLS configuration', () => {
    const auraConfig = {
      uri: 'neo4j+s://instance.databases.neo4j.io',
      username: 'neo4j',
      password: 'aura-password',
      database: 'neo4j',
    };

    connectionManager = new Neo4jConnectionManager(auraConfig);

    // Verify the driver was called with TLS configuration
    expect(neo4j.driver).toHaveBeenCalledWith(
      'neo4j+s://instance.databases.neo4j.io',
      'mock-auth',
      expect.objectContaining({
        encrypted: true,
        trust: 'TRUST_SYSTEM_CA_SIGNED_CERTIFICATES',
        maxConnectionPoolSize: 50,
        connectionAcquisitionTimeout: 60000,
        maxTransactionRetryTime: 60000,
      })
    );
  });

  it('should create local connection without TLS', () => {
    const localConfig = {
      uri: 'bolt://localhost:7687',
      username: 'neo4j',
      password: 'password',
      database: 'neo4j',
    };

    connectionManager = new Neo4jConnectionManager(localConfig);

    // Verify the driver was called without TLS configuration
    expect(neo4j.driver).toHaveBeenCalledWith(
      'bolt://localhost:7687',
      'mock-auth',
      expect.objectContaining({
        encrypted: false,
        maxConnectionPoolSize: 100,
        connectionAcquisitionTimeout: 30000,
        maxTransactionRetryTime: 30000,
      })
    );
  });

  it('should handle Aura connection errors gracefully', async () => {
    // Mock a TLS error
    const mockDriverInstance = (neo4j.driver as unknown as ReturnType<typeof vi.fn>)();
    const sessionInstance = mockDriverInstance.session();
    const mockRun = sessionInstance.run as ReturnType<typeof vi.fn>;
    
    mockRun.mockRejectedValueOnce(new Error('TLS certificate validation failed'));

    connectionManager = new Neo4jConnectionManager({
      uri: 'neo4j+s://instance.databases.neo4j.io',
      username: 'neo4j',
      password: 'aura-password',
    });

    await expect(connectionManager.executeQuery('MATCH (n) RETURN n', {}))
      .rejects.toThrow(/TLS\/SSL error connecting to Neo4j Aura/);
  });

  it('should handle Aura authentication errors', async () => {
    const mockDriverInstance = (neo4j.driver as unknown as ReturnType<typeof vi.fn>)();
    const sessionInstance = mockDriverInstance.session();
    const mockRun = sessionInstance.run as ReturnType<typeof vi.fn>;
    
    mockRun.mockRejectedValueOnce(new Error('authentication failed'));

    connectionManager = new Neo4jConnectionManager({
      uri: 'neo4j+s://instance.databases.neo4j.io',
      username: 'neo4j',
      password: 'wrong-password',
    });

    await expect(connectionManager.executeQuery('MATCH (n) RETURN n', {}))
      .rejects.toThrow(/Authentication failed for Neo4j Aura/);
  });

  it('should handle Aura timeout errors', async () => {
    const mockDriverInstance = (neo4j.driver as unknown as ReturnType<typeof vi.fn>)();
    const sessionInstance = mockDriverInstance.session();
    const mockRun = sessionInstance.run as ReturnType<typeof vi.fn>;
    
    mockRun.mockRejectedValueOnce(new Error('Connection timeout'));

    connectionManager = new Neo4jConnectionManager({
      uri: 'neo4j+s://instance.databases.neo4j.io',
      username: 'neo4j',
      password: 'aura-password',
    });

    await expect(connectionManager.executeQuery('MATCH (n) RETURN n', {}))
      .rejects.toThrow(/Connection timeout to Neo4j Aura/);
  });

  it('should handle service unavailable errors', async () => {
    const mockDriverInstance = (neo4j.driver as unknown as ReturnType<typeof vi.fn>)();
    const sessionInstance = mockDriverInstance.session();
    const mockRun = sessionInstance.run as ReturnType<typeof vi.fn>;
    
    mockRun.mockRejectedValueOnce(new Error('ServiceUnavailable'));

    connectionManager = new Neo4jConnectionManager({
      uri: 'neo4j+s://instance.databases.neo4j.io',
      username: 'neo4j',
      password: 'aura-password',
    });

    await expect(connectionManager.executeQuery('MATCH (n) RETURN n', {}))
      .rejects.toThrow(/Neo4j Aura service is temporarily unavailable/);
  });
});
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import express from 'express';
import { randomUUID } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { setupServer } from '../server/setup.js';
import { KnowledgeGraphManager } from '../KnowledgeGraphManager.js';
import { FileStorageProvider } from '../storage/FileStorageProvider.js';

// Mock the logger to avoid console output during tests
vi.mock('../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    debug: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
  }
}));

describe('HTTP Transport', () => {
  let app: express.Application;
  let knowledgeGraphManager: KnowledgeGraphManager;
  let server: any;
  let transports: { [key: string]: StreamableHTTPServerTransport };

  beforeEach(() => {
    // Create a test KnowledgeGraphManager with file storage
    const storageProvider = new FileStorageProvider();
    knowledgeGraphManager = new KnowledgeGraphManager({ storageProvider });
    server = setupServer(knowledgeGraphManager);

    // Set up Express app similar to the main implementation
    app = express();
    app.use(express.json());
    transports = {};

    // Handle POST requests for MCP communication
    app.post('/mcp', async (req, res) => {
      try {
        const sessionId = req.headers['mcp-session-id'] as string;
        let transport: StreamableHTTPServerTransport;

        if (sessionId && transports[sessionId]) {
          transport = transports[sessionId];
        } else if (!sessionId && isInitializeRequest(req.body)) {
          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            onsessioninitialized: (sessionId: string) => {
              transports[sessionId] = transport;
            }
          });

          transport.onclose = () => {
            const sid = transport.sessionId;
            if (sid && transports[sid]) {
              delete transports[sid];
            }
          };

          await server.connect(transport);
          await transport.handleRequest(req, res, req.body);
          return;
        } else {
          res.status(400).json({
            jsonrpc: '2.0',
            error: {
              code: -32000,
              message: 'Bad Request: No valid session ID provided',
            },
            id: null,
          });
          return;
        }

        await transport.handleRequest(req, res, req.body);
      } catch (error) {
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: {
              code: -32603,
              message: 'Internal server error',
            },
            id: null,
          });
        }
      }
    });

    // Handle GET requests for SSE streams
    app.get('/mcp', async (req, res) => {
      const sessionId = req.headers['mcp-session-id'] as string;
      if (!sessionId || !transports[sessionId]) {
        res.status(400).send('Invalid or missing session ID');
        return;
      }

      const transport = transports[sessionId];
      await transport.handleRequest(req, res);
    });

    // Handle DELETE requests for session termination
    app.delete('/mcp', async (req, res) => {
      const sessionId = req.headers['mcp-session-id'] as string;
      if (!sessionId || !transports[sessionId]) {
        res.status(400).send('Invalid or missing session ID');
        return;
      }

      try {
        const transport = transports[sessionId];
        await transport.handleRequest(req, res);
      } catch (error) {
        if (!res.headersSent) {
          res.status(500).send('Error processing session termination');
        }
      }
    });

    // Health check endpoint
    app.get('/health', (req, res) => {
      res.json({ status: 'ok', timestamp: new Date().toISOString() });
    });
  });

  afterEach(async () => {
    // Clean up transports
    for (const sessionId in transports) {
      try {
        await transports[sessionId].close();
        delete transports[sessionId];
      } catch (error) {
        // Ignore cleanup errors in tests
      }
    }
  });

  describe('Health Check', () => {
    it('should return health status', async () => {
      const response = await request(app)
        .get('/health')
        .expect(200);

      expect(response.body).toHaveProperty('status', 'ok');
      expect(response.body).toHaveProperty('timestamp');
      expect(new Date(response.body.timestamp)).toBeInstanceOf(Date);
    });
  });

  describe('MCP Initialization', () => {
    it('should handle initialization request without session ID', async () => {
      const initRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {
            tools: {},
          },
          clientInfo: {
            name: 'test-client',
            version: '1.0.0',
          },
        },
      };

      const response = await request(app)
        .post('/mcp')
        .set('Accept', 'application/json')
        .set('Content-Type', 'application/json')
        .send(initRequest)
        .expect(200);

      expect(response.headers).toHaveProperty('mcp-session-id');
      expect(response.headers['mcp-session-id']).toBeDefined();
      expect(response.body).toHaveProperty('jsonrpc', '2.0');
      expect(response.body).toHaveProperty('id', 1);
      expect(response.body).toHaveProperty('result');
      expect(response.body.result).toHaveProperty('capabilities');
      expect(response.body.result).toHaveProperty('serverInfo');
    });

    it('should reject non-initialization requests without session ID', async () => {
      const toolsRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/list',
        params: {},
      };

      const response = await request(app)
        .post('/mcp')
        .set('Accept', 'application/json')
        .set('Content-Type', 'application/json')
        .send(toolsRequest)
        .expect(400);

      expect(response.body).toHaveProperty('jsonrpc', '2.0');
      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toHaveProperty('code', -32000);
    });
  });

  describe('Session Management', () => {
    let sessionId: string;

    beforeEach(async () => {
      // Initialize a session first
      const initRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {
            tools: {},
          },
          clientInfo: {
            name: 'test-client',
            version: '1.0.0',
          },
        },
      };

      const response = await request(app)
        .post('/mcp')
        .set('Accept', 'application/json')
        .set('Content-Type', 'application/json')
        .send(initRequest)
        .expect(200);

      sessionId = response.headers['mcp-session-id'];
      expect(sessionId).toBeDefined();
    });

    it('should handle requests with valid session ID', async () => {
      const toolsRequest = {
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/list',
        params: {},
      };

      const response = await request(app)
        .post('/mcp')
        .set('mcp-session-id', sessionId)
        .set('Accept', 'application/json')
        .set('Content-Type', 'application/json')
        .send(toolsRequest)
        .expect(200);

      expect(response.body).toHaveProperty('jsonrpc', '2.0');
      expect(response.body).toHaveProperty('id', 2);
      expect(response.body).toHaveProperty('result');
      expect(response.body.result).toHaveProperty('tools');
      expect(Array.isArray(response.body.result.tools)).toBe(true);
    });

    it('should reject requests with invalid session ID', async () => {
      const toolsRequest = {
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/list',
        params: {},
      };

      const response = await request(app)
        .post('/mcp')
        .set('mcp-session-id', 'invalid-session-id')
        .set('Accept', 'application/json')
        .set('Content-Type', 'application/json')
        .send(toolsRequest)
        .expect(400);

      expect(response.body).toHaveProperty('jsonrpc', '2.0');
      expect(response.body).toHaveProperty('error');
    });

    it('should handle SSE stream requests with valid session ID', async () => {
      const response = await request(app)
        .get('/mcp')
        .set('mcp-session-id', sessionId)
        .expect(200);

      expect(response.headers['content-type']).toMatch(/text\/event-stream/);
      expect(response.headers['cache-control']).toBe('no-cache');
      expect(response.headers['connection']).toBe('keep-alive');
    });

    it('should reject SSE stream requests with invalid session ID', async () => {
      await request(app)
        .get('/mcp')
        .set('mcp-session-id', 'invalid-session-id')
        .expect(400);
    });

    it('should handle session termination', async () => {
      await request(app)
        .delete('/mcp')
        .set('mcp-session-id', sessionId)
        .expect(200);

      // After termination, the session should no longer be valid
      const toolsRequest = {
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/list',
        params: {},
      };

      await request(app)
        .post('/mcp')
        .set('mcp-session-id', sessionId)
        .set('Accept', 'application/json')
        .set('Content-Type', 'application/json')
        .send(toolsRequest)
        .expect(400);
    });
  });

  describe('MCP Tool Functionality', () => {
    let sessionId: string;

    beforeEach(async () => {
      // Initialize a session
      const initRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {
            tools: {},
          },
          clientInfo: {
            name: 'test-client',
            version: '1.0.0',
          },
        },
      };

      const response = await request(app)
        .post('/mcp')
        .set('Accept', 'application/json')
        .set('Content-Type', 'application/json')
        .send(initRequest)
        .expect(200);

      sessionId = response.headers['mcp-session-id'];
      expect(sessionId).toBeDefined();
    });

    it('should list available tools', async () => {
      const toolsRequest = {
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/list',
        params: {},
      };

      const response = await request(app)
        .post('/mcp')
        .set('mcp-session-id', sessionId)
        .set('Accept', 'application/json')
        .set('Content-Type', 'application/json')
        .send(toolsRequest)
        .expect(200);

      expect(response.body.result.tools).toBeDefined();
      expect(Array.isArray(response.body.result.tools)).toBe(true);
      
      // Check for some expected tools
      const toolNames = response.body.result.tools.map((tool: any) => tool.name);
      expect(toolNames).toContain('create_entities');
      expect(toolNames).toContain('read_graph');
      expect(toolNames).toContain('search_nodes');
    });

    it('should create entities via HTTP transport', async () => {
      const createEntitiesRequest = {
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: {
          name: 'create_entities',
          arguments: {
            entities: [
              {
                name: 'test_entity',
                entityType: 'person',
                observations: ['This is a test entity for HTTP transport']
              }
            ]
          }
        }
      };

      const response = await request(app)
        .post('/mcp')
        .set('mcp-session-id', sessionId)
        .set('Accept', 'application/json')
        .set('Content-Type', 'application/json')
        .send(createEntitiesRequest)
        .expect(200);

      expect(response.body).toHaveProperty('jsonrpc', '2.0');
      expect(response.body).toHaveProperty('id', 3);
      expect(response.body).toHaveProperty('result');
      expect(response.body.result.content[0].text).toContain('Created 1 entities');
    });

    it('should read graph via HTTP transport', async () => {
      // First create an entity
      const createEntitiesRequest = {
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: {
          name: 'create_entities',
          arguments: {
            entities: [
              {
                name: 'http_test_entity',
                entityType: 'test',
                observations: ['Entity created via HTTP transport']
              }
            ]
          }
        }
      };

      await request(app)
        .post('/mcp')
        .set('mcp-session-id', sessionId)
        .set('Accept', 'application/json')
        .set('Content-Type', 'application/json')
        .send(createEntitiesRequest)
        .expect(200);

      // Then read the graph
      const readGraphRequest = {
        jsonrpc: '2.0',
        id: 4,
        method: 'tools/call',
        params: {
          name: 'read_graph',
          arguments: {}
        }
      };

      const response = await request(app)
        .post('/mcp')
        .set('mcp-session-id', sessionId)
        .set('Accept', 'application/json')
        .set('Content-Type', 'application/json')
        .send(readGraphRequest)
        .expect(200);

      expect(response.body.result.content[0].text).toContain('http_test_entity');
    });
  });

  describe('Error Handling', () => {
    it('should handle malformed JSON requests', async () => {
      const response = await request(app)
        .post('/mcp')
        .set('Accept', 'application/json')
        .set('Content-Type', 'application/json')
        .send('invalid json')
        .expect(400);

      // Express should handle the malformed JSON and return 400
    });

    it('should handle server errors gracefully', async () => {
      // Mock a server error by sending an invalid method
      const invalidRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'nonexistent/method',
        params: {},
      };

      const response = await request(app)
        .post('/mcp')
        .set('Accept', 'application/json')
        .set('Content-Type', 'application/json')
        .send(invalidRequest)
        .expect(400); // Should be handled as bad request due to no session ID
    });
  });
});
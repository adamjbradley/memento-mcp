#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { InMemoryEventStore } from '@modelcontextprotocol/sdk/examples/shared/inMemoryEventStore.js';
import express from 'express';
import { randomUUID } from 'node:crypto';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { KnowledgeGraphManager } from './KnowledgeGraphManager.js';
import { initializeStorageProvider } from './config/storage.js';
import { setupServer } from './server/setup.js';
import { EmbeddingJobManager } from './embeddings/EmbeddingJobManager.js';
import { EmbeddingServiceFactory } from './embeddings/EmbeddingServiceFactory.js';
import { logger } from './utils/logger.js';
import { getOAuthConfig, OAuthService, AuthMiddleware } from './auth/index.js';

// Re-export the types and classes for use in other modules
export * from './KnowledgeGraphManager.js';
// Export the Relation type
export { RelationMetadata, Relation } from './types/relation.js';

// Initialize storage and create KnowledgeGraphManager
const storageProvider = initializeStorageProvider();

// Initialize embedding job manager only if storage provider supports it
let embeddingJobManager: EmbeddingJobManager | undefined = undefined;
try {
  // Force debug logging to help troubleshoot
  logger.debug(`OpenAI API key exists: ${!!process.env.OPENAI_API_KEY}`);
  logger.debug(`OpenAI Embedding model: ${process.env.OPENAI_EMBEDDING_MODEL || 'not set'}`);
  logger.debug(`Storage provider type: ${process.env.MEMORY_STORAGE_TYPE || 'default'}`);

  // Ensure OPENAI_API_KEY is defined for embedding generation
  if (!process.env.OPENAI_API_KEY) {
    logger.warn(
      'OPENAI_API_KEY environment variable is not set. Semantic search will use random embeddings.'
    );
  } else {
    logger.info('OpenAI API key found, will use for generating embeddings');
  }

  // Initialize the embedding service
  const embeddingService = EmbeddingServiceFactory.createFromEnvironment();
  logger.debug(`Embedding service model info: ${JSON.stringify(embeddingService.getModelInfo())}`);

  // Configure rate limiting options - stricter limits to prevent OpenAI API abuse
  const rateLimiterOptions = {
    tokensPerInterval: process.env.EMBEDDING_RATE_LIMIT_TOKENS
      ? parseInt(process.env.EMBEDDING_RATE_LIMIT_TOKENS, 10)
      : 20, // Default: 20 requests per minute
    interval: process.env.EMBEDDING_RATE_LIMIT_INTERVAL
      ? parseInt(process.env.EMBEDDING_RATE_LIMIT_INTERVAL, 10)
      : 60 * 1000, // Default: 1 minute
  };

  logger.info('Initializing EmbeddingJobManager', {
    rateLimiterOptions,
    model: embeddingService.getModelInfo().name,
    storageType: process.env.MEMORY_STORAGE_TYPE || 'neo4j',
  });

  // For Neo4j (which is always the storage provider)
  // Create a compatible wrapper for the Neo4j storage provider
  const adaptedStorageProvider = {
    ...storageProvider,
    // Add a fake db with exec function for compatibility
    db: {
      exec: (sql: string) => {
        logger.debug(`Neo4j adapter: Received SQL: ${sql}`);
        // No-op, just for compatibility
        return null;
      },
      prepare: () => ({
        run: () => null,
        all: () => [],
        get: () => null,
      }),
    },
    // Make sure getEntity is available
    getEntity: async (name: string) => {
      if (typeof storageProvider.getEntity === 'function') {
        return storageProvider.getEntity(name);
      }
      const result = await storageProvider.openNodes([name]);
      return result.entities[0] || null;
    },
    // Make sure storeEntityVector is available
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    storeEntityVector: async (name: string, embedding: any) => {
      logger.debug(`Neo4j adapter: storeEntityVector called for ${name}`, {
        embeddingType: typeof embedding,
        vectorLength: embedding?.vector?.length || 'no vector',
        model: embedding?.model || 'no model',
      });

      // Ensure embedding has the correct format
      const formattedEmbedding = {
        vector: embedding.vector || embedding,
        model: embedding.model || 'unknown',
        lastUpdated: embedding.lastUpdated || Date.now(),
      };

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      if (typeof (storageProvider as any).updateEntityEmbedding === 'function') {
        try {
          logger.debug(`Neo4j adapter: Using updateEntityEmbedding for ${name}`);
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          return await (storageProvider as any).updateEntityEmbedding(name, formattedEmbedding);
        } catch (error) {
          logger.error(`Neo4j adapter: Error in storeEntityVector for ${name}`, error);
          throw error;
        }
      } else {
        const errorMsg = `Neo4j adapter: Neither storeEntityVector nor updateEntityEmbedding implemented for ${name}`;
        logger.error(errorMsg);
        throw new Error(errorMsg);
      }
    },
  };

  // Create the embedding job manager with adapted storage provider
  embeddingJobManager = new EmbeddingJobManager(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    adaptedStorageProvider as any,
    embeddingService,
    rateLimiterOptions,
    null, // Use default cache options
    logger
  );

  // Schedule periodic processing for embedding jobs
  const EMBEDDING_PROCESS_INTERVAL = 10000; // 10 seconds - more frequent processing
  setInterval(async () => {
    try {
      // Process pending embedding jobs
      await embeddingJobManager?.processJobs(10);
    } catch (error) {
      // Log error but don't crash
      logger.error('Error in scheduled job processing', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      });
    }
  }, EMBEDDING_PROCESS_INTERVAL);
} catch (error) {
  // Fail gracefully if embedding job manager initialization fails
  logger.error('Failed to initialize EmbeddingJobManager', {
    error: error instanceof Error ? error.message : String(error),
    stack: error instanceof Error ? error.stack : undefined,
  });
  embeddingJobManager = undefined;
}

// Create the KnowledgeGraphManager with the storage provider, embedding job manager, and vector store options
const knowledgeGraphManager = new KnowledgeGraphManager({
  storageProvider,
  embeddingJobManager,
  // Pass vector store options from storage provider if available
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  vectorStoreOptions: (storageProvider as any).vectorStoreOptions,
});

// Ensure the storeEntityVector method is available on KnowledgeGraphManager's storageProvider
// Cast to any to bypass type checking for internal properties
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const knowledgeGraphManagerAny = knowledgeGraphManager as any;

if (
  knowledgeGraphManagerAny.storageProvider &&
  typeof knowledgeGraphManagerAny.storageProvider.storeEntityVector !== 'function'
) {
  // Add the storeEntityVector method to the storage provider
  knowledgeGraphManagerAny.storageProvider.storeEntityVector = async (
    name: string,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    embedding: any
  ) => {
    logger.debug(`Neo4j knowledgeGraphManager adapter: storeEntityVector called for ${name}`, {
      embeddingType: typeof embedding,
      vectorLength: embedding?.vector?.length || 'no vector',
      model: embedding?.model || 'no model',
    });

    // Ensure embedding has the correct format
    const formattedEmbedding = {
      vector: embedding.vector || embedding,
      model: embedding.model || 'unknown',
      lastUpdated: embedding.lastUpdated || Date.now(),
    };

    if (typeof knowledgeGraphManagerAny.storageProvider.updateEntityEmbedding === 'function') {
      try {
        logger.debug(
          `Neo4j knowledgeGraphManager adapter: Using updateEntityEmbedding for ${name}`
        );
        return await knowledgeGraphManagerAny.storageProvider.updateEntityEmbedding(
          name,
          formattedEmbedding
        );
      } catch (error) {
        logger.error(
          `Neo4j knowledgeGraphManager adapter: Error in storeEntityVector for ${name}`,
          error
        );
        throw error;
      }
    } else {
      const errorMsg = `Neo4j knowledgeGraphManager adapter: updateEntityEmbedding not implemented for ${name}`;
      logger.error(errorMsg);
      throw new Error(errorMsg);
    }
  };

  logger.info(
    'Added storeEntityVector adapter method to Neo4j storage provider for KnowledgeGraphManager'
  );
}

// Use a custom createEntities method for immediate job processing, but only if knowledgeGraphManager exists
if (knowledgeGraphManager && typeof knowledgeGraphManager.createEntities === 'function') {
  const originalCreateEntities = knowledgeGraphManager.createEntities.bind(knowledgeGraphManager);
  knowledgeGraphManager.createEntities = async function (entities) {
    // First call the original method to create the entities
    const result = await originalCreateEntities(entities);

    // Then process jobs immediately if we have an embedding job manager
    if (embeddingJobManager) {
      try {
        logger.info('Processing embedding jobs immediately after entity creation', {
          entityCount: entities.length,
          entityNames: entities.map((e) => e.name).join(', '),
        });
        await embeddingJobManager.processJobs(entities.length);
      } catch (error) {
        logger.error('Error processing embedding jobs immediately', {
          error: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined,
        });
      }
    }

    return result;
  };
}

// Setup the server with the KnowledgeGraphManager
const server = setupServer(knowledgeGraphManager);

// Setup OAuth authentication
const oauthConfig = getOAuthConfig();
const oauthService = new OAuthService(oauthConfig);
const authMiddleware = new AuthMiddleware(oauthService, oauthConfig.enabled);

logger.info(`OAuth authentication ${oauthConfig.enabled ? 'enabled' : 'disabled'}`);
logger.debug('OAuth configuration details:', {
  enabled: oauthConfig.enabled,
  envOAuthEnabled: process.env.OAUTH_ENABLED,
  clientId: oauthConfig.clientId,
  issuer: oauthConfig.issuer
});

if (oauthConfig.enabled) {
  logger.info(`OAuth issuer: ${oauthConfig.issuer}`);
  logger.info(`OAuth scopes: ${oauthConfig.scopes.join(', ')}`);
}

// Export main function for testing
export async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

// Export HTTP server function for direct connection
export async function startHttpServer(): Promise<void> {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Map to store transports by session ID
  const transports: { [key: string]: StreamableHTTPServerTransport } = {};

  // Configure server based on environment variables
  const port = parseInt(process.env.MCP_HTTP_PORT || '8080', 10);
  const host = process.env.MCP_HTTP_HOST || 'localhost';

  logger.info(`Starting HTTP server on ${host}:${port}`);

  // OAuth endpoints (only if OAuth is enabled)
  if (oauthConfig.enabled) {
    // OAuth authorization endpoint
    app.get('/oauth/authorize', (req, res) => oauthService.handleAuthorize(req, res));
    app.post('/oauth/authorize', (req, res) => oauthService.handleAuthorize(req, res));
    
    // OAuth callback endpoint (for testing and development)
    app.get('/oauth/callback', (req, res) => oauthService.handleCallback(req, res));
    
    // OAuth token endpoint
    app.post('/oauth/token', (req, res) => oauthService.handleToken(req, res));
    
    // OAuth token introspection endpoint
    app.post('/oauth/introspect', (req, res) => oauthService.handleIntrospect(req, res));
    
    // RFC7591 Dynamic Client Registration endpoints
    app.post('/oauth/register', (req, res) => oauthService.handleClientRegistration(req, res));
    app.get('/oauth/register/:client_id', (req, res) => oauthService.handleClientRegistration(req, res));
    app.put('/oauth/register/:client_id', (req, res) => oauthService.handleClientRegistration(req, res));
    app.delete('/oauth/register/:client_id', (req, res) => oauthService.handleClientRegistration(req, res));
    
    // OAuth server metadata endpoint
    app.get('/.well-known/oauth-authorization-server', (req, res) => oauthService.handleServerMetadata(req, res));
    
    logger.info('OAuth endpoints configured:');
    logger.info('  GET/POST /oauth/authorize - Authorization endpoint');
    logger.info('  GET /oauth/callback - Authorization callback (for testing)');
    logger.info('  POST /oauth/token - Token endpoint');
    logger.info('  POST /oauth/introspect - Token introspection');
    logger.info('  POST /oauth/register - Client registration (RFC7591)');
    logger.info('  GET/PUT/DELETE /oauth/register/:client_id - Client management (RFC7591)');
    logger.info('  GET /.well-known/oauth-authorization-server - Server metadata');
  } else {
    logger.info('OAuth is disabled - OAuth endpoints not registered');
  }

  // Handle POST requests for MCP communication (with authentication middleware)
  app.post('/mcp', authMiddleware.authenticate(), async (req, res) => {
    logger.debug('Received MCP request:', req.body);

    try {
      // Check for existing session ID
      const sessionId = req.headers['mcp-session-id'] as string;
      let transport: StreamableHTTPServerTransport;

      if (sessionId && transports[sessionId]) {
        // Reuse existing transport
        transport = transports[sessionId];
      } else if (!sessionId && isInitializeRequest(req.body)) {
        // New initialization request
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          eventStore: new InMemoryEventStore(),
          onsessioninitialized: (sessionId: string) => {
            logger.info(`Session initialized with ID: ${sessionId}`);
            transports[sessionId] = transport;
          },
        });

        // Set up onclose handler to clean up transport when closed
        transport.onclose = () => {
          const sid = transport.sessionId;
          if (sid && transports[sid]) {
            logger.info(`Transport closed for session ${sid}, removing from transports map`);
            delete transports[sid];
          }
        };

        // Connect the transport to the MCP server
        await server.connect(transport);
        await transport.handleRequest(req, res, req.body);
        return;
      } else {
        // Invalid request - no session ID or not initialization request
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

      // Handle the request with existing transport
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      logger.error('Error handling MCP request:', error);
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

  // Handle GET requests for SSE streams (with authentication middleware)
  app.get('/mcp', authMiddleware.authenticate(), async (req, res) => {
    const sessionId = req.headers['mcp-session-id'] as string;
    if (!sessionId || !transports[sessionId]) {
      res.status(400).send('Invalid or missing session ID');
      return;
    }

    const lastEventId = req.headers['last-event-id'] as string;
    if (lastEventId) {
      logger.debug(`Client reconnecting with Last-Event-ID: ${lastEventId}`);
    } else {
      logger.debug(`Establishing new SSE stream for session ${sessionId}`);
    }

    const transport = transports[sessionId];
    await transport.handleRequest(req, res);
  });

  // Handle DELETE requests for session termination (with authentication middleware)
  app.delete('/mcp', authMiddleware.authenticate(), async (req, res) => {
    const sessionId = req.headers['mcp-session-id'] as string;
    if (!sessionId || !transports[sessionId]) {
      res.status(400).send('Invalid or missing session ID');
      return;
    }

    logger.info(`Received session termination request for session ${sessionId}`);
    try {
      const transport = transports[sessionId];
      await transport.handleRequest(req, res);
    } catch (error) {
      logger.error('Error handling session termination:', error);
      if (!res.headersSent) {
        res.status(500).send('Error processing session termination');
      }
    }
  });

  // Health check endpoint
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // Start the server
  const httpServer = app.listen(port, host, () => {
    logger.info(`MCP HTTP Server listening on http://${host}:${port}`);
    logger.info('Available endpoints:');
    logger.info('  POST /mcp - MCP communication' + (oauthConfig.enabled ? ' (requires authentication)' : ''));
    logger.info('  GET /mcp - SSE streams' + (oauthConfig.enabled ? ' (requires authentication)' : ''));
    logger.info('  DELETE /mcp - Session termination' + (oauthConfig.enabled ? ' (requires authentication)' : ''));
    logger.info('  GET /health - Health check');
    if (oauthConfig.enabled) {
      logger.info('OAuth endpoints available:');
      logger.info('  GET/POST /oauth/authorize - Authorization');
      logger.info('  POST /oauth/token - Token exchange');
      logger.info('  POST /oauth/introspect - Token introspection');
      logger.info('  POST /oauth/register - Client registration (RFC7591)');
      logger.info('  GET/PUT/DELETE /oauth/register/:client_id - Client management (RFC7591)');
      logger.info('  GET /.well-known/oauth-authorization-server - Server metadata');
    } else {
      logger.info('OAuth endpoints: Not available (OAuth disabled)');
    }
  });

  // Handle server shutdown
  const shutdown = async (): Promise<void> => {
    logger.info('Shutting down HTTP server...');

    // Close all active transports
    for (const sessionId in transports) {
      try {
        logger.debug(`Closing transport for session ${sessionId}`);
        await transports[sessionId].close();
        delete transports[sessionId];
      } catch (error) {
        logger.error(`Error closing transport for session ${sessionId}:`, error);
      }
    }

    // Close HTTP server
    httpServer.close(() => {
      logger.info('HTTP server shutdown complete');
      process.exit(0);
    });
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

// Determine which transport to use based on environment
const transportMode = process.env.MCP_TRANSPORT_MODE || 'stdio';

// Only run main if not in a test environment
if (!process.env.VITEST && !process.env.NODE_ENV?.includes('test')) {
  if (transportMode === 'http') {
    startHttpServer().catch((error) => {
      logger.error(`HTTP server terminated: ${error}`);
      process.exit(1);
    });
  } else {
    main().catch((error) => {
      logger.error(`Main process terminated: ${error}`);
      process.exit(1);
    });
  }
}

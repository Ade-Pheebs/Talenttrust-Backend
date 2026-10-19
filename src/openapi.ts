import { config, explorerUrl } from './config';

const json = (schema: object) => ({ 'application/json': { schema } });
const ok = (description: string, schema: object = { type: 'object' }) => ({
  200: { description, content: json(schema) },
});
const idParam = { name: 'id', in: 'path', required: true, schema: { type: 'integer' } };
const contractRef = { $ref: '#/components/schemas/EscrowContract' };
const reputationRef = { $ref: '#/components/schemas/Reputation' };

/** Applied to every protected operation. */
const bearerSecurity = [{ bearerAuth: [] }];

/** Standard 401/403 responses added to every protected operation. */
const authResponses = {
  401: {
    description: 'Missing or invalid bearer token.',
    content: json({ $ref: '#/components/schemas/ErrorResponse' }),
  },
  403: {
    description: 'Authenticated caller is not the required party for this operation.',
    content: json({ $ref: '#/components/schemas/ErrorResponse' }),
  },
};

export const openapi = {
  openapi: '3.0.3',
  info: {
    title: 'TalentTrust API',
    version: config.version,
    description:
      'Milestone-based escrow API for freelancers and clients. State mirrors the TalentTrust ' +
      `Soroban escrow contract on Stellar ${config.network} (${config.contractId}). ` +
      `Explorer: ${explorerUrl()}. Data is held in memory and resets on redeploy.\n\n` +
      '**Authentication**: mutating routes require a bearer token obtained via the auth endpoints. ' +
      'Call `GET /api/v1/auth/challenge?address=G…`, sign the returned challenge string with your ' +
      'Stellar ed25519 private key, then `POST /api/v1/auth/token` to receive a short-lived JWT.',
  },
  servers: [{ url: '/' }],
  tags: [
    { name: 'System' },
    { name: 'Auth', description: 'Wallet-signature authentication (SEP-10 style)' },
    { name: 'Contracts' },
    { name: 'Reputation' },
  ],
  paths: {
    '/health': {
      get: { tags: ['System'], summary: 'Health check', responses: ok('Service is healthy') },
    },
    '/api/v1/chain': {
      get: { tags: ['System'], summary: 'On-chain escrow contract deployment info', responses: ok('Deployment') },
    },
    '/api/v1/stats': {
      get: { tags: ['System'], summary: 'Aggregate escrow statistics', responses: ok('Stats') },
    },

    // --- Auth ---

    '/api/v1/auth/challenge': {
      get: {
        tags: ['Auth'],
        summary: 'Request a sign challenge for a Stellar address',
        description:
          'Returns a short-lived HMAC-signed challenge string. ' +
          'Sign it with the ed25519 private key corresponding to `address` and pass it to `POST /api/v1/auth/token`.',
        parameters: [
          {
            name: 'address',
            in: 'query',
            required: true,
            description: 'Stellar G… ed25519 public key.',
            schema: { type: 'string', example: 'GBZXQ...' },
          },
        ],
        responses: {
          200: {
            description: 'Challenge issued.',
            content: json({ $ref: '#/components/schemas/ChallengeResponse' }),
          },
          400: {
            description: 'Invalid Stellar address.',
            content: json({ $ref: '#/components/schemas/ErrorResponse' }),
          },
        },
      },
    },

    '/api/v1/auth/token': {
      post: {
        tags: ['Auth'],
        summary: 'Exchange a signed challenge for a bearer token',
        description:
          'Verifies the HMAC, challenge expiry, address match, and ed25519 signature. ' +
          'Returns an HS256 JWT (≤ 1 h) to use as `Authorization: Bearer <token>` on protected routes.',
        requestBody: {
          required: true,
          content: json({ $ref: '#/components/schemas/TokenRequest' }),
        },
        responses: {
          200: {
            description: 'Token issued.',
            content: json({ $ref: '#/components/schemas/TokenResponse' }),
          },
          400: {
            description: 'Malformed request body.',
            content: json({ $ref: '#/components/schemas/ErrorResponse' }),
          },
          401: {
            description: 'invalid_challenge / challenge_expired / challenge_replayed / invalid_signature.',
            content: json({ $ref: '#/components/schemas/ErrorResponse' }),
          },
        },
      },
    },

    // --- Contracts ---

    '/api/v1/contracts': {
      get: {
        tags: ['Contracts'],
        summary: 'List escrow contracts',
        parameters: [
          { name: 'status', in: 'query', schema: { type: 'string' } },
          { name: 'party', in: 'query', schema: { type: 'string' }, description: 'Filter by client or freelancer address' },
        ],
        responses: ok('Contracts', { type: 'object', properties: { data: { type: 'array', items: contractRef } } }),
      },
      post: {
        tags: ['Contracts'],
        summary: 'Create an escrow contract (auth required — caller must be the client)',
        security: bearerSecurity,
        requestBody: {
          required: true,
          content: json({
            type: 'object',
            required: ['freelancer', 'milestones'],
            properties: {
              title: { type: 'string' },
              client: {
                type: 'string',
                description: 'Must equal the authenticated address (or be omitted — it is forced to the token subject).',
              },
              freelancer: { type: 'string' },
              token: { type: 'string', default: 'XLM' },
              milestones: {
                type: 'array',
                items: { type: 'object', properties: { title: { type: 'string' }, amount: { type: 'number' } } },
              },
            },
          }),
        },
        responses: { 201: { description: 'Created', content: json(contractRef) }, ...authResponses },
      },
    },

    '/api/v1/contracts/{id}': {
      get: {
        tags: ['Contracts'],
        summary: 'Get a contract',
        parameters: [idParam],
        responses: ok('Contract', contractRef),
      },
    },

    '/api/v1/contracts/{id}/deposit': {
      post: {
        tags: ['Contracts'],
        summary: 'Deposit funds into escrow (client only)',
        security: bearerSecurity,
        parameters: [idParam],
        requestBody: { content: json({ type: 'object', properties: { amount: { type: 'number' } } }) },
        responses: { ...ok('Updated contract', contractRef), ...authResponses },
      },
    },

    '/api/v1/contracts/{id}/milestones/{index}/release': {
      post: {
        tags: ['Contracts'],
        summary: 'Release a milestone payment to the freelancer (client only)',
        security: bearerSecurity,
        parameters: [
          idParam,
          { name: 'index', in: 'path', required: true, schema: { type: 'integer' } },
        ],
        responses: { ...ok('Updated contract', contractRef), ...authResponses },
      },
    },

    '/api/v1/contracts/{id}/dispute': {
      post: {
        tags: ['Contracts'],
        summary: 'Open a dispute (client or freelancer)',
        security: bearerSecurity,
        parameters: [idParam],
        requestBody: {
          content: json({
            type: 'object',
            properties: {
              reason: { type: 'string' },
              raisedBy: {
                type: 'string',
                description:
                  'Accepted for backwards compatibility but must equal the authenticated address (or be omitted).',
              },
            },
          }),
        },
        responses: { ...ok('Updated contract', contractRef), ...authResponses },
      },
    },

    '/api/v1/contracts/{id}/resolve': {
      post: {
        tags: ['Contracts'],
        summary: 'Resolve a dispute (admin — not covered by this auth scheme)',
        parameters: [idParam],
        requestBody: {
          content: json({ type: 'object', properties: { freelancerBps: { type: 'integer', minimum: 0, maximum: 10000 } } }),
        },
        responses: ok('Updated contract', contractRef),
      },
    },

    '/api/v1/contracts/{id}/cancel': {
      post: {
        tags: ['Contracts'],
        summary: 'Cancel and refund (client only)',
        security: bearerSecurity,
        parameters: [idParam],
        responses: { ...ok('Updated contract', contractRef), ...authResponses },
      },
    },

    '/api/v1/contracts/{id}/reputation': {
      post: {
        tags: ['Reputation'],
        summary: 'Rate the freelancer of a completed contract (client only)',
        security: bearerSecurity,
        parameters: [idParam],
        requestBody: {
          content: json({ type: 'object', properties: { rating: { type: 'integer', minimum: 1, maximum: 5 } } }),
        },
        responses: { ...ok('Reputation', reputationRef), ...authResponses },
      },
    },

    '/api/v1/reputation/{address}': {
      get: {
        tags: ['Reputation'],
        summary: 'Get freelancer reputation',
        parameters: [{ name: 'address', in: 'path', required: true, schema: { type: 'string' } }],
        responses: ok('Reputation', reputationRef),
      },
    },
  },
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'HS256 JWT obtained via POST /api/v1/auth/token after signing a challenge.',
      },
    },
    schemas: {
      EscrowContract: {
        type: 'object',
        properties: {
          id: { type: 'integer' },
          title: { type: 'string' },
          client: { type: 'string' },
          freelancer: { type: 'string' },
          token: { type: 'string' },
          milestones: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                index: { type: 'integer' },
                title: { type: 'string' },
                amount: { type: 'number' },
                released: { type: 'boolean' },
              },
            },
          },
          totalAmount: { type: 'number' },
          fundedAmount: { type: 'number' },
          releasedAmount: { type: 'number' },
          status: {
            type: 'string',
            enum: ['Created', 'Funded', 'Completed', 'Disputed', 'Resolved', 'Cancelled'],
          },
          reputationIssued: { type: 'boolean' },
          dispute: {
            type: 'object',
            nullable: true,
            properties: {
              raisedBy: { type: 'string' },
              reason: { type: 'string' },
              openedAt: { type: 'string', format: 'date-time' },
              freelancerBps: { type: 'integer' },
              resolvedAt: { type: 'string', format: 'date-time', nullable: true },
            },
          },
          createdAt: { type: 'string', format: 'date-time' },
          updatedAt: { type: 'string', format: 'date-time' },
        },
      },
      Reputation: {
        type: 'object',
        properties: {
          address: { type: 'string' },
          completedContracts: { type: 'integer' },
          totalRating: { type: 'number' },
          averageRating: { type: 'number' },
        },
      },
      ChallengeResponse: {
        type: 'object',
        required: ['address', 'challenge', 'expiresAt'],
        properties: {
          address: { type: 'string' },
          challenge: { type: 'string', description: 'The challenge string to sign with your Stellar private key.' },
          expiresAt: { type: 'string', format: 'date-time' },
        },
      },
      TokenRequest: {
        type: 'object',
        required: ['address', 'challenge', 'signature'],
        properties: {
          address: { type: 'string', description: 'Stellar G… public key.' },
          challenge: { type: 'string', description: 'The exact challenge string returned by GET /challenge.' },
          signature: {
            type: 'string',
            description: 'base64-encoded ed25519 signature over the UTF-8 bytes of the challenge string.',
          },
        },
      },
      TokenResponse: {
        type: 'object',
        required: ['token', 'tokenType', 'expiresAt'],
        properties: {
          token: { type: 'string', description: 'HS256 JWT to use as a bearer token (≤ 1 h).' },
          tokenType: { type: 'string', enum: ['Bearer'] },
          expiresAt: { type: 'string', format: 'date-time' },
        },
      },
      ErrorResponse: {
        type: 'object',
        required: ['error', 'message'],
        properties: {
          error: { type: 'string', description: 'Machine-readable error code.' },
          message: { type: 'string', description: 'Human-readable explanation.' },
        },
      },
    },
  },
};

export const docsHtml = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>TalentTrust API Docs</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.17.14/swagger-ui.css" />
  <style>body{margin:0;background:#fafafa}.tt-bar{background:#0f172a;color:#fff;padding:14px 24px;font-family:system-ui,sans-serif;display:flex;gap:16px;align-items:center;flex-wrap:wrap}.tt-bar a{color:#a5b4fc}</style>
</head>
<body>
  <div class="tt-bar"><strong>TalentTrust API</strong>
    <a href="/">Endpoints (JSON)</a>
    <a href="/openapi.json">openapi.json</a>
    <a href="${config.frontendUrl}">Website</a>
    <a href="${explorerUrl()}">Escrow contract on stellar.expert</a>
  </div>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.17.14/swagger-ui-bundle.js" crossorigin></script>
  <script>window.onload=function(){window.ui=SwaggerUIBundle({url:'/openapi.json',dom_id:'#swagger-ui'})}</script>
</body>
</html>`;

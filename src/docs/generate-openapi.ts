import { OpenApiGeneratorV3 } from '@asteasolutions/zod-to-openapi';
import { registry } from './openapi-registry';
import * as yaml from 'yaml';
import * as fs from 'fs';
import * as path from 'path';

// Import all routes/schemas so they register themselves
import '../modules/contracts/dto/contract.dto';
import '../modules/contractMetadata/contractMetadata.schema';
import '../modules/reputation/dto/reputation.dto';
import '../routes/contracts.routes';
import '../routes/reputation.routes';
import '../routes/health';

// The contracts router registers its Express handlers but does not expose an
// OpenAPI collection entry, and the reputation router only registers the
// item-level (`/reputation/{id}`) operations. Register the collection-level
// paths here so the generated spec advertises the top-level `/contracts` and
// `/reputation` resources alongside the already-registered `/health` route.
// These run once at module load (the registry is a shared singleton), so
// repeated calls to generateOpenApiSpec() do not double-register.
registry.registerPath({
  method: 'get',
  path: '/contracts',
  summary: 'List contracts',
  tags: ['Contracts'],
  responses: {
    200: { description: 'A list of contracts' },
  },
});

registry.registerPath({
  method: 'get',
  path: '/reputation',
  summary: 'List reputation profiles',
  tags: ['Reputation'],
  responses: {
    200: { description: 'A list of reputation profiles' },
  },
});

export function generateOpenApiSpec(): any {
  const generator = new OpenApiGeneratorV3(registry.definitions);

  // Register the apiKey security scheme
  registry.registerComponent('securitySchemes', 'apiKey', {
    type: 'apiKey',
    in: 'header',
    name: 'X-API-Key',
    description:
      'Scoped API key for machine-to-machine authentication. ' +
      'Provide via `X-API-Key` header or `Authorization: ApiKey <key>`.',
  });

  // Register POST /contracts/{id}/resolve
  registry.registerPath({
    method: 'post',
    path: '/contracts/{id}/resolve',
    summary: 'Resolve a dispute (scoped API key)',
    tags: ['Contracts', 'Disputes'],
    security: [{ apiKey: [] }],
    parameters: [
      {
        name: 'id',
        in: 'path',
        required: true,
        schema: { type: 'string' },
        description: 'Contract ID',
      },
    ],
    requestBody: {
      required: true,
      content: {
        'application/json': {
          schema: {
            type: 'object',
            required: ['freelancerBps'],
            properties: {
              freelancerBps: {
                type: 'integer',
                minimum: 0,
                maximum: 10000,
                description:
                  'Basis-point split to the freelancer (10000 = 100% freelancer, 0 = 100% client).',
              },
            },
          },
        },
      },
    },
    responses: {
      200: {
        description: 'Dispute resolved successfully',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                status: { type: 'string', example: 'success' },
                data: {
                  type: 'object',
                  properties: {
                    disputeId: { type: 'string' },
                    contractId: { type: 'string' },
                    status: { type: 'string', example: 'resolved' },
                    freelancerBps: { type: 'integer' },
                    clientBps: { type: 'integer' },
                    resolvedBy: { type: 'string' },
                    resolution: { type: 'string' },
                  },
                },
              },
            },
          },
        },
      },
      401: { description: 'Missing or invalid API key' },
      403: { description: 'Insufficient scope (requires disputes:resolve)' },
      404: { description: 'No active dispute found for the contract' },
    },
  });

  // Register GET /auth/whoami
  registry.registerPath({
    method: 'get',
    path: '/auth/whoami',
    summary: 'Return the authenticated API key id and scopes',
    tags: ['Auth'],
    security: [{ apiKey: [] }],
    responses: {
      200: {
        description: 'API key identity and scopes',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                keyId: { type: 'string' },
                scopes: {
                  type: 'array',
                  items: { type: 'string' },
                },
              },
            },
          },
        },
      },
      401: { description: 'Missing or invalid API key' },
    },
  });

  const spec = generator.generateDocument({
    openapi: '3.0.0',
    info: {
      version: '1.0.0',
      title: 'TalentTrust API',
      description: 'TalentTrust API Gateway and services documentation',
    },
    servers: [{ url: '/api/v1' }],
  });

  return spec;
}

if (require.main === module) {
  const spec = generateOpenApiSpec();
  const yamlSpec = yaml.stringify(spec);
  const outputPath = path.join(__dirname, '../../docs/openapi.yaml');

  if (!fs.existsSync(path.dirname(outputPath))) {
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  }

  fs.writeFileSync(outputPath, yamlSpec);
  console.log(`OpenAPI spec generated at ${outputPath}`);
}

# TalentTrust Backend

## Live

- Website: https://talenttrust-frontend.vercel.app
- Docs: https://talenttrust-frontend.vercel.app/docs
- API: https://talenttrust-backend.vercel.app
- API docs (Swagger UI): https://talenttrust-backend.vercel.app/docs
- Contract (Stellar testnet): [`CCZMIVUBMG5SBC47SDTC32RWLBJ2HW2DCFVWJEOKCH2IFJBZGBKTXK5W`](https://stellar.expert/explorer/testnet/contract/CCZMIVUBMG5SBC47SDTC32RWLBJ2HW2DCFVWJEOKCH2IFJBZGBKTXK5W)

Express + TypeScript API for TalentTrust, a milestone-based freelancer escrow protocol on Stellar.
The API mirrors the state machine of the Soroban escrow contract
([Talenttrust-Contracts](https://github.com/Talenttrust/Talenttrust-Contracts)) so clients and
freelancers can create engagements, fund escrow, release milestones, raise disputes and build reputation.

Storage is in-memory (seeded with demo data), so no database is required. On serverless hosting the
data is per-instance and resets on redeploy.

## Endpoints

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| GET | `/` | — | Service info and endpoint list (JSON) |
| GET | `/health` | — | Health check |
| GET | `/docs` | — | Swagger UI |
| GET | `/openapi.json` | — | OpenAPI 3 spec |
| GET | `/api/v1/chain` | — | On-chain contract deployment info |
| GET | `/api/v1/stats` | — | Aggregate statistics |
| GET | `/api/v1/auth/challenge` | — | Request a sign challenge (`?address=G…`) |
| POST | `/api/v1/auth/token` | — | Exchange signed challenge for a bearer token |
| GET/POST | `/api/v1/contracts` | POST: Bearer | List (`?status=`, `?party=`) / create escrow contracts |
| GET | `/api/v1/contracts/:id` | — | Get a contract |
| POST | `/api/v1/contracts/:id/deposit` | Bearer (client) | `{ "amount": 100 }` |
| POST | `/api/v1/contracts/:id/milestones/:index/release` | Bearer (client) | Release a milestone |
| POST | `/api/v1/contracts/:id/dispute` | Bearer (client/freelancer) | `{ "reason": "..." }` (`raisedBy` optional, must match token) |
| POST | `/api/v1/contracts/:id/resolve` | — | `{ "freelancerBps": 5000 }` (admin — handled separately) |
| POST | `/api/v1/contracts/:id/cancel` | Bearer (client) | Cancel and refund |
| POST | `/api/v1/contracts/:id/reputation` | Bearer (client) | `{ "rating": 5 }` |
| GET | `/api/v1/reputation/:address` | — | Freelancer reputation |

## Authentication

Mutating routes require a **bearer token** obtained via the SEP-10-style wallet-signature flow:

1. `GET /api/v1/auth/challenge?address=G…` — receive a short-lived, HMAC-signed challenge string.
2. Sign the exact challenge string with your Stellar ed25519 private key (base64-encode the signature).
3. `POST /api/v1/auth/token` with `{ address, challenge, signature }` — receive an HS256 JWT (≤ 1 h).
4. Send `Authorization: Bearer <token>` on protected routes.

The token subject (`sub`) is the caller's Stellar address. The store enforces the same party rules as
the on-chain contract: `deposit`, `release`, `cancel`, `reputation` require the caller to be the
contract client; `dispute` requires the caller to be the client or freelancer. A body `raisedBy` on
dispute is accepted for backwards compatibility but rejected (403) if it differs from the token subject.

## Development

```bash
npm ci
npm run dev      # http://localhost:3001
npm run lint     # type check
npm test
npm run build && npm start
```

Configuration (all optional unless noted, see `.env.example`): `PORT`, `ESCROW_CONTRACT_ID`,
`STELLAR_NETWORK`, `STELLAR_RPC_URL`, `FRONTEND_URL`, `AUTH_SECRET`.

| Variable | Required | Description |
| --- | --- | --- |
| `AUTH_SECRET` | Yes (production) | Secret (≥ 32 bytes) used to sign challenges and JWTs. In dev/test a random per-process secret is generated with a warning. |
| `NODE_ENV` | No | When `production`, `AUTH_SECRET` must be set or the app will refuse to start. |
| `ESCROW_CONTRACT_ID` | No | On-chain contract ID (Stellar testnet default provided). |
| `STELLAR_NETWORK` | No | `testnet` (default) or `public`. |
| `STELLAR_RPC_URL` | No | Soroban RPC endpoint. |
| `FRONTEND_URL` | No | Used in docs / root info. |
| `PORT` | No | Listen port (default 3001). |

## Deployment

Deployed on Vercel as a serverless function: `api/index.ts` exports the Express app and
`vercel.json` rewrites every path to it. `src/index.ts` only calls `listen()` when run directly.

```bash
vercel deploy --prod
```

## License

MIT

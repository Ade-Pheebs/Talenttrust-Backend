import { runInNewContext } from 'node:vm';
import {
  buildAuditMetadata, INVALID, LIMIT_EXCEEDED, MAX_DEPTH, MAX_NODES,
  maskEmail, redactBody, redactHeaders, REDACTED,
} from './redact';

describe('audit redaction validation boundaries', () => {
  it('copies accepted records, arrays and primitives without mutation', () => {
    const input = Object.freeze({ nested: Object.freeze([{ password: 'secret', email: 'alice@example.com' }]), n: 0, b: false, nil: null });
    expect(redactBody(input)).toEqual({ nested: [{ password: REDACTED, email: 'ali***@example.com' }], n: 0, b: false, nil: null });
    expect(input.nested[0].password).toBe('secret');
    expect(redactBody(undefined)).toBeUndefined();
    expect(redactBody(Object.assign(Object.create(null), { ok: true }))).toEqual({ ok: true });
  });

  it.each([BigInt(1), Symbol('secret'), () => 'secret', NaN, Infinity, new Date(), new Map(), Buffer.from('secret')])('rejects unsupported values with a safe marker (%#)', value => {
    expect(redactBody(value)).toBe(INVALID);
  });

  it('never calls accessors, toJSON or proxy traps', () => {
    const getter = jest.fn(() => { throw new Error('secret'); });
    const input = Object.defineProperties({}, {
      ordinary: { enumerable: true, get: getter },
      password: { enumerable: true, get: getter },
    });
    expect(redactBody(input)).toEqual({ ordinary: INVALID, password: REDACTED });
    expect(redactHeaders(input)).toEqual({ ordinary: INVALID, password: INVALID });
    const proxy = new Proxy({}, { ownKeys: getter, getPrototypeOf: getter });
    expect(redactBody(proxy)).toBe(INVALID);
    const toJSON = jest.fn(() => 'secret');
    expect(JSON.stringify(redactBody({ toJSON }))).not.toContain('secret');
    expect(getter).not.toHaveBeenCalled();
    expect(toJSON).not.toHaveBeenCalled();
  });

  it('handles cycles, repeated references and retries independently', () => {
    const shared = { email: 'a@example.com', token: 'secret' };
    const input: Record<string, unknown> = { a: shared, b: shared };
    input.self = input;
    const output = redactBody(input);
    expect(output).toEqual({ a: { email: 'a***@example.com', token: REDACTED }, b: { email: 'a***@example.com', token: REDACTED }, self: INVALID });
    expect(redactBody(input)).toEqual(output);
    expect(redactBody(output)).toEqual(output);
    expect(redactBody({ ok: true })).toEqual({ ok: true });
  });

  it.each(['a@host.io', 'ab@host.io', 'alice@host.io', 'not-email'])('masks idempotently: %s', email => {
    expect(maskEmail(maskEmail(email))).toBe(maskEmail(email));
  });

  it('preserves prototype-shaped keys as own data', () => {
    const output = redactBody(JSON.parse('{"__proto__":{"password":"secret"},"constructor":"ok"}')) as object;
    expect(Object.getPrototypeOf(output)).toBe(Object.prototype);
    expect(Object.hasOwn(output, '__proto__')).toBe(true);
    expect(JSON.stringify(output)).toBe('{"__proto__":{"password":"[REDACTED]"},"constructor":"ok"}');
  });

  it('bounds depth and width and diagnoses sparse slots', () => {
    const nest = (depth: number): unknown => depth === 0 ? 1 : [nest(depth - 1)];
    expect(redactBody(nest(MAX_DEPTH))).toEqual(nest(MAX_DEPTH));
    expect(JSON.stringify(redactBody(nest(MAX_DEPTH + 1)))).toContain(LIMIT_EXCEEDED);
    expect(redactBody(Array(MAX_NODES - 1).fill(1))).toHaveLength(MAX_NODES - 1);
    expect(redactBody(Array(MAX_NODES).fill(1))).toBe(LIMIT_EXCEEDED);
    expect(redactBody(Array(1))).toEqual([INVALID]);
  });

  it('redacts duplicate case variants and copies header arrays', () => {
    const headers = { Authorization: 'secret1', authorization: ['secret2'], 'set-cookie': ['secret3'], accept: ['json'] };
    const output = redactHeaders(headers);
    expect(output).toEqual({ Authorization: REDACTED, authorization: REDACTED, 'set-cookie': REDACTED, accept: ['json'] });
    headers.accept.push('html');
    expect(output.accept).toEqual(['json']);
    expect(redactBody({ headers })).toMatchObject({ headers: { Authorization: REDACTED, authorization: REDACTED } });
    expect(redactHeaders({ ' Authorization ': 'secret' })).toEqual({ ' Authorization ': INVALID });
  });

  it('accepts plain records from another realm', () => {
    expect(redactHeaders(runInNewContext('({authorization: \"secret\"})'))).toEqual({ authorization: REDACTED });
  });

  it('diagnoses invalid header values and enforces header bounds', () => {
    expect(redactHeaders({ accept: 42 } as never)).toEqual({ accept: INVALID });
    expect(redactHeaders({ accept: ['ok', 42] } as never)).toEqual({ accept: INVALID });
    expect(redactHeaders({ accept: Array(MAX_NODES + 1).fill('x') })).toEqual({ accept: LIMIT_EXCEEDED });
    expect(redactHeaders({ accept: Array(MAX_NODES - 1).fill('x') }).accept).toHaveLength(MAX_NODES - 1);
    expect(() => redactHeaders(Object.fromEntries(Array.from({ length: MAX_NODES + 1 }, (_, i) => [`x-${i}`, 'x'])))).toThrow('Audit headers limit exceeded');
  });

  it('shares the node budget across branches and recovers on the next call', () => {
    const branch = Array(MAX_NODES - 3).fill(0);
    const input = { first: branch, second: branch };
    expect(redactBody(input)).toEqual({ first: branch, second: LIMIT_EXCEEDED });
    expect(redactBody({ ok: 1 })).toEqual({ ok: 1 });
  });

  it.each([100, 200, 599])('accepts HTTP status boundary %s', status => {
    expect(buildAuditMetadata('GET', '/', {}, undefined, {}, status, undefined)).toEqual({ method: 'GET', path: '/', headers: {}, body: null, query: null, statusCode: status, requestId: null });
  });

  it.each([99, 600, 200.5, NaN])('rejects invalid status %s without echoing input', status => {
    expect(() => buildAuditMetadata('GET', '/', {}, null, {}, status, undefined)).toThrow('Invalid audit metadata envelope');
  });

  it('rejects invalid envelopes while preserving valid calls after failure', () => {
    expect(() => buildAuditMetadata('GET', '/?token=secret', {}, null, {}, 200, undefined)).toThrow('Invalid audit metadata envelope');
    expect(() => redactHeaders(null as never)).toThrow('Invalid audit headers');
    expect(() => buildAuditMetadata('GET', '/', {}, null, [] as never, 200, undefined)).toThrow('Invalid audit metadata envelope');
    expect(buildAuditMetadata('POST', '/api', {}, { password: 'secret' }, { q: 'a@host.io' }, 201, 'id')).toMatchObject({ body: { password: REDACTED }, query: { q: 'a***@host.io' }, requestId: 'id' });
  });
});

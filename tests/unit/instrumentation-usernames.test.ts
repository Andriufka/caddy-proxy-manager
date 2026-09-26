/**
 * Starting the server never changes a stored username, including ones the
 * login page cannot use (an email with a '+', a mixed-case username) and
 * missing ones. Only an administrator sets a username for those accounts.
 * It only warns about usernames to check: one that reaches another account
 * too, and one that is an email address other than the account's own (such
 * as alice-cpm@example.com on the account alice+cpm@example.com).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createTestDb, type TestDb } from '../helpers/db';
import { accounts, users } from '../../src/lib/db/schema';
import { CREDENTIAL_ACCOUNT_ISSUER } from '../../src/lib/account-issuer';

let db: TestDb;

vi.mock('../../src/lib/db', () => ({
  get default() { return db; },
  get sqlite() { return undefined; },
  nowIso: () => new Date().toISOString(),
  toIso: (value: string | Date | null | undefined): string | null => {
    if (!value) return null;
    return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
  },
}));
vi.mock('../../src/lib/config', () => ({ validateProductionConfig: () => {} }));
vi.mock('../../src/lib/init-db', () => ({ ensureAdminUser: async () => {} }));
vi.mock('../../src/lib/models/certificates', () => ({ migrateLegacyCertificateStorage: async () => 0 }));
vi.mock('../../src/lib/models/ca-certificates', () => ({ migrateLegacyCaPrivateKeys: async () => 0 }));
vi.mock('../../src/lib/secret-rotation', () => ({
  reencryptStoredSecrets: async () => ({ reencrypted: 0, encryptedPlaintext: 0, failed: 0, clearedOAuthTokens: 0 }),
}));
vi.mock('../../src/lib/caddy', () => ({ applyCaddyConfig: async () => {} }));
vi.mock('../../src/lib/caddy-monitor', () => ({ startCaddyMonitoring: () => {} }));
vi.mock('../../src/lib/clickhouse/client', () => ({ initClickHouse: async () => {}, closeClickHouse: () => {} }));
// Failing parser start-up keeps register() from installing intervals and SIGTERM handlers.
vi.mock('../../src/lib/log-parser', () => ({
  initLogParser: async () => { throw new Error('not in tests'); },
  parseNewLogEntries: async () => {},
  stopLogParser: () => {},
}));
vi.mock('../../src/lib/waf-log-parser', () => ({
  initWafLogParser: async () => { throw new Error('not in tests'); },
  parseNewWafLogEntries: async () => {},
  stopWafLogParser: () => {},
}));
vi.mock('../../src/lib/instance-sync', () => ({
  getInstanceMode: async () => 'standalone',
  getSyncIntervalMs: () => 0,
  runPeriodicInstanceSync: async () => null,
}));

import { register } from '../../src/instrumentation';

const NOW = '2026-02-01T00:00:00.000Z';

function seedCredentialUser(email: string, username: string | null) {
  const user = db.insert(users).values({
    email,
    username,
    displayUsername: username,
    name: null,
    passwordHash: 'hash',
    role: 'user',
    provider: 'credentials',
    subject: email,
    status: 'active',
    createdAt: NOW,
    updatedAt: NOW,
  }).returning().get();
  db.insert(accounts).values({
    userId: user.id,
    issuer: CREDENTIAL_ACCOUNT_ISSUER,
    accountId: String(user.id),
    providerId: 'credential',
    password: 'hash',
    createdAt: NOW,
    updatedAt: NOW,
  }).run();
  return user.id;
}

function usernameColumns() {
  return db.select({
    email: users.email,
    username: users.username,
    displayUsername: users.displayUsername,
    updatedAt: users.updatedAt,
  }).from(users).orderBy(users.id).all();
}

describe('instrumentation and sign-in usernames', () => {
  const originalRuntime = process.env.NEXT_RUNTIME;

  beforeEach(() => {
    process.env.NEXT_RUNTIME = 'nodejs';
    db = createTestDb();
  });

  afterEach(() => {
    if (originalRuntime === undefined) delete process.env.NEXT_RUNTIME;
    else process.env.NEXT_RUNTIME = originalRuntime;
    vi.restoreAllMocks();
  });

  it('leaves every stored username as it is on startup', async () => {
    seedCredentialUser('alice+cpm@example.com', 'alice+cpm@example.com');
    seedCredentialUser('bob@example.com', 'Bob');
    seedCredentialUser('carol+x@example.com', null);
    seedCredentialUser('dave@example.com', null);
    seedCredentialUser('erin@example.com', 'erin');
    const before = usernameColumns();
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});

    await register();

    expect(usernameColumns()).toEqual(before);
    expect(log.mock.calls.map((call) => call.map(String).join(' ')).join('\n')).not.toMatch(/sign-in username/i);
  });

  it('does not warn about an email-shaped username that is the account\'s own portal name', async () => {
    seedCredentialUser('admin@example.com@localhost', 'admin@example.com');
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});

    await register();

    const warnings = warn.mock.calls.map((call) => call.map(String).join(' ')).filter((line) => /sign-in username/i.test(line));
    expect(warnings).toEqual([]);
  });

  it('warns about usernames to check without changing them', async () => {
    const derived = seedCredentialUser('alice+cpm@example.com', 'alice-cpm@example.com');
    const shared = seedCredentialUser('anna@example.com', 'bob@example.com');
    seedCredentialUser('bob@example.com', null);
    const portal = seedCredentialUser('erin@example.com', 'ops');
    seedCredentialUser('ops@localhost', 'ops@localhost');
    seedCredentialUser('carol@example.com', 'carol@example.com');
    seedCredentialUser('dave@example.com', 'dave');
    seedCredentialUser('Fay@Example.com', 'fay@example.com');
    const before = usernameColumns();
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});

    await register();

    expect(usernameColumns()).toEqual(before);
    const warnings = warn.mock.calls.map((call) => call.map(String).join(' ')).filter((line) => /sign-in username/i.test(line));
    expect(warnings).toEqual([
      expect.stringMatching(new RegExp(`^Sign-in username "alice-cpm@example.com" of user ${derived} is an email address other than the account's own`)),
      expect.stringMatching(new RegExp(`^Sign-in username "bob@example.com" of user ${shared} is also another account's username, email address or forward-auth portal name`)),
      expect.stringMatching(new RegExp(`^Sign-in username "ops" of user ${portal} is also another account's`)),
    ]);
  });
});

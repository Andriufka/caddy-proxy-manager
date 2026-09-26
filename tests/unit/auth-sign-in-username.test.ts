/**
 * Better Auth's username sign-in only reaches an account by a username CPM
 * stored on purpose: the account's own email, or one an administrator set.
 * An email the login page refuses (here one with a '+') is never turned into
 * a username, so no account can sign in as a lookalike address such as
 * alice-cpm@example.com, which may be somebody else's.
 *
 * Like auth-password-policy-endpoints.test.ts, this boots the real db module
 * and the real auth-server (no better-auth stub) against a file-backed SQLite
 * database.
 */
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import bcrypt from 'bcryptjs';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CREDENTIAL_ACCOUNT_ISSUER } from '../../src/lib/account-issuer';

const workDir = mkdtempSync(join(tmpdir(), 'cpm-sign-in-username-'));
const PASSWORD = 'Correct-Horse-9!';
const OTHER_PASSWORD = 'Another-Horse-7!';

const globalForDb = globalThis as {
  __SQLITE_CLIENT__?: { close: () => void };
  __DRIZZLE_DB__?: unknown;
  __MIGRATIONS_RAN__?: boolean;
};

function resetGlobals() {
  globalForDb.__SQLITE_CLIENT__?.close();
  delete globalForDb.__SQLITE_CLIENT__;
  delete globalForDb.__DRIZZLE_DB__;
  delete globalForDb.__MIGRATIONS_RAN__;
}

type App = {
  db: Awaited<typeof import('../../src/lib/db')>['default'];
  schema: typeof import('../../src/lib/db/schema');
  auth: ReturnType<Awaited<typeof import('../../src/lib/auth-server')>['getAuth']>;
  userModel: typeof import('../../src/lib/models/user');
};
let app: App;

beforeAll(async () => {
  process.env.DATABASE_URL = `file:${join(workDir, 'app.db')}`;
  // Vitest leaks Vite's BASE_URL='/' into process.env, which better-auth rejects.
  process.env.BASE_URL = 'http://localhost:3000';
  process.env.AUTH_RATE_LIMIT_ENABLED = 'false';
  resetGlobals();
  vi.resetModules();

  const dbModule = await import('../../src/lib/db');
  const schema = await import('../../src/lib/db/schema');
  const { getAuth } = await import('../../src/lib/auth-server');
  const userModel = await import('../../src/lib/models/user');
  app = { db: dbModule.default, schema, auth: getAuth(), userModel };
});

afterAll(() => {
  resetGlobals();
  rmSync(workDir, { recursive: true, force: true });
  process.env.DATABASE_URL = ':memory:';
  delete process.env.AUTH_RATE_LIMIT_ENABLED;
  vi.resetModules();
});

async function signIn(username: string, password: string): Promise<string | undefined> {
  const signInUsername = (app.auth.api as unknown as Record<string, (args: { body: Record<string, unknown> }) => Promise<unknown>>)
    .signInUsername;
  const result = (await signInUsername({ body: { username, password } })) as { user?: { id?: string } };
  return result.user?.id;
}

/** signIn, or null when Better Auth rejects the attempt. */
async function trySignIn(username: string, password: string): Promise<string | null> {
  try {
    return (await signIn(username, password)) ?? null;
  } catch {
    return null;
  }
}

/** The way an OAuth sign-up provisions a user: no username, no password. */
async function seedOAuthUser(email: string) {
  const { db, schema } = app;
  const now = new Date().toISOString();
  const [user] = await db.insert(schema.users).values({
    email,
    name: null,
    role: 'user',
    status: 'active',
    provider: 'dex',
    subject: `dex-${email}`,
    emailVerified: false,
    createdAt: now,
    updatedAt: now,
  }).returning();
  return user;
}

/**
 * A credential-only account as older releases created it: the email, here
 * plus-addressed, copied as the username.
 */
async function seedLegacyCredentialUser(email: string) {
  const { db, schema } = app;
  const now = new Date().toISOString();
  const hash = bcrypt.hashSync(PASSWORD, 4);
  const [user] = await db.insert(schema.users).values({
    email,
    username: email,
    displayUsername: email.split('@')[0],
    name: null,
    passwordHash: hash,
    role: 'user',
    status: 'active',
    provider: 'credentials',
    subject: email,
    emailVerified: false,
    createdAt: now,
    updatedAt: now,
  }).returning();
  await db.insert(schema.accounts).values({
    userId: user.id,
    issuer: CREDENTIAL_ACCOUNT_ISSUER,
    accountId: String(user.id),
    providerId: 'credential',
    password: hash,
    createdAt: now,
    updatedAt: now,
  });
  return user;
}

describe('sign-in usernames', () => {
  it('gives a plus-addressed OAuth user who sets a password no username made from their email', async () => {
    const user = await seedOAuthUser('dex+cpm@example.com');

    await app.userModel.changeUserPassword(user.id, bcrypt.hashSync(PASSWORD, 4), null);

    expect(await app.userModel.getPasswordSignInStatus(user.id)).toEqual({ username: null, blocker: 'no-username' });
    expect(await trySignIn('dex-cpm@example.com', PASSWORD)).toBeNull();
    expect(await trySignIn('dex+cpm@example.com', PASSWORD)).toBeNull();
  });

  it('does not let an account sign in as an address derived from its email', async () => {
    // Formerly this account became alice-x@example.com, and the real owner of
    // that address got alice-x-2@example.com.
    const squatter = await seedOAuthUser('alice+x@example.com');
    await app.userModel.changeUserPassword(squatter.id, bcrypt.hashSync(PASSWORD, 4), null);

    const owner = await app.userModel.createUser({
      email: 'alice-x@example.com',
      provider: 'credentials',
      subject: 'alice-x@example.com',
      passwordHash: bcrypt.hashSync(OTHER_PASSWORD, 4),
    });

    expect(owner.username).toBe('alice-x@example.com');
    expect(await signIn('alice-x@example.com', OTHER_PASSWORD)).toBe(String(owner.id));
    expect(await trySignIn('alice-x@example.com', PASSWORD)).toBeNull();
    expect(await trySignIn('alice-x-2@example.com', OTHER_PASSWORD)).toBeNull();
  });

  it('gives a plus-addressed user an administrator created no username', async () => {
    const user = await app.userModel.createUser({
      email: 'carol+cpm@example.com',
      provider: 'credentials',
      subject: 'carol+cpm@example.com',
      passwordHash: bcrypt.hashSync(PASSWORD, 4),
    });

    expect(user.username).toBeNull();
    expect(await trySignIn('carol-cpm@example.com', PASSWORD)).toBeNull();
  });

  it('leaves a legacy plus-addressed username alone when an administrator edits the profile', async () => {
    const user = await seedLegacyCredentialUser('fay+cpm@example.com');

    await app.userModel.updateUserProfile(user.id, { name: 'Fay', email: 'fay@example.com' });

    expect((await app.userModel.getUserById(user.id))?.username).toBe('fay+cpm@example.com');
    expect(await trySignIn('fay-cpm@example.com', PASSWORD)).toBeNull();
    expect(await trySignIn('fay@example.com', PASSWORD)).toBeNull();
  });

  it('signs in a legacy plus-addressed user with the username an administrator set, in any case', async () => {
    const user = await seedLegacyCredentialUser('erin+cpm@example.com');
    expect(await trySignIn('erin+cpm@example.com', PASSWORD)).toBeNull();
    expect(await trySignIn('erin-cpm@example.com', PASSWORD)).toBeNull();

    await app.userModel.setUserSignInUsername(user.id, 'erin');

    expect(await signIn('erin', PASSWORD)).toBe(String(user.id));
    expect(await signIn('ERIN', PASSWORD)).toBe(String(user.id));
    expect(await trySignIn('erin-cpm@example.com', PASSWORD)).toBeNull();
  });
});

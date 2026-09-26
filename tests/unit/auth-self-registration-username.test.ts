/**
 * Accounts Better Auth creates follow the same sign-in name rules as the rest
 * of CPM. With AUTH_ALLOW_SELF_REGISTRATION=true, a registrant cannot choose
 * a username (not another account's email, nor another case of an
 * administrator-set name): the account gets its own email address as username
 * when it qualifies, and none otherwise. A registration or OAuth sign-up whose
 * email address another account signs in with is refused.
 *
 * Like auth-password-policy-endpoints.test.ts, this boots the real db module
 * and the real auth-server (no better-auth stub) against a file-backed SQLite
 * database, so the hooks run exactly as they do in production.
 */
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import bcrypt from 'bcryptjs';
import { eq } from 'drizzle-orm';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const workDir = mkdtempSync(join(tmpdir(), 'cpm-self-registration-username-'));
const APP_BASE_URL = 'http://localhost:3000';
const PASSWORD = 'Strong-Password-2026!';
const VICTIM_PASSWORD = 'Victim-Password-2026!';

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
  process.env.BASE_URL = APP_BASE_URL;
  process.env.AUTH_ALLOW_SELF_REGISTRATION = 'true';
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
  delete process.env.AUTH_ALLOW_SELF_REGISTRATION;
  delete process.env.AUTH_RATE_LIMIT_ENABLED;
  vi.resetModules();
});

type ApiCall = (args: { body: Record<string, unknown> }) => Promise<unknown>;
const api = (name: string) => (app.auth.api as unknown as Record<string, ApiCall>)[name];

type SignedUp = { user?: { id?: string; email?: string; username?: string | null } };

function signUp(body: Record<string, unknown>): Promise<SignedUp> {
  return api('signUpEmail')({ body: { password: PASSWORD, name: 'Someone', ...body } }) as Promise<SignedUp>;
}

/** The APIError a Better Auth API call rejects with. */
async function apiError(call: Promise<unknown>) {
  const error = await call.then(
    () => { throw new Error('expected the call to be rejected'); },
    (e: unknown) => e as { statusCode?: number; message?: string; body?: { message?: string } }
  );
  return { statusCode: error.statusCode, message: error.body?.message ?? error.message };
}

/** The user id Better Auth's username sign-in reaches, or null when it refuses. */
async function signIn(username: string, password: string): Promise<string | null> {
  try {
    const result = (await api('signInUsername')({ body: { username, password } })) as { user?: { id?: string } };
    return result.user?.id ?? null;
  } catch {
    return null;
  }
}

function storedUsername(userId: number | string) {
  const { db, schema } = app;
  return db.select({ username: schema.users.username, displayUsername: schema.users.displayUsername })
    .from(schema.users).where(eq(schema.users.id, Number(userId))).get();
}

function userCount(email: string) {
  const { db, schema } = app;
  return db.select().from(schema.users).where(eq(schema.users.email, email)).all().length;
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

describe('self-registration usernames', () => {
  it("does not store another account's email address as the registrant's username", async () => {
    const victim = await seedOAuthUser('victim@example.com');

    const attacker = await signUp({ email: 'attacker@evil.example.com', username: 'victim@example.com' });

    expect(attacker.user?.username).toBe('attacker@evil.example.com');
    expect(storedUsername(attacker.user!.id!)?.username).toBe('attacker@evil.example.com');

    // The victim's own address stays theirs to sign in with.
    await app.userModel.changeUserPassword(victim.id, bcrypt.hashSync(VICTIM_PASSWORD, 4), null);
    expect(await app.userModel.getPasswordSignInStatus(victim.id))
      .toEqual({ username: 'victim@example.com', blocker: null });
    expect(await signIn('victim@example.com', VICTIM_PASSWORD)).toBe(String(victim.id));
    expect(await signIn('victim@example.com', PASSWORD)).toBeNull();
    expect(await signIn('attacker@evil.example.com', PASSWORD)).toBe(attacker.user?.id);
  });

  it('ignores a chosen username or display username, in any case', async () => {
    const bob = await app.userModel.createUser({
      email: 'bob@example.com', provider: 'credentials', subject: 'bob', username: 'bob',
      passwordHash: bcrypt.hashSync(VICTIM_PASSWORD, 4),
    });

    const upper = await signUp({ email: 'mallory@example.com', username: 'BOB@example.com' });
    const display = await signUp({ email: 'trudy@example.com', displayUsername: 'Bob' });

    expect(storedUsername(upper.user!.id!)).toEqual({ username: 'mallory@example.com', displayUsername: 'mallory@example.com' });
    expect(storedUsername(display.user!.id!)).toEqual({ username: 'trudy@example.com', displayUsername: 'trudy@example.com' });
    expect(await signIn('bob@example.com', PASSWORD)).toBeNull();
    expect(await signIn('bob', PASSWORD)).toBeNull();
    expect(await signIn('bob', VICTIM_PASSWORD)).toBe(String(bob.id));
  });

  it('signs a registrant in with their own email address, in any case', async () => {
    const dave = await signUp({ email: 'Dave@Example.com' });

    expect(dave.user?.username).toBe('dave@example.com');
    expect(await signIn('dave@example.com', PASSWORD)).toBe(dave.user?.id);
    expect(await signIn('DAVE@example.com', PASSWORD)).toBe(dave.user?.id);
  });

  it('gives a registrant whose email the login page refuses no username', async () => {
    const carol = await signUp({ email: 'carol+x@example.com', username: 'carol-x@example.com' });

    expect(carol.user?.username).toBeNull();
    expect(await app.userModel.getPasswordSignInStatus(Number(carol.user?.id)))
      .toEqual({ username: null, blocker: 'no-username' });
    expect(await signIn('carol-x@example.com', PASSWORD)).toBeNull();
  });

  it('refuses a registration whose email address another account signs in with', async () => {
    await app.userModel.createUser({ email: 'anna@example.com', provider: 'credentials', subject: 'anna', username: 'boss@example.com' });

    const boss = await apiError(signUp({ email: 'Boss@Example.com' }));

    expect(boss).toEqual({ statusCode: 400, message: 'Another account signs in with this email address as its username' });
    expect(userCount('boss@example.com')).toBe(0);
  });

  it('refuses the same over HTTP and does not say whether a requested username is taken', async () => {
    await app.userModel.createUser({ email: 'owen@example.com', provider: 'credentials', subject: 'owen', username: 'owen' });
    const post = (body: Record<string, unknown>) => app.auth.handler(new Request(`${APP_BASE_URL}/api/auth/sign-up/email`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: APP_BASE_URL },
      body: JSON.stringify({ password: PASSWORD, name: 'Someone', ...body }),
    }));

    // A requested name that is taken gets no "Username is already taken" answer.
    const taken = await post({ email: 'olivia@example.com', username: 'owen' });
    expect(taken.status).toBe(200);
    expect((await taken.json()).user.username).toBe('olivia@example.com');

    await app.userModel.createUser({ email: 'pat@example.com', provider: 'credentials', subject: 'pat', username: 'boss2@example.com' });
    const conflict = await post({ email: 'boss2@example.com' });
    expect(conflict.status).toBe(400);
    expect((await conflict.json()).message).toBe('Another account signs in with this email address as its username');
  });
});

describe('accounts Better Auth creates outside self-registration (OAuth sign-up)', () => {
  type InternalAdapter = { createUser: (user: Record<string, unknown>) => Promise<{ id: string | number }> };
  async function internalAdapter(): Promise<InternalAdapter> {
    return ((await app.auth.$context) as unknown as { internalAdapter: InternalAdapter }).internalAdapter;
  }

  it('stores no username, whatever the profile carried', async () => {
    await seedOAuthUser('owner@example.com');

    const created = await (await internalAdapter()).createUser({
      email: 'idp-user@example.com', name: 'IdP User', emailVerified: false, username: 'owner@example.com',
    });

    expect(storedUsername(created.id)?.username).toBeNull();
  });

  it('refuses an email address another account signs in with', async () => {
    await app.userModel.createUser({ email: 'zed@example.com', provider: 'credentials', subject: 'zed', username: 'chief@example.com' });
    await app.userModel.createUser({ email: 'erin@example.com', provider: 'credentials', subject: 'erin', username: 'ops' });
    const adapter = await internalAdapter();

    await expect(adapter.createUser({ email: 'chief@example.com', name: 'Chief', emailVerified: false }))
      .rejects.toThrow('Another account signs in with this email address as its username');
    // The forward-auth portal would read "ops" as ops@localhost.
    await expect(adapter.createUser({ email: 'ops@localhost', name: 'Ops', emailVerified: false }))
      .rejects.toThrow('Another account signs in with the name before @localhost as its username');
    expect(userCount('chief@example.com')).toBe(0);
    expect(userCount('ops@localhost')).toBe(0);
  });
});

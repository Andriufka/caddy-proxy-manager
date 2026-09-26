/**
 * Integration tests for password storage on user accounts against a real
 * (in-memory) database:
 *
 *  - setting a password keeps users.passwordHash and the Better Auth
 *    credential account in step, creating the credential account for an
 *    OAuth-only user (the login page checks only that account);
 *  - the only username CPM gives an account by itself is the account's own
 *    email, lowercased, when the login page accepts it and no other account
 *    has it as username or email. Nothing is made up from an email: no
 *    replaced characters, no numbered variants; otherwise the username stays
 *    empty (or as it was) and the profile page reports "no-username";
 *  - createUser applies the same rule and checks an explicit username, and
 *    refuses an email address another account has or signs in with, or one
 *    that lowercasing turns into another address;
 *  - profile edits never change a username and refuse such an email address;
 *    administrators set a username with setUserSignInUsername, which must not
 *    be another account's username, email address or forward-auth portal
 *    name;
 *  - changeUserPassword ends the user's other sign-ins in the same
 *    transaction as the password write;
 *  - "has a password" counts a hash stored only on the credential account
 *    (Better Auth self-registration) in the change-password route;
 *  - unlink-oauth only goes ahead when the login page can still sign the
 *    user in: a username plus a password on the credential account, and the
 *    profile page gets the reason when it cannot.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
import bcrypt from 'bcryptjs';
import { and, eq, sql } from 'drizzle-orm';
import { createTestDb, type TestDb } from '../helpers/db';
import { accounts, forwardAuthSessions, proxyHosts, sessions, users } from '@/src/lib/db/schema';
import { CREDENTIAL_ACCOUNT_ISSUER } from '@/src/lib/account-issuer';

let db: TestDb;

vi.mock('@/src/lib/db', () => ({
  get default() { return db; },
  get sqlite() { return undefined; },
  nowIso: () => new Date().toISOString(),
  toIso: (value: string | Date | null | undefined): string | null => {
    if (!value) return null;
    return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
  },
}));

const caller = vi.hoisted(() => ({ userId: 0, sessionId: null as number | null, sessionCreatedAt: new Date() }));
vi.mock('@/src/lib/auth', () => ({
  auth: vi.fn(async () => ({ user: { id: String(caller.userId), role: 'user' } })),
  checkSameOrigin: vi.fn(() => null),
  getCurrentSessionInfo: vi.fn(async () =>
    caller.sessionId === null ? null : { id: caller.sessionId, createdAt: caller.sessionCreatedAt }
  ),
}));

import {
  SignInUsernameError,
  changeUserPassword,
  createUser,
  getPasswordSignInStatus,
  getPasswordSignInUsername,
  getUserById,
  getUserPasswordHash,
  setUserSignInUsername,
  updateUserAccount,
  updateUserProfile,
} from '@/src/lib/models/user';
import { SIGN_IN_USERNAME_RULES_MESSAGE } from '@/src/lib/login-username';
import { SIGN_IN_NAME_TAKEN_MESSAGE } from '@/src/lib/sign-in-names';
import { ApiValidationError } from '@/src/lib/api-errors';
import { POST as changePassword } from '@/app/api/user/change-password/route';
import { POST as unlinkOAuth } from '@/app/api/user/unlink-oauth/route';
import { POST as updateAvatar } from '@/app/api/user/update-avatar/route';

const NOW = '2026-02-01T00:00:00.000Z';
const FUTURE = '2099-01-01T00:00:00.000Z';
const PASSWORD = 'Correct-Horse-9!';

async function seedUser(
  email: string,
  passwordHash: string | null = null,
  username: string | null = email
) {
  const [row] = await db.insert(users).values({
    email,
    username,
    name: email,
    role: 'user',
    provider: 'dex',
    subject: `sub-${email}`,
    passwordHash,
    status: 'active',
    createdAt: NOW,
    updatedAt: NOW,
  }).returning();
  return row.id;
}

async function seedOAuthAccount(userId: number) {
  await db.insert(accounts).values({
    userId,
    issuer: 'https://dex.example.com',
    accountId: `dex-${userId}`,
    providerId: 'dex',
    createdAt: NOW,
    updatedAt: NOW,
  });
}

async function seedCredentialAccount(userId: number, password: string | null) {
  await db.insert(accounts).values({
    userId,
    issuer: CREDENTIAL_ACCOUNT_ISSUER,
    accountId: String(userId),
    providerId: 'credential',
    password,
    createdAt: NOW,
    updatedAt: NOW,
  });
}

async function seedSession(id: number, userId: number) {
  await db.insert(sessions).values({
    id, userId, token: `tok-${id}`, expiresAt: FUTURE, createdAt: NOW, updatedAt: NOW,
  });
}

async function seedForwardAuthSession(userId: number) {
  const [host] = await db.insert(proxyHosts).values({
    name: `host-${userId}`,
    domains: JSON.stringify([`app${userId}.example.com`]),
    upstreams: JSON.stringify(['127.0.0.1:8080']),
    createdAt: NOW,
    updatedAt: NOW,
  }).returning();
  await db.insert(forwardAuthSessions).values({
    userId,
    proxyHostId: host.id,
    audienceOrigin: `https://app${userId}.example.com`,
    tokenHash: `hash-${userId}`,
    expiresAt: FUTURE,
    createdAt: NOW,
  });
}

function signInColumns(userId: number) {
  return db.select({ username: users.username, displayUsername: users.displayUsername })
    .from(users).where(eq(users.id, userId)).get();
}

function credentialRows(userId: number) {
  return db.select().from(accounts)
    .where(and(eq(accounts.userId, userId), eq(accounts.providerId, 'credential')))
    .all();
}

function post(path: string, body: Record<string, unknown> = {}) {
  return new NextRequest(`http://localhost:3000${path}`, {
    method: 'POST',
    headers: { origin: 'http://localhost:3000', 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

beforeEach(() => {
  db = createTestDb();
  caller.sessionId = null;
  caller.sessionCreatedAt = new Date();
});

describe('changeUserPassword', () => {
  it('creates the credential account for an OAuth-only user', async () => {
    const userId = await seedUser('oauth@example.com');
    await seedOAuthAccount(userId);
    expect(credentialRows(userId)).toHaveLength(0);

    const hash = bcrypt.hashSync(PASSWORD, 4);
    await changeUserPassword(userId, hash, null);

    const [credential] = credentialRows(userId);
    expect(credential).toMatchObject({
      issuer: CREDENTIAL_ACCOUNT_ISSUER,
      accountId: String(userId),
      password: hash,
    });
    expect((await getUserById(userId))?.passwordHash).toBe(hash);
  });

  it('updates the existing credential account instead of adding another', async () => {
    const userId = await seedUser('local@example.com', 'old-hash');
    await seedCredentialAccount(userId, 'old-hash');

    await changeUserPassword(userId, 'new-hash', null);

    const rows = credentialRows(userId);
    expect(rows).toHaveLength(1);
    expect(rows[0].password).toBe('new-hash');
  });

  it('gives a user provisioned by OAuth sign-up their email as username', async () => {
    const userId = await seedUser('Dex.User@example.com', null, null);
    await seedOAuthAccount(userId);

    await changeUserPassword(userId, 'new-hash', null);

    expect(signInColumns(userId)).toEqual({
      username: 'dex.user@example.com',
      displayUsername: 'Dex.User@example.com',
    });
  });

  it('keeps an existing username and display name', async () => {
    const userId = await seedUser('alice@example.com', null, 'alice');
    db.update(users).set({ displayUsername: 'Alice A.' }).where(eq(users.id, userId)).run();

    await changeUserPassword(userId, 'new-hash', null);

    expect(signInColumns(userId)).toEqual({ username: 'alice', displayUsername: 'Alice A.' });
  });

  it('leaves the username empty when another account signs in with the email', async () => {
    const holder = await seedUser('holder@example.com', null, 'dexuser@example.com');
    const userId = await seedUser('dexuser@example.com', null, null);

    await changeUserPassword(userId, 'new-hash', null);

    // No numbered variant such as dexuser-2@example.com.
    expect(signInColumns(userId)?.username).toBeNull();
    expect(signInColumns(holder)?.username).toBe('dexuser@example.com');
    expect(credentialRows(userId)[0].password).toBe('new-hash');
    expect(await getPasswordSignInStatus(userId)).toEqual({ username: null, blocker: 'no-username' });
  });

  it('treats a username or email held in another case as taken', async () => {
    await seedUser('holder@example.com', null, 'DexUser@Example.com');
    const first = await seedUser('dexuser@example.com', null, null);
    await seedUser('Carol@Example.com', null, null);
    const second = await seedUser('carol@example.com', null, null);

    await changeUserPassword(first, 'new-hash', null);
    await changeUserPassword(second, 'new-hash', null);

    expect(signInColumns(first)?.username).toBeNull();
    expect(signInColumns(second)?.username).toBeNull();
  });

  it('never makes a username from an email the login page refuses', async () => {
    const userId = await seedUser('Dex+Tag@example.com', null, null);

    await changeUserPassword(userId, 'new-hash', null);

    // Not dex-tag@example.com, which can be somebody else's address.
    expect(signInColumns(userId)).toEqual({ username: null, displayUsername: null });
    expect(credentialRows(userId)[0].password).toBe('new-hash');
    expect(await getPasswordSignInUsername(userId)).toBeNull();
    expect(await getPasswordSignInStatus(userId)).toEqual({ username: null, blocker: 'no-username' });
    expect(db.select().from(users).where(eq(users.username, 'dex-tag@example.com')).all()).toEqual([]);
  });

  it('does not fold a look-alike character in a stored email into another address', async () => {
    // createUser refuses such an address (see below); older rows can hold one.
    const userId = await seedUser('\u212Aate@example.com', null, null);

    await changeUserPassword(userId, 'new-hash', null);

    // '\u212A'.toLowerCase() is 'k', which would make kate@example.com.
    expect(signInColumns(userId)?.username).toBeNull();
  });

  it("does not give an account a username that is another account's forward-auth portal name", async () => {
    // The portal reads "ops" as ops@localhost.
    await seedUser('ops@localhost', null, 'ops@localhost');
    const userId = await seedUser('ops', null, null);

    await changeUserPassword(userId, 'new-hash', null);

    expect(signInColumns(userId)?.username).toBeNull();
  });

  it('keeps a stored username the login page cannot find unless the email itself can replace it', async () => {
    // Older releases copied the email as it was.
    const plus = await seedUser('alice+cpm@example.com', 'old-hash', 'alice+cpm@example.com');
    await seedCredentialAccount(plus, 'old-hash');
    await seedOAuthAccount(plus);
    const upper = await seedUser('bob@example.com', 'old-hash', 'Bob');
    await seedCredentialAccount(upper, 'old-hash');
    expect(await getPasswordSignInUsername(plus)).toBeNull();
    expect(await getPasswordSignInUsername(upper)).toBeNull();

    await changeUserPassword(plus, 'new-hash', null);
    await changeUserPassword(upper, 'new-hash', null);

    expect(signInColumns(plus)?.username).toBe('alice+cpm@example.com');
    expect(await getPasswordSignInStatus(plus)).toEqual({ username: null, blocker: 'no-username' });
    expect(await getPasswordSignInUsername(upper)).toBe('bob@example.com');
  });

  it('ends the other sessions and all forward-auth sessions, keeping the given one', async () => {
    const userId = await seedUser('alice@example.com', 'old-hash');
    const otherId = await seedUser('bob@example.com', 'bob-hash');
    await seedCredentialAccount(userId, 'old-hash');
    await seedSession(10, userId);
    await seedSession(11, userId);
    await seedSession(20, otherId);
    await seedForwardAuthSession(userId);
    await seedForwardAuthSession(otherId);

    await changeUserPassword(userId, 'new-hash', 10);

    expect(credentialRows(userId)[0].password).toBe('new-hash');
    const remaining = db.select({ id: sessions.id }).from(sessions).all().map((r) => r.id).sort();
    expect(remaining).toEqual([10, 20]);
    const faOwners = db.select({ userId: forwardAuthSessions.userId }).from(forwardAuthSessions).all();
    expect(faOwners).toEqual([{ userId: otherId }]);
  });

  it('leaves the password unchanged when revoking the sessions fails', async () => {
    const userId = await seedUser('alice@example.com', 'old-hash');
    await seedCredentialAccount(userId, 'old-hash');
    await seedSession(10, userId);
    // Make the forward-auth delete fail inside the transaction.
    db.run(sql`DROP TABLE forward_auth_exchanges`);
    db.run(sql`DROP TABLE forward_auth_sessions`);

    await expect(changeUserPassword(userId, 'new-hash', null)).rejects.toThrow();

    expect((await getUserById(userId))?.passwordHash).toBe('old-hash');
    expect(credentialRows(userId)[0].password).toBe('old-hash');
    expect(db.select().from(sessions).all()).toHaveLength(1);
  });
});

describe('createUser', () => {
  it('uses the lowercased email as username when the login page accepts it', async () => {
    const user = await createUser({ email: 'Carol@Example.com', provider: 'credentials', subject: 'carol', passwordHash: 'h' });
    expect(signInColumns(user.id)?.username).toBe('carol@example.com');
    expect(user.username).toBe('carol@example.com');
    expect(await getPasswordSignInUsername(user.id)).toBe('carol@example.com');
  });

  it('gives a plus-addressed email no username', async () => {
    const user = await createUser({ email: 'carol+cpm@example.com', provider: 'credentials', subject: 'carol', passwordHash: 'h' });
    expect(user.username).toBeNull();
    expect(signInColumns(user.id)?.username).toBeNull();
    expect(await getPasswordSignInStatus(user.id)).toEqual({ username: null, blocker: 'no-username' });
  });

  it.each(['+alice@example.com', 'alice@example.com+', 'j\u00f6hn@example.com', 'a b@example.com', '"a"@b'])(
    'gives %s no username',
    async (email) => {
      const user = await createUser({ email, provider: 'credentials', subject: email, passwordHash: 'h' });
      expect(user.username).toBeNull();
    }
  );

  it('refuses an email that lowercasing turns into another address, instead of storing that one', async () => {
    for (const email of ['\u212Aate@example.com', 'K\u212Aate@example.com', '\u0130van@example.com']) {
      const attempt = createUser({ email, provider: 'credentials', subject: email, passwordHash: 'h' });
      await expect(attempt).rejects.toThrow(ApiValidationError);
      await expect(attempt).rejects.toThrow(/Kelvin sign/);
    }
    expect(db.select().from(users).all()).toEqual([]);

    // The same account created with plain letters, then given a password.
    const user = await createUser({ email: 'Kate@example.com', provider: 'credentials', subject: 'kate' });
    await changeUserPassword(user.id, 'new-hash', null);
    expect((await getUserById(user.id))).toMatchObject({ email: 'kate@example.com', username: 'kate@example.com' });
  });

  it('refuses an email address another account has or signs in with, instead of numbering a username', async () => {
    await seedUser('holder@example.com', null, 'carol@example.com');
    await seedUser('Dora@Example.com', null, null);
    await seedUser('erin@example.com', null, 'ops');
    for (const [email, message] of [
      ['carol@example.com', 'Another account signs in with this email address as its username'],
      ['dora@example.com', 'A user with this email already exists'],
      ['Ops@localhost', 'Another account signs in with the name before @localhost as its username'],
    ]) {
      const attempt = createUser({ email, provider: 'credentials', subject: email, passwordHash: 'h' });
      await expect(attempt).rejects.toThrow(ApiValidationError);
      await expect(attempt).rejects.toThrow(message);
    }
    expect(db.select().from(users).all()).toHaveLength(3);
    expect(db.select().from(accounts).all()).toEqual([]);
  });

  it('leaves a plain address to its owner when a similar one was created first', async () => {
    const plus = await createUser({ email: '+alice@example.com', provider: 'credentials', subject: 'a1', passwordHash: 'h' });
    const owner = await createUser({ email: 'alice@example.com', provider: 'credentials', subject: 'a2', passwordHash: 'h' });
    expect(plus.username).toBeNull();
    expect(owner.username).toBe('alice@example.com');
  });

  it('keeps an explicit username, trimmed', async () => {
    const user = await createUser({ email: 'dave@example.com', provider: 'credentials', subject: 'dave', username: ' admin ' });
    expect(signInColumns(user.id)?.username).toBe('admin');
  });

  it('refuses an explicit username the login page cannot use or another account holds', async () => {
    await seedUser('Taken@Example.com', null, 'erin');
    for (const [username, message] of [
      ['Dave', SIGN_IN_USERNAME_RULES_MESSAGE],
      ['dave+x@example.com', SIGN_IN_USERNAME_RULES_MESSAGE],
      ['', SIGN_IN_USERNAME_RULES_MESSAGE],
      ['ERIN', SIGN_IN_USERNAME_RULES_MESSAGE],
      ['erin', SIGN_IN_NAME_TAKEN_MESSAGE],
      ['taken@example.com', SIGN_IN_NAME_TAKEN_MESSAGE],
    ]) {
      const attempt = createUser({ email: 'dave@example.com', provider: 'credentials', subject: 'dave', passwordHash: 'h', username });
      await expect(attempt).rejects.toThrow(SignInUsernameError);
      await expect(attempt).rejects.toThrow(message);
    }
    expect(db.select().from(users).where(eq(users.email, 'dave@example.com')).all()).toEqual([]);
    expect(db.select().from(accounts).all()).toEqual([]);
  });
});

describe('getUserPasswordHash', () => {
  it('reads users.passwordHash, then the credential account, else null', async () => {
    const local = await seedUser('local@example.com', 'users-hash');
    const selfRegistered = await seedUser('self@example.com');
    await seedCredentialAccount(selfRegistered, 'account-hash');
    const oauthOnly = await seedUser('oauth@example.com');
    await seedOAuthAccount(oauthOnly);
    const emptyCredential = await seedUser('empty@example.com');
    await seedCredentialAccount(emptyCredential, null);

    expect(await getUserPasswordHash((await getUserById(local))!)).toBe('users-hash');
    expect(await getUserPasswordHash((await getUserById(selfRegistered))!)).toBe('account-hash');
    expect(await getUserPasswordHash((await getUserById(oauthOnly))!)).toBeNull();
    expect(await getUserPasswordHash((await getUserById(emptyCredential))!)).toBeNull();
  });
});

describe('getPasswordSignInUsername', () => {
  it('needs a login-page username and a password on the credential account', async () => {
    const local = await seedUser('local@example.com', 'users-hash');
    await seedCredentialAccount(local, 'users-hash');
    // Set a password before the credential account was kept in step.
    const legacy = await seedUser('legacy@example.com', 'users-hash');
    const noUsername = await seedUser('self@example.com', null, null);
    await seedCredentialAccount(noUsername, 'account-hash');
    const badUsername = await seedUser('bad@example.com', null, 'bad name');
    await seedCredentialAccount(badUsername, 'account-hash');
    const emptyCredential = await seedUser('empty@example.com');
    await seedCredentialAccount(emptyCredential, null);

    expect(await getPasswordSignInUsername(local)).toBe('local@example.com');
    expect(await getPasswordSignInUsername(legacy)).toBeNull();
    expect(await getPasswordSignInUsername(noUsername)).toBeNull();
    expect(await getPasswordSignInUsername(badUsername)).toBeNull();
    expect(await getPasswordSignInUsername(emptyCredential)).toBeNull();
  });
});

describe('getPasswordSignInStatus', () => {
  it('returns the username when the login page can sign the user in', async () => {
    const userId = await seedUser('local@example.com', 'hash');
    await seedCredentialAccount(userId, 'hash');
    expect(await getPasswordSignInStatus(userId)).toEqual({ username: 'local@example.com', blocker: null });
  });

  it('reports no-credential when setting or changing the password fixes it', async () => {
    const oauthOnly = await seedUser('oauth@example.com', null, null);
    await seedOAuthAccount(oauthOnly);
    const legacy = await seedUser('legacy@example.com', 'users-hash');
    const upper = await seedUser('bob@example.com', null, 'Bob');
    await seedCredentialAccount(upper, 'hash');

    for (const userId of [oauthOnly, legacy, upper]) {
      expect(await getPasswordSignInStatus(userId)).toEqual({ username: null, blocker: 'no-credential' });
      await changeUserPassword(userId, 'new-hash', null);
      expect((await getPasswordSignInStatus(userId)).blocker).toBeNull();
    }
  });

  it('reports no-username until an administrator sets one', async () => {
    const userId = await seedUser('dex+tag@example.com', null, null);
    await seedOAuthAccount(userId);
    expect(await getPasswordSignInStatus(userId)).toEqual({ username: null, blocker: 'no-username' });

    await changeUserPassword(userId, 'new-hash', null);
    expect(signInColumns(userId)?.username).toBeNull();
    expect(await getPasswordSignInStatus(userId)).toEqual({ username: null, blocker: 'no-username' });

    // A new email address gives no username by itself.
    await updateUserProfile(userId, { email: 'dex@example.com' });
    expect(signInColumns(userId)?.username).toBeNull();

    await setUserSignInUsername(userId, 'dex');
    expect(await getPasswordSignInStatus(userId)).toEqual({ username: 'dex', blocker: null });
  });

  it('reports no-username when another account has the email as username', async () => {
    await seedUser('holder@example.com', null, 'dex@example.com');
    const userId = await seedUser('dex@example.com', null, null);
    await seedOAuthAccount(userId);
    expect(await getPasswordSignInStatus(userId)).toEqual({ username: null, blocker: 'no-username' });
  });
});

describe('password routes against the database', () => {
  it('lets an OAuth-only user set a password that the credential login can use', async () => {
    const userId = await seedUser('oauth@example.com', null, null);
    await seedOAuthAccount(userId);
    caller.userId = userId;
    caller.sessionId = 10;
    await seedSession(10, userId);

    const res = await changePassword(post('/api/user/change-password', { newPassword: PASSWORD }));
    expect(res.status).toBe(200);

    const [credential] = credentialRows(userId);
    expect(credential?.password).toBeTruthy();
    expect(await bcrypt.compare(PASSWORD, credential!.password!)).toBe(true);
    expect(await getPasswordSignInUsername(userId)).toBe('oauth@example.com');

    // With a working password sign-in, OAuth can now be unlinked.
    const unlinked = await unlinkOAuth(post('/api/user/unlink-oauth'));
    expect(unlinked.status).toBe(200);
  });

  it('lets a plus-addressed OAuth-only user unlink OAuth only once an administrator set a username', async () => {
    const userId = await seedUser('alice+cpm@example.com', null, null);
    await seedOAuthAccount(userId);
    caller.userId = userId;
    caller.sessionId = 10;
    await seedSession(10, userId);

    const res = await changePassword(post('/api/user/change-password', { newPassword: PASSWORD }));
    expect(res.status).toBe(200);
    expect(signInColumns(userId)?.username).toBeNull();
    expect(await getPasswordSignInUsername(userId)).toBeNull();

    const refused = await unlinkOAuth(post('/api/user/unlink-oauth'));
    expect(refused.status).toBe(400);

    await setUserSignInUsername(userId, 'alice');
    const unlinked = await unlinkOAuth(post('/api/user/unlink-oauth'));
    expect(unlinked.status).toBe(200);
  });

  it('requires the current password of a self-registered user and syncs both copies', async () => {
    const userId = await seedUser('self@example.com');
    await seedCredentialAccount(userId, bcrypt.hashSync(PASSWORD, 4));
    caller.userId = userId;
    caller.sessionId = 10;
    await seedSession(10, userId);

    const withoutCurrent = await changePassword(post('/api/user/change-password', { newPassword: 'Another-Pass-2026!' }));
    expect(withoutCurrent.status).toBe(400);

    const res = await changePassword(post('/api/user/change-password', {
      currentPassword: PASSWORD,
      newPassword: 'Another-Pass-2026!',
    }));
    expect(res.status).toBe(200);
    const user = await getUserById(userId);
    expect(await bcrypt.compare('Another-Pass-2026!', user!.passwordHash!)).toBe(true);
    expect(credentialRows(userId)[0].password).toBe(user!.passwordHash);
  });

  it('lets a user whose password is only on the credential account unlink OAuth', async () => {
    const userId = await seedUser('self@example.com');
    await seedCredentialAccount(userId, bcrypt.hashSync(PASSWORD, 4));
    await seedOAuthAccount(userId);
    caller.userId = userId;

    const res = await unlinkOAuth(post('/api/user/unlink-oauth'));
    expect(res.status).toBe(200);
    const remaining = db.select({ providerId: accounts.providerId }).from(accounts)
      .where(eq(accounts.userId, userId)).all();
    expect(remaining).toEqual([{ providerId: 'credential' }]);
  });

  it('refuses to unlink when the password is not on the credential account', async () => {
    const userId = await seedUser('legacy@example.com', bcrypt.hashSync(PASSWORD, 4));
    await seedOAuthAccount(userId);
    caller.userId = userId;

    const res = await unlinkOAuth(post('/api/user/unlink-oauth'));
    expect(res.status).toBe(400);
    expect(db.select().from(accounts).where(eq(accounts.providerId, 'dex')).all()).toHaveLength(1);
  });

  it('refuses to unlink when the user has no username to sign in with', async () => {
    const userId = await seedUser('self@example.com', null, null);
    await seedCredentialAccount(userId, bcrypt.hashSync(PASSWORD, 4));
    await seedOAuthAccount(userId);
    caller.userId = userId;

    const res = await unlinkOAuth(post('/api/user/unlink-oauth'));
    expect(res.status).toBe(400);
    expect(db.select().from(accounts).where(eq(accounts.providerId, 'dex')).all()).toHaveLength(1);
  });

  it('refuses to unlink the only login method', async () => {
    const userId = await seedUser('oauth@example.com');
    await seedOAuthAccount(userId);
    await seedCredentialAccount(userId, null);
    caller.userId = userId;

    const res = await unlinkOAuth(post('/api/user/unlink-oauth'));
    expect(res.status).toBe(400);
    expect(db.select().from(accounts).where(eq(accounts.providerId, 'dex')).all()).toHaveLength(1);
  });
});

describe('updateUserProfile', () => {
  it('leaves a username the login page cannot find as it is', async () => {
    // Stored by older releases, which copied the email as it was.
    const userId = await seedUser('carol+cpm@example.com', 'hash', 'carol+cpm@example.com');
    await seedCredentialAccount(userId, 'hash');
    db.update(users).set({ displayUsername: 'carol+cpm' }).where(eq(users.id, userId)).run();

    const updated = await updateUserProfile(userId, { name: 'Carol' });

    expect(updated?.username).toBe('carol+cpm@example.com');
    expect(signInColumns(userId)).toEqual({ username: 'carol+cpm@example.com', displayUsername: 'carol+cpm' });
    expect(await getPasswordSignInUsername(userId)).toBeNull();
  });

  it('does not make a username from a new email', async () => {
    const plus = await seedUser('carol+cpm@example.com', 'hash', 'carol+cpm@example.com');
    await seedCredentialAccount(plus, 'hash');
    const empty = await seedUser('dex+tag@example.com', 'hash', null);
    await seedCredentialAccount(empty, 'hash');

    await updateUserProfile(plus, { email: 'carol@example.com' });
    await updateUserProfile(empty, { email: 'dex@example.com' });

    expect(signInColumns(plus)?.username).toBe('carol+cpm@example.com');
    expect(signInColumns(empty)?.username).toBeNull();
  });

  it("refuses a new email address another account has or signs in with, and changes nothing", async () => {
    await seedUser('anna@example.com', 'hash', 'boss@example.com');
    await seedUser('Dora@Example.com', null, null);
    await seedUser('erin@example.com', null, 'ops');
    const userId = await seedUser('ben@example.com', 'hash', 'ben@example.com');

    for (const [email, message] of [
      ['boss@example.com', 'Another account signs in with this email address as its username'],
      ['BOSS@example.com', 'Another account signs in with this email address as its username'],
      ['dora@example.com', 'A user with this email already exists'],
      ['ops@localhost', 'Another account signs in with the name before @localhost as its username'],
    ]) {
      const attempt = updateUserProfile(userId, { email, name: 'Changed' });
      await expect(attempt).rejects.toThrow(ApiValidationError);
      await expect(attempt).rejects.toThrow(message);
    }
    expect(await getUserById(userId)).toMatchObject({ email: 'ben@example.com', name: 'ben@example.com' });
  });

  it('allows a new case of the email address the user has', async () => {
    const userId = await seedUser('ben@example.com', 'hash', 'ben@example.com');
    expect((await updateUserProfile(userId, { email: 'Ben@Example.com' }))?.email).toBe('Ben@Example.com');
  });

  it('keeps a username that works when the email changes', async () => {
    const working = await seedUser('alice@example.com', 'hash', 'alice@example.com');
    await seedCredentialAccount(working, 'hash');

    await updateUserProfile(working, { email: 'alice.new@example.com' });

    expect(signInColumns(working)?.username).toBe('alice@example.com');
  });

  it('leaves the username alone when a user changes their avatar', async () => {
    const userId = await seedUser('erin+cpm@example.com', 'hash', 'erin+cpm@example.com');
    await seedCredentialAccount(userId, 'hash');
    const oauthOnly = await seedUser('fay+cpm@example.com', null, null);
    await seedOAuthAccount(oauthOnly);

    for (const id of [userId, oauthOnly]) {
      caller.userId = id;
      const res = await updateAvatar(post('/api/user/update-avatar', { avatarUrl: 'data:image/png;base64,AAAA' }));
      expect(res.status).toBe(200);
    }

    expect(signInColumns(userId)?.username).toBe('erin+cpm@example.com');
    expect(signInColumns(oauthOnly)?.username).toBeNull();
  });
});

describe('setUserSignInUsername', () => {
  it('sets the username and display username and returns the previous one', async () => {
    const userId = await seedUser('alice+cpm@example.com', 'hash', 'alice+cpm@example.com');
    await seedCredentialAccount(userId, 'hash');

    const result = await setUserSignInUsername(userId, '  alice.cpm  ');

    expect(result?.previousUsername).toBe('alice+cpm@example.com');
    expect(result?.user.username).toBe('alice.cpm');
    expect(signInColumns(userId)).toEqual({ username: 'alice.cpm', displayUsername: 'alice.cpm' });
    expect(await getPasswordSignInStatus(userId)).toEqual({ username: 'alice.cpm', blocker: null });
  });

  it.each(['', '  ', 'ab', 'Alice', 'alice+cpm@example.com', 'bad name', 'j\u00f6hn', 'a'.repeat(256)])(
    'refuses %j',
    async (username) => {
      const userId = await seedUser('alice@example.com', null, 'alice');
      const attempt = setUserSignInUsername(userId, username);
      await expect(attempt).rejects.toThrow(SignInUsernameError);
      await expect(attempt).rejects.toThrow(SIGN_IN_USERNAME_RULES_MESSAGE);
      expect(signInColumns(userId)?.username).toBe('alice');
    }
  );

  it("refuses another account's username, email or forward-auth portal name, whatever its case", async () => {
    await seedUser('Holder@Example.com', null, 'Holder');
    // The portal reads "ops" as ops@localhost.
    await seedUser('Ops@localhost', null, 'ops@localhost');
    const userId = await seedUser('alice@example.com', null, 'alice');

    for (const username of ['holder', 'holder@example.com', 'ops', 'ops@localhost']) {
      await expect(setUserSignInUsername(userId, username)).rejects.toThrow(SIGN_IN_NAME_TAKEN_MESSAGE);
    }
    expect(signInColumns(userId)?.username).toBe('alice');
  });

  it('allows the portal name of the account itself', async () => {
    const userId = await seedUser('ops@localhost', null, null);
    expect((await setUserSignInUsername(userId, 'ops'))?.user.username).toBe('ops');
  });

  it("allows the account's own email and current username", async () => {
    const userId = await seedUser('Alice@Example.com', null, 'alice');

    expect((await setUserSignInUsername(userId, 'alice'))?.user.username).toBe('alice');
    expect((await setUserSignInUsername(userId, 'alice@example.com'))?.user.username).toBe('alice@example.com');
  });

  it('returns null for a user that does not exist', async () => {
    expect(await setUserSignInUsername(999, 'nobody')).toBeNull();
  });
});

describe('updateUserAccount', () => {
  it('changes nothing when the username or the email address is refused', async () => {
    await seedUser('holder@example.com', null, 'holder');
    const userId = await seedUser('alice@example.com', null, 'alice');

    await expect(updateUserAccount(userId, { username: 'bob', email: 'holder@example.com', name: 'Changed' }))
      .rejects.toThrow('A user with this email already exists');
    await expect(updateUserAccount(userId, { username: 'holder', email: 'alice.new@example.com', name: 'Changed' }))
      .rejects.toThrow(SIGN_IN_NAME_TAKEN_MESSAGE);

    expect(await getUserById(userId)).toMatchObject({ username: 'alice', email: 'alice@example.com', name: 'alice@example.com' });
  });

  it('saves the other fields when the username is the one the user already has, even one the login page refuses', async () => {
    const userId = await seedUser('carol+cpm@example.com', null, 'carol+cpm@example.com');

    const result = await updateUserAccount(userId, { username: 'carol+cpm@example.com', name: 'Carol' });

    expect(result?.previousUsername).toBe('carol+cpm@example.com');
    expect(result?.user).toMatchObject({ username: 'carol+cpm@example.com', name: 'Carol' });
  });

  it('treats an empty username as no change for a user without one', async () => {
    const userId = await seedUser('dex+tag@example.com', null, null);
    const result = await updateUserAccount(userId, { username: '', name: 'Dex' });
    expect(result?.user).toMatchObject({ username: null, name: 'Dex' });
  });
});

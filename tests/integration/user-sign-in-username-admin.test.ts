/**
 * Administrators set a user's sign-in username explicitly, through
 * PUT /api/v1/users/{id}, POST /api/v1/users and the Users page edit dialog's
 * action, against a real (in-memory) database: the username must be one the
 * login page can find and not another account's username, email or
 * forward-auth portal name (400 or an inline error otherwise), the change is
 * audited, and nobody else can make it. A refused username or email address
 * leaves every other field of the request unchanged.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { eq } from 'drizzle-orm';
import { createTestDb, type TestDb } from '../helpers/db';
import { users } from '@/src/lib/db/schema';
import { logAuditEvent } from '@/src/lib/audit';

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

const caller = vi.hoisted(() => ({ userId: 1, role: 'admin' }));

vi.mock('@/src/lib/auth', () => ({
  auth: vi.fn(async () => ({ user: { id: String(caller.userId), role: caller.role } })),
  checkSameOrigin: vi.fn(() => null),
  requireAdmin: vi.fn(async () => {
    // The real requireAdmin redirects everyone else away.
    if (caller.role !== 'admin') throw new Error('NEXT_REDIRECT');
    return { user: { id: String(caller.userId), role: caller.role } };
  }),
}));
vi.mock('@/src/lib/api-auth', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/src/lib/api-auth')>();
  const result = () => ({ userId: caller.userId, role: caller.role, authMethod: 'bearer' as const });
  return {
    ...actual,
    requireApiUser: vi.fn(async () => result()),
    requireApiAdmin: vi.fn(async () => {
      if (caller.role !== 'admin') throw new actual.ApiAuthError('Administrator privileges required', 403);
      return result();
    }),
  };
});
vi.mock('next/cache', () => ({ revalidatePath: vi.fn() }));

import { POST as createUserRoute } from '@/app/api/v1/users/route';
import { PUT as updateUserRoute } from '@/app/api/v1/users/[id]/route';
import { updateUserInfoAction } from '@/app/(dashboard)/users/actions';
import { SIGN_IN_USERNAME_RULES_MESSAGE } from '@/src/lib/login-username';
import { SIGN_IN_NAME_TAKEN_MESSAGE } from '@/src/lib/sign-in-names';

const NOW = '2026-02-01T00:00:00.000Z';
const TAKEN = SIGN_IN_NAME_TAKEN_MESSAGE;

function seedUser(email: string, username: string | null, role = 'user') {
  return db.insert(users).values({
    email,
    username,
    displayUsername: username,
    name: null,
    role,
    provider: 'credentials',
    subject: email,
    status: 'active',
    createdAt: NOW,
    updatedAt: NOW,
  }).returning().get().id;
}

function stored(userId: number) {
  return db.select({
    username: users.username,
    displayUsername: users.displayUsername,
    role: users.role,
    status: users.status,
    name: users.name,
    email: users.email,
  }).from(users).where(eq(users.id, userId)).get();
}

/** The audit events written (tests/setup.vitest.ts replaces logAuditEvent with a mock). */
function auditRows() {
  return vi.mocked(logAuditEvent).mock.calls.map(([event]) => event);
}

function request(body: unknown): never {
  return { headers: { get: () => null }, json: async () => body } as never;
}

function put(userId: number, body: unknown) {
  return updateUserRoute(request(body), { params: Promise.resolve({ id: String(userId) }) });
}

let adminId: number;

beforeEach(() => {
  vi.mocked(logAuditEvent).mockClear();
  db = createTestDb();
  adminId = seedUser('admin@example.com', 'admin', 'admin');
  caller.userId = adminId;
  caller.role = 'admin';
});

describe('PUT /api/v1/users/{id} username', () => {
  it('sets the username, returns it and audits the change', async () => {
    const userId = seedUser('alice+cpm@example.com', 'alice+cpm@example.com');

    const res = await put(userId, { username: ' alice.cpm ' });

    expect(res.status).toBe(200);
    expect((await res.json()).username).toBe('alice.cpm');
    expect(stored(userId)).toMatchObject({ username: 'alice.cpm', displayUsername: 'alice.cpm' });
    const [event] = auditRows();
    expect(event).toMatchObject({ userId: adminId, action: 'update', entityType: 'user', entityId: userId });
    expect(event.summary).toContain('alice.cpm');
    expect(event.data).toEqual({ previousUsername: 'alice+cpm@example.com', username: 'alice.cpm' });
  });

  it.each([['Alice'], ['alice+cpm@example.com'], ['ab'], [''], ['bad name'], [42]])(
    'answers %j with 400 and changes nothing',
    async (username) => {
      const userId = seedUser('alice@example.com', 'alice');

      const res = await put(userId, { username, name: 'Changed', role: 'viewer' });

      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe(SIGN_IN_USERNAME_RULES_MESSAGE);
      expect(stored(userId)).toMatchObject({ username: 'alice', name: null, role: 'user' });
      expect(auditRows()).toEqual([]);
    }
  );

  it("answers another account's username, email or portal name, in any case, with 400", async () => {
    seedUser('Holder@Example.com', 'holder');
    // The forward-auth portal reads "ops" as ops@localhost.
    seedUser('Ops@localhost', 'ops@localhost');
    const userId = seedUser('alice@example.com', 'alice');

    for (const username of ['holder', 'holder@example.com', 'admin', 'admin@example.com', 'ops', 'ops@localhost']) {
      const res = await put(userId, { username });
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe(TAKEN);
    }
    expect(stored(userId)?.username).toBe('alice');
    expect(auditRows()).toEqual([]);
  });

  it('does not audit setting the username the user already has', async () => {
    const userId = seedUser('alice@example.com', 'alice');
    const res = await put(userId, { username: 'alice' });
    expect(res.status).toBe(200);
    expect(auditRows()).toEqual([]);
  });

  it('treats a null username as no change, as a GET body sent back carries it', async () => {
    const userId = seedUser('alice@example.com', 'alice');

    const res = await put(userId, { username: null, name: 'Changed' });

    expect(res.status).toBe(200);
    expect(stored(userId)).toMatchObject({ username: 'alice', name: 'Changed' });
  });

  it('answers 404 for a user that does not exist', async () => {
    const res = await put(999, { username: 'nobody' });
    expect(res.status).toBe(404);
  });

  it('refuses a caller who is not an administrator, including for their own account', async () => {
    const userId = seedUser('alice@example.com', 'alice');
    caller.userId = userId;
    caller.role = 'user';

    for (const target of [userId, adminId]) {
      const res = await put(target, { username: 'someone' });
      expect(res.status).toBe(403);
    }
    expect(stored(userId)?.username).toBe('alice');
    expect(stored(adminId)?.username).toBe('admin');
    expect(auditRows()).toEqual([]);
  });

  it('leaves the username alone when only the email changes', async () => {
    const userId = seedUser('alice+cpm@example.com', null);
    const res = await put(userId, { email: 'alice@example.com' });
    expect(res.status).toBe(200);
    expect(stored(userId)?.username).toBeNull();
  });

  it('answers an email address another account signs in with with 400 and changes nothing', async () => {
    seedUser('anna@example.com', 'boss@example.com');
    seedUser('erin@example.com', 'ops');
    const userId = seedUser('ben@example.com', 'ben');

    for (const email of ['boss@example.com', 'Boss@Example.com', 'ops@localhost']) {
      const res = await put(userId, { email, username: 'benjamin', name: 'Changed', role: 'viewer', status: 'disabled' });
      expect(res.status).toBe(400);
      expect((await res.json()).error).toMatch(/^Another account signs in with/);
    }
    expect(stored(userId)).toMatchObject({
      email: 'ben@example.com', username: 'ben', name: null, role: 'user', status: 'active',
    });
    expect(auditRows()).toEqual([]);
  });

  it("refuses a change to the caller's own role or status before changing the username", async () => {
    for (const body of [{ username: 'root', role: 'viewer' }, { username: 'root', status: 'disabled' }]) {
      const res = await put(adminId, body);
      expect(res.status).toBe(400);
    }
    expect(stored(adminId)).toMatchObject({ username: 'admin', role: 'admin', status: 'active' });
    expect(auditRows()).toEqual([]);
  });

  it('applies a valid username together with the other fields', async () => {
    const userId = seedUser('alice@example.com', 'alice');

    const res = await put(userId, { username: 'alice.a', name: 'Alice', role: 'viewer' });

    expect(res.status).toBe(200);
    expect(stored(userId)).toMatchObject({ username: 'alice.a', name: 'Alice', role: 'viewer' });
  });
});

describe('POST /api/v1/users username', () => {
  const PASSWORD = 'Compliant-Pass-2026';

  function create(body: Record<string, unknown>) {
    return createUserRoute(request({ email: 'new@example.com', password: PASSWORD, ...body }));
  }

  it('uses an explicit username', async () => {
    const res = await create({ email: 'new+tag@example.com', username: 'newbie' });
    expect(res.status).toBe(201);
    expect((await res.json()).username).toBe('newbie');
  });

  it('gives an email the login page refuses no username instead of a made-up one', async () => {
    const res = await create({ email: 'new+tag@example.com' });
    expect(res.status).toBe(201);
    expect((await res.json()).username).toBeNull();
  });

  it('refuses an unusable or taken username with 400 and creates nobody', async () => {
    seedUser('holder@example.com', 'holder');
    seedUser('ops@localhost', 'ops@localhost');
    for (const [username, error] of [
      ['New', SIGN_IN_USERNAME_RULES_MESSAGE],
      [7, SIGN_IN_USERNAME_RULES_MESSAGE],
      ['holder', TAKEN],
      ['holder@example.com', TAKEN],
      ['ops', TAKEN],
    ] as const) {
      const res = await create({ username });
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe(error);
    }
    expect(db.select().from(users).where(eq(users.email, 'new@example.com')).all()).toEqual([]);
  });

  it('refuses an email address another account has or signs in with, with 400', async () => {
    seedUser('holder@example.com', 'new@example.com');
    const res = await create({});
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe('Another account signs in with this email address as its username');

    const duplicate = await create({ email: 'Holder@Example.com' });
    expect(duplicate.status).toBe(400);
    expect((await duplicate.json()).error).toBe('A user with this email already exists');
    expect(db.select().from(users).all()).toHaveLength(2);
  });

  it('refuses a caller who is not an administrator', async () => {
    caller.role = 'user';
    const res = await create({ username: 'newbie' });
    expect(res.status).toBe(403);
    expect(db.select().from(users).where(eq(users.email, 'new@example.com')).all()).toEqual([]);
  });
});

describe('updateUserInfoAction username', () => {
  function edit(userId: number, fields: Record<string, string>) {
    const data = new FormData();
    for (const [key, value] of Object.entries(fields)) data.set(key, value);
    return updateUserInfoAction(userId, data);
  }

  it('sets the username with the other fields and audits the change', async () => {
    const userId = seedUser('alice+cpm@example.com', null);

    expect(await edit(userId, { name: 'Alice', email: 'alice+cpm@example.com', username: ' alice ' })).toEqual({ ok: true });

    expect(stored(userId)).toMatchObject({ username: 'alice', displayUsername: 'alice', name: 'Alice' });
    const usernameEvent = auditRows().find((event) => event.data);
    expect(usernameEvent).toMatchObject({ userId: adminId, action: 'update', entityType: 'user', entityId: userId });
    expect(usernameEvent?.data).toEqual({ previousUsername: null, username: 'alice' });
  });

  it('returns the reason a username or email address cannot be used and saves nothing', async () => {
    seedUser('holder@example.com', 'holder');
    const userId = seedUser('alice@example.com', 'alice');

    for (const [fields, error] of [
      [{ username: 'Alice' }, SIGN_IN_USERNAME_RULES_MESSAGE],
      [{ username: 'holder@example.com' }, TAKEN],
      [{ username: 'alice2', email: 'holder@example.com' }, 'A user with this email already exists'],
    ] as const) {
      expect(await edit(userId, { name: 'Changed', ...fields })).toEqual({ ok: false, error });
    }
    expect(await edit(999, { username: 'nobody' })).toEqual({ ok: false, error: 'User not found' });
    expect(stored(userId)).toMatchObject({ username: 'alice', name: null, email: 'alice@example.com' });
    expect(auditRows()).toEqual([]);
  });

  it('saves the other fields when the username field holds the unusable one the user has', async () => {
    const userId = seedUser('bob@example.com', 'Bob');

    expect(await edit(userId, { name: 'Bob B.', username: 'Bob' })).toEqual({ ok: true });

    expect(stored(userId)).toMatchObject({ username: 'Bob', name: 'Bob B.' });
    expect(auditRows().filter((event) => event.data)).toEqual([]);
  });

  it('refuses a caller who is not an administrator', async () => {
    const userId = seedUser('alice@example.com', 'alice');
    caller.userId = userId;
    caller.role = 'user';

    await expect(edit(userId, { username: 'someone' })).rejects.toThrow();

    expect(stored(userId)?.username).toBe('alice');
    expect(auditRows()).toEqual([]);
  });
});

/**
 * Admin user Server Actions validate their client-supplied arguments and
 * return problems as `{ ok: false, error }` for the Users page to show inline,
 * instead of throwing (a thrown Server Action error replaces the page).
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  requireAdmin: vi.fn(),
  createUser: vi.fn(),
  updateUserAccount: vi.fn(),
  updateUserRole: vi.fn(),
  updateUserStatus: vi.fn(),
  deleteUser: vi.fn(),
}));

vi.mock('next/cache', () => ({ revalidatePath: vi.fn() }));
vi.mock('@/src/lib/auth', () => ({ requireAdmin: mocks.requireAdmin }));
vi.mock('@/src/lib/models/user', () => ({
  createUser: mocks.createUser,
  updateUserAccount: mocks.updateUserAccount,
  updateUserRole: mocks.updateUserRole,
  updateUserStatus: mocks.updateUserStatus,
  deleteUser: mocks.deleteUser,
}));

import {
  createUserAction,
  deleteUserAction,
  updateUserInfoAction,
  updateUserRoleAction,
  updateUserStatusAction,
} from '@/app/(dashboard)/users/actions';
import { ApiValidationError } from '@/src/lib/api-errors';

beforeEach(() => {
  for (const fn of Object.values(mocks)) fn.mockReset();
  mocks.requireAdmin.mockResolvedValue({ user: { id: '1', role: 'admin' } });
});

function form(fields: Record<string, string>) {
  const data = new FormData();
  for (const [key, value] of Object.entries(fields)) data.set(key, value);
  return data;
}

/** What drizzle throws for a duplicate key: the query text wraps the driver error. */
function uniqueViolation() {
  const cause = new Error('UNIQUE constraint failed: users.email');
  return new Error('Failed query: insert into "users" ... params: bob@example.com,$2a$12$secrethash', { cause });
}

describe('users actions', () => {
  it('rejects unknown roles and statuses', async () => {
    expect(await updateUserRoleAction(2, 'superuser' as never)).toEqual({ ok: false, error: 'Invalid role' });
    expect(await updateUserStatusAction(2, 'pending')).toEqual({ ok: false, error: 'Invalid status' });
    expect(mocks.updateUserRole).not.toHaveBeenCalled();
    expect(mocks.updateUserStatus).not.toHaveBeenCalled();
  });

  it('refuses to act on the calling admin', async () => {
    expect(await updateUserRoleAction(1, 'viewer')).toEqual({ ok: false, error: 'Cannot change your own role' });
    expect(await updateUserStatusAction(1, 'disabled')).toEqual({ ok: false, error: 'Cannot change your own status' });
    expect(await deleteUserAction(1)).toEqual({ ok: false, error: 'Cannot delete your own account' });
    expect(mocks.deleteUser).not.toHaveBeenCalled();
  });

  it('accepts known roles and statuses', async () => {
    expect(await updateUserRoleAction(2, 'viewer')).toEqual({ ok: true });
    expect(await updateUserStatusAction(2, 'disabled')).toEqual({ ok: true });
    expect(mocks.updateUserRole).toHaveBeenCalledWith(2, 'viewer');
    expect(mocks.updateUserStatus).toHaveBeenCalledWith(2, 'disabled');
  });

  it('returns the policy error for a weak password instead of throwing', async () => {
    const result = await createUserAction(form({ email: 'a@example.com', password: 'password' }));
    expect(result.ok).toBe(false);
    expect(!result.ok && result.error).toMatch(/at least 12/);
    expect(mocks.createUser).not.toHaveBeenCalled();
  });

  it('returns an error for a long password that fails only the complexity rules', async () => {
    const result = await createUserAction(form({ email: 'bob@example.com', password: 'Welcome123456' }));
    expect(result).toEqual({ ok: false, error: expect.stringMatching(/special character/) });
    expect(mocks.createUser).not.toHaveBeenCalled();
  });

  it('creates a user with a compliant password', async () => {
    mocks.createUser.mockResolvedValue({ id: 5, email: 'bob@example.com' });
    const result = await createUserAction(form({ email: 'bob@example.com', password: 'Correct-Horse-9!' }));
    expect(result).toEqual({ ok: true });
    expect(mocks.createUser).toHaveBeenCalledWith(expect.objectContaining({ email: 'bob@example.com', provider: 'credentials' }));
  });

  it('reports a duplicate email without leaking the query', async () => {
    mocks.createUser.mockRejectedValue(uniqueViolation());
    const created = await createUserAction(form({ email: 'bob@example.com', password: 'Correct-Horse-9!' }));
    expect(created).toEqual({ ok: false, error: 'A user with this email already exists' });

    mocks.updateUserAccount.mockRejectedValue(uniqueViolation());
    const updated = await updateUserInfoAction(2, form({ email: 'bob@example.com' }));
    expect(updated).toEqual({ ok: false, error: 'A user with this email already exists' });
  });

  it('returns the reason the model refuses a value', async () => {
    const refusal = new ApiValidationError('Another account signs in with this email address as its username');
    mocks.createUser.mockRejectedValue(refusal);
    mocks.updateUserAccount.mockRejectedValue(refusal);

    const created = await createUserAction(form({ email: 'bob@example.com', password: 'Correct-Horse-9!' }));
    const updated = await updateUserInfoAction(2, form({ email: 'bob@example.com' }));

    expect(created).toEqual({ ok: false, error: refusal.message });
    expect(updated).toEqual({ ok: false, error: refusal.message });
  });

  it('saves name, email and username in one model call', async () => {
    mocks.updateUserAccount.mockResolvedValue({ user: { id: 2, username: 'bob' }, previousUsername: 'bob' });
    const result = await updateUserInfoAction(2, form({ name: 'Bob', email: 'bob@example.com', username: 'bob' }));
    expect(result).toEqual({ ok: true });
    expect(mocks.updateUserAccount).toHaveBeenCalledTimes(1);
    expect(mocks.updateUserAccount).toHaveBeenCalledWith(2, { name: 'Bob', email: 'bob@example.com', username: 'bob' });
  });

  it('leaves the username alone when the form has no username field', async () => {
    mocks.updateUserAccount.mockResolvedValue({ user: { id: 2, username: null }, previousUsername: null });
    expect(await updateUserInfoAction(2, form({ name: 'Bob' }))).toEqual({ ok: true });
    expect(mocks.updateUserAccount).toHaveBeenCalledWith(2, { name: 'Bob', email: undefined, username: undefined });
  });

  it('does not save anything for a caller who is not an administrator', async () => {
    mocks.requireAdmin.mockRejectedValue(new Error('NEXT_REDIRECT'));
    await expect(updateUserInfoAction(2, form({ username: 'alice' }))).rejects.toThrow('NEXT_REDIRECT');
    expect(mocks.updateUserAccount).not.toHaveBeenCalled();
  });

  it('reports other storage failures generically', async () => {
    mocks.deleteUser.mockRejectedValue(new Error('Failed query: delete from "users" params: 2'));
    const result = await deleteUserAction(2);
    expect(result).toEqual({ ok: false, error: 'Failed to delete user' });
  });
});

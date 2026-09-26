/**
 * The profile page shows the username the login page accepts and, when there
 * is none, why: advice to change the password only where that fixes it, and
 * otherwise that an administrator has to set a sign-in username. It never
 * promises a username made from the email address.
 */
import { describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

vi.mock('next/navigation', () => ({ useRouter: () => ({ refresh: vi.fn(), push: vi.fn() }) }));
vi.mock('@/src/lib/auth-client', () => ({ authClient: { signIn: { social: vi.fn() } } }));
vi.mock('@/app/(dashboard)/api-tokens/actions', () => ({
  createApiTokenAction: vi.fn(),
  deleteApiTokenAction: vi.fn(),
}));
vi.mock('@/app/(dashboard)/profile/session-actions', () => ({
  revokeSessionAction: vi.fn(),
  revokeOtherSessionsAction: vi.fn(),
}));

import ProfileClient from '@/app/(dashboard)/profile/ProfileClient';

type Props = Parameters<typeof ProfileClient>[0];

const CHANGE_ONCE = 'Change it once here to enable password sign-in';
const NO_USERNAME = 'Your account has no sign-in username the login page can use';
const ADMIN_SETS = 'An administrator has to set a sign-in username for your account';
const SET_FIRST = 'you must first set a password';

function render(user: Partial<Props['user']>) {
  const props: Props = {
    user: {
      id: 7,
      email: 'alice+cpm@example.com',
      name: 'Alice',
      provider: 'dex',
      subject: 'dex-7',
      hasPassword: true,
      signInUsername: null,
      passwordSignInBlocker: null,
      role: 'user',
      avatarUrl: null,
      ...user,
    },
    linkedProviders: [{ providerId: 'dex', accountId: 'dex-7' }],
    enabledProviders: [{ id: 'dex', name: 'Dex', autoLink: true }],
    apiTokens: [],
    sessions: [],
  };
  return renderToStaticMarkup(createElement(ProfileClient, props));
}

describe('profile password sign-in', () => {
  it('shows the sign-in username and the unlink button when password sign-in works', () => {
    const html = render({ signInUsername: 'alice' });
    expect(html).toContain('Sign-in username');
    expect(html).toContain('>alice<');
    expect(html).toContain('Unlink OAuth Account');
    expect(html).not.toContain(CHANGE_ONCE);
    expect(html).not.toContain(NO_USERNAME);
  });

  it('suggests changing the password once when that sets up password sign-in', () => {
    const html = render({ passwordSignInBlocker: 'no-credential' });
    expect(html).toContain(CHANGE_ONCE);
    expect(html).not.toContain(NO_USERNAME);
    expect(html).not.toContain('Unlink OAuth Account');
    expect(html).not.toContain('Sign-in username');
  });

  it('explains a missing username instead of suggesting a password change', () => {
    const html = render({ passwordSignInBlocker: 'no-username' });
    expect(html).toContain(NO_USERNAME);
    expect(html).toContain(ADMIN_SETS);
    expect(html).toContain('This page then shows it.');
    expect(html).not.toContain('then you can set your password here');
    expect(html).not.toContain(CHANGE_ONCE);
    expect(html).not.toContain('Unlink OAuth Account');
    expect(html).not.toContain('Sign-in username</p>');
  });

  it('never says a username is made from the email address', () => {
    for (const hasPassword of [true, false]) {
      const html = render({ hasPassword, passwordSignInBlocker: 'no-username' });
      expect(html).not.toMatch(/made from|could be made|generated|change your email address/i);
    }
  });

  it('asks an OAuth-only user to set a password first', () => {
    const html = render({ hasPassword: false, passwordSignInBlocker: 'no-credential' });
    expect(html).toContain(SET_FIRST);
    expect(html).toContain('You are using OAuth-only authentication');
    expect(html).not.toContain(CHANGE_ONCE);
    expect(html).not.toContain(NO_USERNAME);
  });

  it('tells an OAuth-only user without a usable username before they set a password', () => {
    const html = render({ hasPassword: false, passwordSignInBlocker: 'no-username' });
    expect(html).toContain(NO_USERNAME);
    expect(html).toContain(`${ADMIN_SETS}, then you can set your password here`);
    expect(html).not.toContain('This page then shows it');
    expect(html).not.toContain('You are using OAuth-only authentication');
  });
});

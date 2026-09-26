/**
 * The rules for the username the login page signs in with. A stored username
 * the login page can find passes isValidLoginUsername and is lowercase,
 * because Better Auth lowercases what is typed before looking it up. The
 * module only states the rules: nothing in it turns an email into a username.
 */
import { describe, expect, it } from 'vitest';
import * as loginUsername from '@/src/lib/login-username';
import {
  LOGIN_USERNAME_MAX_LENGTH,
  LOGIN_USERNAME_MIN_LENGTH,
  SIGN_IN_USERNAME_RULES_MESSAGE,
  isUsableSignInUsername,
  isValidLoginUsername,
} from '@/src/lib/login-username';

describe('isValidLoginUsername', () => {
  it('accepts 3-255 characters from A-Z a-z 0-9 _ . @ -', () => {
    expect(isValidLoginUsername('alice@example.com')).toBe(true);
    expect(isValidLoginUsername('Alice_B.C-D')).toBe(true);
    expect(isValidLoginUsername('a'.repeat(LOGIN_USERNAME_MIN_LENGTH))).toBe(true);
    expect(isValidLoginUsername('a'.repeat(LOGIN_USERNAME_MAX_LENGTH))).toBe(true);
  });

  it('refuses other characters and lengths', () => {
    expect(isValidLoginUsername('alice+cpm@example.com')).toBe(false);
    expect(isValidLoginUsername('a b')).toBe(false);
    expect(isValidLoginUsername('jöhn')).toBe(false);
    expect(isValidLoginUsername('Kate')).toBe(false);
    expect(isValidLoginUsername('ab')).toBe(false);
    expect(isValidLoginUsername('a'.repeat(LOGIN_USERNAME_MAX_LENGTH + 1))).toBe(false);
  });
});

describe('isUsableSignInUsername', () => {
  it('accepts a lowercase valid username only', () => {
    expect(isUsableSignInUsername('alice@example.com')).toBe(true);
    expect(isUsableSignInUsername('Alice')).toBe(false);
    expect(isUsableSignInUsername('alice+cpm@example.com')).toBe(false);
    expect(isUsableSignInUsername('ab')).toBe(false);
    expect(isUsableSignInUsername('')).toBe(false);
    expect(isUsableSignInUsername(null)).toBe(false);
    expect(isUsableSignInUsername(undefined)).toBe(false);
  });
});

describe('login-username module', () => {
  it('names the rules in the message administrators see', () => {
    expect(SIGN_IN_USERNAME_RULES_MESSAGE).toContain(`${LOGIN_USERNAME_MIN_LENGTH}-${LOGIN_USERNAME_MAX_LENGTH}`);
    expect(SIGN_IN_USERNAME_RULES_MESSAGE).toContain('lowercase');
  });

  it('offers no way to derive a username from an email', () => {
    expect(Object.keys(loginUsername).sort()).toEqual([
      'LOGIN_USERNAME_MAX_LENGTH',
      'LOGIN_USERNAME_MIN_LENGTH',
      'SIGN_IN_USERNAME_RULES_MESSAGE',
      'isUsableSignInUsername',
      'isValidLoginUsername',
    ]);
  });
});

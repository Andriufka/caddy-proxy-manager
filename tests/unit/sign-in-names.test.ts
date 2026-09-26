/**
 * lowercasesIntoAscii flags an address that lowercasing would turn into
 * another one. The rules that read the database (isSignInNameTaken,
 * signInEmailConflict, ownEmailUsername) are covered against a real database
 * in tests/integration/user-password-credential.test.ts.
 */
import { describe, expect, it } from 'vitest';
import { lowercasesIntoAscii } from '@/src/lib/sign-in-names';

describe('lowercasesIntoAscii', () => {
  it.each([
    ['Kate@example.com'], // Kelvin sign, lowercased to 'k'
    ['İvan@example.com'], // capital I with dot, lowercased to 'i' and a combining dot
    ['kate@examplK.com'],
  ])('flags %s', (value) => {
    expect(lowercasesIntoAscii(value)).toBe(true);
  });

  it.each([
    ['Kate@Example.com'],
    ['alice+cpm@example.com'],
    ['JÖHN@example.com'], // lowercased to another non-ASCII letter
    ['åsa@example.com'],
    ['\u{1D400}@example.com'],
    [''],
  ])('leaves %s alone', (value) => {
    expect(lowercasesIntoAscii(value)).toBe(false);
  });
});

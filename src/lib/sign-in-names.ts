/**
 * Which account a sign-in name reaches. The login page finds an account by
 * username; the forward-auth portal takes the name typed there as the email
 * address `<name>@localhost`. CPM keeps every name pointing at one account:
 * a username is never another account's username, email address or portal
 * name, and an email address is never another account's username (nor, for a
 * @localhost address, is the part before it). Better Auth lowercases what is
 * typed on the login page, so names are compared case-insensitively.
 *
 * Server only: the page-safe username rules are in login-username.ts.
 */
import { and, ne, or, sql } from "drizzle-orm";
import type db from "./db";
import { users } from "./db/schema";
import { isUsableSignInUsername, isValidLoginUsername } from "./login-username";

type DbTransaction = Parameters<Parameters<typeof db.transaction>[0]>[0];

/** The database or a transaction on it. */
export type SignInNameReader = Pick<DbTransaction, "select">;

/** The forward-auth portal finds the account whose email is the typed name plus this. */
export const PORTAL_EMAIL_DOMAIN = "@localhost";

export const SIGN_IN_NAME_TAKEN_MESSAGE = "Another account already signs in with this name or has it as its email address";

/** Condition matching every account but `userId` (null: every account). */
function otherThan(userId: number | null) {
  return userId === null ? undefined : ne(users.id, userId);
}

/**
 * Whether an account other than `userId` (null: any account) has `name`
 * (lowercase) as its username or email address, or has the email address the
 * portal looks up for `name`.
 */
export function isSignInNameTaken(reader: SignInNameReader, userId: number | null, name: string): boolean {
  return !!reader
    .select({ id: users.id })
    .from(users)
    .where(and(
      or(
        sql`lower(${users.username}) = ${name}`,
        sql`lower(${users.email}) = ${name}`,
        sql`lower(${users.email}) = ${name + PORTAL_EMAIL_DOMAIN}`
      ),
      otherThan(userId)
    ))
    .get();
}

/**
 * Why account `userId` (null for one not created yet) cannot have the email
 * address `email`, or null when it can: another account has the address, in
 * any case, or signs in with it (or, for a @localhost address, with the part
 * before it) as its username.
 */
export function signInEmailConflict(reader: SignInNameReader, userId: number | null, email: string): string | null {
  const address = email.trim().toLowerCase();
  const sameAddress = reader
    .select({ id: users.id })
    .from(users)
    .where(and(sql`lower(${users.email}) = ${address}`, otherThan(userId)))
    .get();
  if (sameAddress) return "A user with this email already exists";

  const signsInWithAddress = reader
    .select({ id: users.id })
    .from(users)
    .where(and(sql`lower(${users.username}) = ${address}`, otherThan(userId)))
    .get();
  if (signsInWithAddress) return "Another account signs in with this email address as its username";

  if (address.endsWith(PORTAL_EMAIL_DOMAIN)) {
    const portalName = address.slice(0, -PORTAL_EMAIL_DOMAIN.length);
    const signsInWithPortalName = reader
      .select({ id: users.id })
      .from(users)
      .where(and(sql`lower(${users.username}) = ${portalName}`, otherThan(userId)))
      .get();
    if (signsInWithPortalName) return `Another account signs in with the name before ${PORTAL_EMAIL_DOMAIN} as its username`;
  }
  return null;
}

/**
 * Whether lowercasing `value` turns a character outside ASCII into ASCII, as
 * it turns the Kelvin sign into 'k'. The lowercased address is then another
 * one, which can belong to somebody else.
 */
export function lowercasesIntoAscii(value: string): boolean {
  return [...value].some((char) =>
    char.codePointAt(0)! > 0x7f && [...char.toLowerCase()].some((lowered) => lowered.codePointAt(0)! <= 0x7f)
  );
}

/**
 * The only username CPM gives an account by itself: the account's own email
 * address, lowercased and otherwise unchanged, when the login page can find
 * that and isSignInNameTaken is false for it. Null otherwise; the account then
 * has no sign-in username until an administrator sets one. `userId` is the
 * account (null for one not created yet).
 */
export function ownEmailUsername(reader: SignInNameReader, userId: number | null, email: string): string | null {
  // Checked before lowercasing, so that only A-Z change (see lowercasesIntoAscii).
  if (!isValidLoginUsername(email)) return null;
  const username = email.toLowerCase();
  return isUsableSignInUsername(username) && !isSignInNameTaken(reader, userId, username) ? username : null;
}

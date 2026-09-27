import db, { nowIso, toIso } from "../db";
import {
  users,
  accounts,
  oauthProviders,
  sessions,
  verifications,
  pendingOAuthLinks,
  accessLists,
  certificates,
  caCertificates,
  issuedClientCertificates,
  proxyHosts,
  l4ProxyHosts,
  apiTokens,
  auditEvents,
  mtlsRoles,
  mtlsAccessRules,
  groups,
  groupMembers,
  forwardAuthAccess,
  forwardAuthSessions,
  forwardAuthExchanges,
} from "../db/schema";
import * as schema from "../db/schema";
import { and, count, desc, eq, inArray, is, isNotNull, ne, notInArray, sql } from "drizzle-orm";
import { SQLiteTable, getTableConfig } from "drizzle-orm/sqlite-core";
import { deleteUserForwardAuthSessions } from "./forward-auth";
import {
  CREDENTIAL_ACCOUNT_ISSUER,
  resolveOAuthAccountIssuer,
} from "../account-issuer";
import { SIGN_IN_USERNAME_RULES_MESSAGE, isUsableSignInUsername } from "../login-username";
import {
  PORTAL_EMAIL_DOMAIN,
  SIGN_IN_NAME_TAKEN_MESSAGE,
  isSignInNameTaken,
  lowercasesIntoAscii,
  ownEmailUsername,
  signInEmailConflict,
  type SignInNameReader,
} from "../sign-in-names";
import { ApiValidationError } from "../api-errors";

export type User = {
  id: number;
  email: string;
  name: string | null;
  /**
   * The username stored for the login page, or null. CPM only ever stores the
   * account's own email (see ownEmailUsername) or one an administrator chose
   * (updateUserAccount).
   */
  username: string | null;
  passwordHash: string | null;
  role: "admin" | "user" | "viewer";
  provider: string | null;
  subject: string | null;
  avatarUrl: string | null;
  status: string;
  createdAt: string;
  updatedAt: string;
};

type DbUser = typeof users.$inferSelect;

function parseDbUser(user: DbUser): User {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    username: user.username,
    passwordHash: user.passwordHash,
    role: user.role as "admin" | "user" | "viewer",
    provider: user.provider,
    subject: user.subject,
    avatarUrl: user.avatarUrl,
    status: user.status,
    createdAt: toIso(user.createdAt)!,
    updatedAt: toIso(user.updatedAt)!
  };
}

export async function getUserById(userId: number): Promise<User | null> {
  const user = await db.query.users.findFirst({
    where: (table, { eq }) => eq(table.id, userId)
  });
  return user ? parseDbUser(user) : null;
}

export async function getUserCount(): Promise<number> {
  const result = await db.select({ value: count() }).from(users);
  return result[0]?.value ?? 0;
}

export async function findUserByProviderSubject(provider: string, subject: string): Promise<User | null> {
  const configuredProvider = await db.select({ issuer: oauthProviders.issuer })
    .from(oauthProviders)
    .where(eq(oauthProviders.id, provider))
    .get();
  const issuer = resolveOAuthAccountIssuer(provider, configuredProvider?.issuer);
  const account = await db.select().from(accounts).where(
    and(eq(accounts.issuer, issuer), eq(accounts.accountId, subject))
  ).limit(1);

  if (account.length === 0) return null;

  const user = await db.query.users.findFirst({
    where: (table, { eq }) => eq(table.id, account[0].userId)
  });
  return user ? parseDbUser(user) : null;
}

export async function findUserByEmail(email: string): Promise<User | null> {
  const normalizedEmail = email.trim().toLowerCase();
  const user = await db.query.users.findFirst({
    where: (table, { eq }) => eq(table.email, normalizedEmail)
  });
  return user ? parseDbUser(user) : null;
}

export async function createUser(data: {
  email: string;
  name?: string | null;
  role?: User["role"];
  provider: string;
  subject: string;
  avatarUrl?: string | null;
  passwordHash?: string | null;
  username?: string | null;
  displayUsername?: string | null;
}): Promise<User> {
  const now = nowIso();
  const role = data.role ?? "user";
  const email = storedEmail(data.email);
  const provider = data.provider === "credential" ? "credentials" : data.provider;

  // One synchronous transaction, so no other account can take the email
  // address or the username between checking it and inserting the user.
  const user = db.transaction((tx) => {
    const emailConflict = signInEmailConflict(tx, null, email);
    if (emailConflict) throw new ApiValidationError(emailConflict);
    const username = data.username != null
      ? checkChosenUsername(tx, null, data.username)
      : ownEmailUsername(tx, null, email);
    const displayUsername = data.displayUsername ?? data.name ?? email.split("@")[0];
    const row = tx
      .insert(users)
      .values({
        email,
        name: data.name ?? null,
        passwordHash: data.passwordHash ?? null,
        role,
        provider,
        subject: data.subject,
        avatarUrl: data.avatarUrl ?? null,
        status: "active",
        username,
        displayUsername,
        createdAt: now,
        updatedAt: now
      })
      .returning()
      .get();

    if (provider === "credentials" && data.passwordHash) {
      tx.insert(accounts).values({
        userId: row.id,
        issuer: CREDENTIAL_ACCOUNT_ISSUER,
        accountId: row.id.toString(),
        providerId: "credential",
        password: data.passwordHash,
        createdAt: now,
        updatedAt: now,
      }).run();
    }
    return row;
  });

  return parseDbUser(user);
}

type DbTransaction = Parameters<Parameters<typeof db.transaction>[0]>[0];

/**
 * `email` as it is stored: trimmed and lowercased. The address is compared
 * lowercased everywhere, so lowercasing must not turn it into another one.
 */
function storedEmail(email: string): string {
  if (lowercasesIntoAscii(email)) {
    throw new ApiValidationError(
      "Email address contains a character that lowercasing turns into an ASCII letter (such as the Kelvin sign); " +
      "enter it with plain letters"
    );
  }
  const stored = email.trim().toLowerCase();
  if (!stored) throw new ApiValidationError("Email address is required");
  return stored;
}

/**
 * A username an administrator chose that the account cannot have. The message
 * says why and is safe to show; the REST API answers it with 400.
 */
export class SignInUsernameError extends ApiValidationError {
  constructor(message: string) {
    super(message);
    this.name = "SignInUsernameError";
  }
}

/**
 * A username an administrator chose for account `userId` (null for one not
 * created yet), trimmed. Throws SignInUsernameError unless the login page can
 * find it and no other account has it (see isSignInNameTaken).
 */
function checkChosenUsername(reader: SignInNameReader, userId: number | null, input: string): string {
  const username = input.trim();
  if (!isUsableSignInUsername(username)) {
    throw new SignInUsernameError(SIGN_IN_USERNAME_RULES_MESSAGE);
  }
  if (isSignInNameTaken(reader, userId, username)) {
    throw new SignInUsernameError(SIGN_IN_NAME_TAKEN_MESSAGE);
  }
  return username;
}

type ProfileChanges = { email?: string; name?: string | null; avatarUrl?: string | null };

/**
 * Applies `data` to user `userId` inside `tx`, or returns null when there is
 * no such user. A new email address (not only a new case of the current one)
 * must pass signInEmailConflict, and a username (`data.username`) other than
 * the one the user has must pass checkChosenUsername; otherwise the reason is
 * thrown and nothing is written. Returns the row and the previous username.
 */
function writeUserChanges(
  tx: DbTransaction,
  userId: number,
  data: ProfileChanges & { username?: string },
  now: string
): { row: DbUser; previousUsername: string | null } | null {
  const current = tx.select().from(users).where(eq(users.id, userId)).get();
  if (!current) return null;
  const email = data.email === undefined ? current.email : storedEmail(data.email);
  if (email !== current.email.toLowerCase()) {
    const conflict = signInEmailConflict(tx, userId, email);
    if (conflict) throw new ApiValidationError(conflict);
  }
  // The username the user has is no change, so the other fields can be edited
  // while it is one the login page cannot use.
  const username = data.username !== undefined && data.username.trim() !== (current.username ?? "")
    ? checkChosenUsername(tx, userId, data.username)
    : null;
  const row = tx
    .update(users)
    .set({
      email,
      name: data.name ?? current.name,
      avatarUrl: data.avatarUrl ?? current.avatarUrl,
      // displayUsername follows, as Better Auth stores it when a username changes.
      ...(username === null ? {} : { username, displayUsername: username }),
      updatedAt: now
    })
    .where(eq(users.id, userId))
    .returning()
    .get();
  return { row, previousUsername: current.username };
}

/**
 * Updates the email, name and avatar. The username is left as it is, whatever
 * the new email: only an administrator changes it (updateUserAccount). A new
 * email address that another account has, or signs in with, is refused with
 * the reason (see signInEmailConflict).
 */
export async function updateUserProfile(userId: number, data: ProfileChanges): Promise<User | null> {
  const now = nowIso();
  const profile: ProfileChanges = { email: data.email, name: data.name, avatarUrl: data.avatarUrl };
  const result = db.transaction((tx) => writeUserChanges(tx, userId, profile, now));
  return result ? parseDbUser(result.row) : null;
}

/**
 * An administrator's edit of a user: the profile fields as updateUserProfile
 * applies them and the username the user signs in with on the login page (see
 * checkChosenUsername; setting the one the user has changes nothing). One
 * transaction, so a refused value leaves every field unchanged. Returns the
 * user and the username they had before, or null when there is no such user.
 */
export async function updateUserAccount(
  userId: number,
  data: ProfileChanges & { username?: string }
): Promise<{ user: User; previousUsername: string | null } | null> {
  const now = nowIso();
  const result = db.transaction((tx) => writeUserChanges(tx, userId, data, now));
  return result ? { user: parseDbUser(result.row), previousUsername: result.previousUsername } : null;
}

/** updateUserAccount with only a username. */
export async function setUserSignInUsername(
  userId: number,
  input: string
): Promise<{ user: User; previousUsername: string | null } | null> {
  return updateUserAccount(userId, { username: input });
}

/**
 * Applies CPM's sign-in name rules to a user Better Auth is about to create,
 * as its database hook receives it (with the email lowercased). An email
 * address another account has, or signs in with, is refused with the reason
 * (see signInEmailConflict). A self-registered account gets its own email as
 * username when ownEmailUsername allows it, and none otherwise, whatever the
 * request asked for: CPM stores no other username than that or one an
 * administrator sets. Any other account (an OAuth sign-up) gets none until its
 * password is set (see writeUserPassword).
 *
 * The address must look like one outside CPM's own names: an identity
 * provider can assert any "email", and one without an '@' (such as "root")
 * or a @localhost one (a forward-auth portal name) would otherwise claim a
 * sign-in name that only an administrator may give out.
 */
export function applySignInNameRules<T extends Record<string, unknown>>(
  user: T,
  selfRegistered: boolean
): T & { username: string | null } {
  const email = typeof user.email === "string" ? user.email : "";
  const at = email.lastIndexOf("@");
  if (at <= 0 || at === email.length - 1 || email.toLowerCase().endsWith(PORTAL_EMAIL_DOMAIN)) {
    throw new ApiValidationError("Email address is not allowed");
  }
  const conflict = signInEmailConflict(db, null, email);
  if (conflict) throw new ApiValidationError(conflict);
  if (!selfRegistered) return { ...user, username: null };
  const username = ownEmailUsername(db, null, email);
  return { ...user, username, displayUsername: username };
}

/**
 * Run after Better Auth has inserted user `userId`. applySignInNameRules
 * checked the username before the insert, but Better Auth writes the row
 * later and asynchronously, so an administrator may have given the name to
 * another account in between (the column has no unique index). The new
 * account then loses it: the name was only the one CPM gives by itself, and
 * an administrator can set another.
 */
export function releaseContestedSignInUsername(userId: number): void {
  db.transaction((tx) => {
    const row = tx.select({ username: users.username }).from(users).where(eq(users.id, userId)).get();
    if (!row?.username || !isSignInNameTaken(tx, userId, row.username.toLowerCase())) return;
    tx.update(users).set({ username: null, updatedAt: nowIso() }).where(eq(users.id, userId)).run();
  });
}

export type SignInUsernameReview = { userId: number; username: string; reason: "shared" | "other-address" };

/**
 * Stored usernames for an administrator to check. It only reads, so it suits
 * startup:
 *  - "shared": another account has the name as username or email address, or
 *    as its forward-auth portal name, so the name can reach either account;
 *  - "other-address": the name is an email address other than the account's
 *    own, such as alice-cpm@example.com on the account alice+cpm@example.com
 *    or the account's address before it changed, which can be somebody else's.
 */
export async function findSignInUsernamesToReview(): Promise<SignInUsernameReview[]> {
  const rows = await db
    .select({ id: users.id, email: users.email, username: users.username })
    .from(users)
    .orderBy(users.id)
    .all();
  const holders = new Map<string, Set<number>>();
  const hold = (name: string, userId: number) => {
    const ids = holders.get(name) ?? new Set<number>();
    ids.add(userId);
    holders.set(name, ids);
  };
  for (const row of rows) {
    const email = row.email.toLowerCase();
    hold(email, row.id);
    if (email.endsWith(PORTAL_EMAIL_DOMAIN)) hold(email.slice(0, -PORTAL_EMAIL_DOMAIN.length), row.id);
    if (row.username) hold(row.username.toLowerCase(), row.id);
  }

  const review: SignInUsernameReview[] = [];
  for (const row of rows) {
    if (!row.username) continue;
    const name = row.username.toLowerCase();
    if ([...holders.get(name)!].some((id) => id !== row.id)) {
      review.push({ userId: row.id, username: row.username, reason: "shared" });
    } else if (
      name.includes("@") &&
      name !== row.email.toLowerCase() &&
      name + PORTAL_EMAIL_DOMAIN !== row.email.toLowerCase()
    ) {
      review.push({ userId: row.id, username: row.username, reason: "other-address" });
    }
  }
  return review;
}

/**
 * Writes the password to users.passwordHash and to the Better Auth credential
 * account, which is what the login page checks. An account without a password
 * (OAuth-only) has no credential account yet, so one is created.
 *
 * The login page signs in by username. A usable username is kept. A user
 * without one (users provisioned by an OAuth sign-in have none; older accounts
 * can hold one the login page refuses, such as an email with a '+') gets their
 * own email when ownEmailUsername allows it and otherwise keeps what they
 * have. The SQLite driver is synchronous, so this runs inside a synchronous
 * transaction.
 */
function writeUserPassword(tx: DbTransaction, userId: number, passwordHash: string, now: string): void {
  const user = tx
    .select({
      email: users.email,
      name: users.name,
      username: users.username,
      displayUsername: users.displayUsername,
    })
    .from(users)
    .where(eq(users.id, userId))
    .get();
  const username = user && !isUsableSignInUsername(user.username) ? ownEmailUsername(tx, userId, user.email) : null;
  const signInName = user && username
    ? { username, displayUsername: user.displayUsername ?? user.name ?? username.split("@")[0] }
    : null;

  tx.update(users)
    .set({ passwordHash, ...signInName, updatedAt: now })
    .where(eq(users.id, userId))
    .run();

  const updated = tx
    .update(accounts)
    .set({ password: passwordHash, updatedAt: now })
    .where(and(eq(accounts.userId, userId), eq(accounts.providerId, "credential")))
    .returning({ id: accounts.id })
    .all();
  if (updated.length === 0) {
    tx.insert(accounts)
      .values({
        userId,
        issuer: CREDENTIAL_ACCOUNT_ISSUER,
        accountId: userId.toString(),
        providerId: "credential",
        password: passwordHash,
        createdAt: now,
        updatedAt: now,
      })
      .run();
  }
}

/**
 * Sets a user's password and ends their other sign-ins: every management
 * session except `keepSessionId` (the caller's, or null to end them all) and
 * every forward-auth session. It runs as one transaction, so the password
 * never changes without the revocation or the other way round. API tokens are
 * separate credentials and are left alone.
 */
export async function changeUserPassword(
  userId: number,
  passwordHash: string,
  keepSessionId: number | null
): Promise<void> {
  const now = nowIso();
  db.transaction((tx) => {
    writeUserPassword(tx, userId, passwordHash, now);
    tx.delete(sessions)
      .where(keepSessionId === null
        ? eq(sessions.userId, userId)
        : and(eq(sessions.userId, userId), ne(sessions.id, keepSessionId)))
      .run();
    tx.delete(forwardAuthSessions).where(eq(forwardAuthSessions.userId, userId)).run();
  });
}

/**
 * The hash of the user's password, or null when the account has none
 * (OAuth-only). Accounts CPM creates keep it in users.passwordHash; Better
 * Auth's self-registration writes it only to the credential account. The
 * change-password route and the profile page use it to decide whether a
 * current password has to be proven.
 */
export async function getUserPasswordHash(user: Pick<User, "id" | "passwordHash">): Promise<string | null> {
  if (user.passwordHash) return user.passwordHash;
  const credential = await db
    .select({ password: accounts.password })
    .from(accounts)
    .where(and(
      eq(accounts.userId, user.id),
      eq(accounts.providerId, "credential"),
      isNotNull(accounts.password)
    ))
    .get();
  return credential?.password || null;
}

/**
 * The username the user signs in with on the login page, or null when that
 * page cannot sign them in without OAuth. It looks the user up by username and
 * checks the password on the credential account, so both have to exist; a
 * password kept only in users.passwordHash does not count. Unlinking OAuth,
 * and the profile page's unlink button, go through here so the last working
 * sign-in method cannot be removed.
 */
export async function getPasswordSignInUsername(userId: number): Promise<string | null> {
  const row = await db
    .select({ username: users.username })
    .from(accounts)
    .innerJoin(users, eq(users.id, accounts.userId))
    .where(and(
      eq(accounts.userId, userId),
      eq(accounts.providerId, "credential"),
      isNotNull(accounts.password),
      ne(accounts.password, "")
    ))
    .get();
  return isUsableSignInUsername(row?.username) ? row.username : null;
}

/**
 * Why the login page cannot sign a user in with a password:
 *  - "no-credential": it has no username and password pair for them yet. The
 *    password is not on the credential account, or the account has no usable
 *    username but can have its own email as one (see ownEmailUsername);
 *    setting or changing the password sets up both.
 *  - "no-username": the account has no usable username and cannot have its
 *    own email as one, so no password change helps. An administrator has to
 *    set one (setUserSignInUsername).
 */
export type PasswordSignInBlocker = "no-credential" | "no-username";

export type PasswordSignInStatus =
  | { username: string; blocker: null }
  | { username: null; blocker: PasswordSignInBlocker };

/** getPasswordSignInUsername plus, when that is null, the reason. */
export async function getPasswordSignInStatus(userId: number): Promise<PasswordSignInStatus> {
  const username = await getPasswordSignInUsername(userId);
  if (username) return { username, blocker: null };
  const user = await db
    .select({ email: users.email, username: users.username })
    .from(users)
    .where(eq(users.id, userId))
    .get();
  const canGetUsername = !!user &&
    (isUsableSignInUsername(user.username) || ownEmailUsername(db, userId, user.email) !== null);
  return { username: null, blocker: canGetUsername ? "no-credential" : "no-username" };
}

/**
 * The OAuth identities linked to a user, read from the authoritative
 * `accounts` table (Better Auth writes federated identities there).
 *
 * The informational `users.provider` / `users.subject` columns are a cached
 * projection of this table and are re-derived via {@link syncUserOAuthIdentity};
 * the Profile page must read connection state from here so a stale projection
 * can never make a linked account look unlinked (or vice versa). (#261)
 */
export async function listUserOAuthProviders(userId: number): Promise<Array<{ providerId: string; accountId: string }>> {
  return db
    .select({ providerId: accounts.providerId, accountId: accounts.accountId })
    .from(accounts)
    .where(and(eq(accounts.userId, userId), ne(accounts.providerId, "credential")))
    .orderBy(desc(accounts.id))
    .all();
}

/**
 * Re-derive `users.provider` / `users.subject` from the authoritative
 * `accounts` table.
 *
 * Better Auth only writes to `accounts` when an OAuth identity is linked
 * (auto-link, profile link, federated sign-up), so without this sync the two
 * representations drift apart and the Profile UI reports the wrong connection
 * state in both directions (#261). The most recently created OAuth account
 * wins; with no OAuth identity left the user falls back to their credential
 * account ("credentials"), or to null when they have neither.
 */
export async function syncUserOAuthIdentity(userId: number): Promise<void> {
  const [oauthAccount] = await db
    .select({ providerId: accounts.providerId, accountId: accounts.accountId })
    .from(accounts)
    .where(and(eq(accounts.userId, userId), ne(accounts.providerId, "credential")))
    .orderBy(desc(accounts.id))
    .limit(1);

  const now = nowIso();
  if (oauthAccount) {
    await db
      .update(users)
      .set({
        provider: oauthAccount.providerId,
        subject: oauthAccount.accountId,
        updatedAt: now,
      })
      .where(eq(users.id, userId));
    return;
  }

  const credentialAccount = await db
    .select({ id: accounts.id })
    .from(accounts)
    .where(and(eq(accounts.userId, userId), eq(accounts.providerId, "credential")))
    .get();
  const user = await getUserById(userId);
  const hasCredential = !!credentialAccount || !!user?.passwordHash;

  await db
    .update(users)
    .set({
      provider: hasCredential ? "credentials" : null,
      subject: null,
      updatedAt: now,
    })
    .where(eq(users.id, userId));
}

export async function listUsers(): Promise<User[]> {
  const rows = await db.query.users.findMany({
    orderBy: (table, { asc }) => asc(table.createdAt)
  });
  return rows.map(parseDbUser);
}

export async function promoteToAdmin(userId: number): Promise<void> {
  const now = nowIso();
  await db
    .update(users)
    .set({
      role: "admin",
      updatedAt: now
    })
    .where(eq(users.id, userId));
}

export async function updateUserRole(userId: number, role: User["role"]): Promise<User | null> {
  const now = nowIso();
  const [updated] = await db
    .update(users)
    .set({ role, updatedAt: now })
    .where(eq(users.id, userId))
    .returning();
  return updated ? parseDbUser(updated) : null;
}

export async function updateUserStatus(userId: number, status: string): Promise<User | null> {
  const now = nowIso();
  const [updated] = await db
    .update(users)
    .set({ status, updatedAt: now })
    .where(eq(users.id, userId))
    .returning();

  // Revoke all sessions when user is deactivated: CPM's own routes refuse a
  // disabled user's session, but Better Auth's endpoints would still take it.
  if (status !== "active") {
    await db.delete(sessions).where(eq(sessions.userId, userId));
    await deleteUserForwardAuthSessions(userId);
  }

  return updated ? parseDbUser(updated) : null;
}

/**
 * The user id in the state of a Better Auth "link account" flow, as text, and
 * null for every other verification row. Better Auth's OAuth callback links
 * the identity to this user id without checking a session.
 */
const linkStateUserId = sql`case when json_valid(${verifications.value})
  then cast(json_extract(${verifications.value}, '$.link.userId') as text) end`;

/**
 * Applies the schema's onDelete rules for a user id: deletes the rows that
 * belong to the user (sign-ins, sign-in methods, API tokens, memberships,
 * forward-auth grants) and clears the user from rows that only record who
 * created or owns them. Production SQLite runs with foreign_keys off, so
 * none of those rules fire by themselves, and a user later created with the
 * same id (the primary admin always gets id 1) would take over whatever is
 * left. It does not touch the users row itself.
 */
function deleteUserReferences(tx: DbTransaction, userId: number): void {
  // onDelete: "cascade". Exchange codes cascade from forward-auth sessions.
  tx.delete(forwardAuthExchanges)
    .where(inArray(
      forwardAuthExchanges.sessionId,
      tx.select({ id: forwardAuthSessions.id }).from(forwardAuthSessions).where(eq(forwardAuthSessions.userId, userId))
    ))
    .run();
  tx.delete(forwardAuthSessions).where(eq(forwardAuthSessions.userId, userId)).run();
  tx.delete(forwardAuthAccess).where(eq(forwardAuthAccess.userId, userId)).run();
  tx.delete(groupMembers).where(eq(groupMembers.userId, userId)).run();
  tx.delete(sessions).where(eq(sessions.userId, userId)).run();
  tx.delete(accounts).where(eq(accounts.userId, userId)).run();
  tx.delete(pendingOAuthLinks).where(eq(pendingOAuthLinks.userId, userId)).run();
  tx.delete(apiTokens).where(eq(apiTokens.createdBy, userId)).run();
  tx.delete(verifications).where(sql`${linkStateUserId} = ${String(userId)}`).run();

  // onDelete: "set null".
  tx.update(auditEvents).set({ userId: null }).where(eq(auditEvents.userId, userId)).run();
  tx.update(proxyHosts).set({ ownerUserId: null }).where(eq(proxyHosts.ownerUserId, userId)).run();
  tx.update(l4ProxyHosts).set({ ownerUserId: null }).where(eq(l4ProxyHosts.ownerUserId, userId)).run();
  tx.update(accessLists).set({ createdBy: null }).where(eq(accessLists.createdBy, userId)).run();
  tx.update(certificates).set({ createdBy: null }).where(eq(certificates.createdBy, userId)).run();
  tx.update(caCertificates).set({ createdBy: null }).where(eq(caCertificates.createdBy, userId)).run();
  tx.update(issuedClientCertificates).set({ createdBy: null })
    .where(eq(issuedClientCertificates.createdBy, userId)).run();
  tx.update(mtlsRoles).set({ createdBy: null }).where(eq(mtlsRoles.createdBy, userId)).run();
  tx.update(mtlsAccessRules).set({ createdBy: null }).where(eq(mtlsAccessRules.createdBy, userId)).run();
  tx.update(groups).set({ createdBy: null }).where(eq(groups.createdBy, userId)).run();
}

/** Deletes the user and, in the same transaction, everything deleteUserReferences covers. */
export async function deleteUser(userId: number): Promise<void> {
  db.transaction((tx) => {
    deleteUserReferences(tx, userId);
    tx.delete(users).where(eq(users.id, userId)).run();
  });
}

/**
 * Runs deleteUserReferences, in one transaction, for every user id that rows
 * still reference although its users row is gone. Older releases left such
 * rows: their deleteUser removed only the users row. The id can be handed out
 * again, because the primary admin is always created as id 1 and rebuilding
 * the users table (migration 0022 does) resets its AUTOINCREMENT counter to
 * the highest remaining id, and the new user would take over the sessions,
 * API tokens and sign-in methods. Returns the ids it cleared.
 */
export async function deleteOrphanedUserReferences(): Promise<number[]> {
  // Every column the schema declares as a reference to users.id.
  const references = (Object.values(schema) as unknown[])
    .filter((value): value is SQLiteTable => is(value, SQLiteTable))
    .flatMap((table) => getTableConfig(table).foreignKeys
      .map((foreignKey) => foreignKey.reference())
      .filter((reference) => reference.foreignTable === users)
      .map((reference) => ({ table, column: reference.columns[0] })));

  return db.transaction((tx) => {
    const orphanIds = new Set<number>();
    for (const { table, column } of references) {
      const rows = tx
        .selectDistinct({ userId: column })
        .from(table)
        .where(and(isNotNull(column), notInArray(column, tx.select({ id: users.id }).from(users))))
        .all();
      for (const { userId } of rows) orphanIds.add(Number(userId));
    }
    for (const userId of orphanIds) deleteUserReferences(tx, userId);
    // Link-account states that name a user that does not exist, whatever form the id takes.
    tx.delete(verifications)
      .where(sql`${linkStateUserId} is not null and ${linkStateUserId} not in (select cast(${users.id} as text) from ${users})`)
      .run();
    return [...orphanIds].sort((a, b) => a - b);
  });
}

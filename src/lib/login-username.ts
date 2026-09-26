/**
 * Rules for the username the login page signs in with. Better Auth's username
 * plugin applies them on sign-in; CPM applies them when it stores a username,
 * so it never records one that the login page would refuse. CPM never makes a
 * username up: an account either gets its own email address as it is (see
 * ownEmailUsername in sign-in-names.ts, which also keeps a name from reaching
 * two accounts) or one an administrator sets.
 */
export const LOGIN_USERNAME_MIN_LENGTH = 3;
export const LOGIN_USERNAME_MAX_LENGTH = 255;

export function isValidLoginUsername(username: string): boolean {
  return (
    username.length >= LOGIN_USERNAME_MIN_LENGTH &&
    username.length <= LOGIN_USERNAME_MAX_LENGTH &&
    /^[a-zA-Z0-9_.@-]+$/.test(username)
  );
}

/**
 * Whether the login page can find an account by this stored username. Better
 * Auth lowercases what is typed and looks it up with an exact match, so a
 * stored username also has to be lowercase.
 */
export function isUsableSignInUsername(username: string | null | undefined): username is string {
  return !!username && isValidLoginUsername(username) && username === username.toLowerCase();
}

/** What an administrator sees when a username they chose fails isUsableSignInUsername. */
export const SIGN_IN_USERNAME_RULES_MESSAGE =
  `Username must be ${LOGIN_USERNAME_MIN_LENGTH}-${LOGIN_USERNAME_MAX_LENGTH} characters long and use only ` +
  `lowercase letters (a-z), digits and the characters _ . @ -`;

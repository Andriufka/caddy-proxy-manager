/**
 * The one-time Better Auth data migration in src/lib/db.ts runs on databases
 * that never had it. It gives a user without a username only their own email
 * address, lowercased, when the login page accepts it and no other account
 * signs in with it or has it as email address; the others keep none.
 */
import Database from 'better-sqlite3';
import { migrate } from 'drizzle-orm/better-sqlite3/migrator';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';

const migrationsFolder = resolve(process.cwd(), 'drizzle');

function resetDbModuleState() {
  vi.resetModules();
  const globals = globalThis as typeof globalThis & {
    __DRIZZLE_DB__?: unknown;
    __SQLITE_CLIENT__?: { close?: () => void };
    __MIGRATIONS_RAN__?: boolean;
  };
  globals.__SQLITE_CLIENT__?.close?.();
  delete globals.__DRIZZLE_DB__;
  delete globals.__SQLITE_CLIENT__;
  delete globals.__MIGRATIONS_RAN__;
}

/** A database from before the migration: users, some without a username. */
function createLegacyDatabase(dbPath: string, rows: Array<[email: string, username: string | null]>) {
  const sqlite = new Database(dbPath);
  migrate(drizzle(sqlite), { migrationsFolder });
  const now = new Date().toISOString();
  const insert = sqlite.prepare(`
    INSERT INTO users (email, username, name, role, provider, subject, status, emailVerified, createdAt, updatedAt)
    VALUES (?, ?, NULL, 'user', 'credentials', ?, 'active', 0, ?, ?)
  `);
  for (const [email, username] of rows) insert.run(email, username, email, now, now);
  sqlite.close();
}

function usernames(dbPath: string) {
  const sqlite = new Database(dbPath, { readonly: true });
  const rows = sqlite.prepare('SELECT email, username FROM users ORDER BY id').all();
  sqlite.close();
  return rows;
}

describe('Better Auth data migration usernames', () => {
  afterEach(() => {
    process.env.DATABASE_URL = ':memory:';
    resetDbModuleState();
  });

  it('gives only a qualifying own email address, and nothing made from one', async () => {
    const tempDir = mkdtempSync(join(process.cwd(), 'tmp-db-legacy-usernames-'));
    const dbPath = join(tempDir, 'legacy.db');
    try {
      createLegacyDatabase(dbPath, [
        ['Dave@Example.com', null],
        ['alice+cpm@example.com', null],
        ['Kate@example.com', null],
        ['holder@example.com', 'carol@example.com'],
        ['carol@example.com', null],
        ['ops@localhost', 'ops@localhost'],
        ['ops', null],
      ]);

      process.env.DATABASE_URL = `file:${dbPath}`;
      resetDbModuleState();
      await import('@/src/lib/db');

      expect(usernames(dbPath)).toEqual([
        { email: 'Dave@Example.com', username: 'dave@example.com' },
        { email: 'alice+cpm@example.com', username: null },
        { email: 'Kate@example.com', username: null },
        { email: 'holder@example.com', username: 'carol@example.com' },
        { email: 'carol@example.com', username: null },
        { email: 'ops@localhost', username: 'ops@localhost' },
        // The forward-auth portal reads "ops" as ops@localhost.
        { email: 'ops', username: null },
      ]);
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
});

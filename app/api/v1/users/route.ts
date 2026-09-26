import { NextRequest, NextResponse } from "next/server";
import { requireApiAdmin, apiErrorResponse } from "@/src/lib/api-auth";
import { listUsers, createUser } from "@/src/lib/models/user";
import { passwordPolicyMessage } from "@/src/lib/password-policy";
import { SIGN_IN_USERNAME_RULES_MESSAGE } from "@/src/lib/login-username";

const VALID_ROLES = new Set(["admin", "user", "viewer"]);

function stripPasswordHash(user: Record<string, unknown>) {
  const { passwordHash: _, ...rest } = user;
  void _;
  return rest;
}

export async function GET(request: NextRequest) {
  try {
    await requireApiAdmin(request);
    const users = await listUsers();
    return NextResponse.json(users.map(u => stripPasswordHash(u as unknown as Record<string, unknown>)));
  } catch (error) {
    return apiErrorResponse(error);
  }
}

export async function POST(request: NextRequest) {
  try {
    await requireApiAdmin(request);
    const body = await request.json();

    const email = String(body.email ?? "").trim();
    const password = String(body.password ?? "");
    const name = body.name ? String(body.name).trim() : null;
    const role = VALID_ROLES.has(body.role) ? body.role : "user";
    // Optional. Without one the user gets their own email when it can be a
    // username (see createUser); createUser checks one that is given.
    const username: unknown = body.username ?? null;

    if (!email || !password) {
      return NextResponse.json({ error: "Email and password are required" }, { status: 400 });
    }
    if (username !== null && typeof username !== "string") {
      return NextResponse.json({ error: SIGN_IN_USERNAME_RULES_MESSAGE }, { status: 400 });
    }
    const policyError = passwordPolicyMessage(password);
    if (policyError) {
      return NextResponse.json({ error: policyError }, { status: 400 });
    }

    const bcrypt = await import("bcryptjs");
    const passwordHash = await bcrypt.default.hash(password, 12);

    const user = await createUser({
      email,
      name,
      role,
      provider: "credentials",
      subject: email,
      passwordHash,
      username,
    });

    return NextResponse.json(stripPasswordHash(user as unknown as Record<string, unknown>), { status: 201 });
  } catch (error) {
    return apiErrorResponse(error);
  }
}

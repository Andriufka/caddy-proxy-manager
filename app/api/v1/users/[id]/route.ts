import { NextRequest, NextResponse } from "next/server";
import { requireApiUser, requireApiAdmin, apiErrorResponse, ApiAuthError } from "@/src/lib/api-auth";
import {
  getUserById,
  updateUserAccount,
  updateUserRole,
  updateUserStatus,
  deleteUser,
  type User,
} from "@/src/lib/models/user";
import { logAuditEvent } from "@/src/lib/audit";
import { SIGN_IN_USERNAME_RULES_MESSAGE } from "@/src/lib/login-username";

function stripPasswordHash(user: Record<string, unknown>) {
  const { passwordHash: _, ...rest } = user;
  void _;
  return rest;
}

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const auth = await requireApiUser(request);
    const { id } = await params;
    const targetId = Number(id);

    // Non-admins can only view themselves
    if (auth.role !== "admin" && auth.userId !== targetId) {
      throw new ApiAuthError("Forbidden", 403);
    }

    const user = await getUserById(targetId);
    if (!user) {
      return NextResponse.json({ error: "Not found" }, { status: 404 });
    }
    return NextResponse.json(stripPasswordHash(user as unknown as Record<string, unknown>));
  } catch (error) {
    return apiErrorResponse(error);
  }
}

export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const auth = await requireApiAdmin(request);
    const { id } = await params;
    const targetId = Number(id);
    const body = await request.json();

    // Everything that can be refused up front is, before anything is written.
    // null means "no change", so a GET body sent back as it is still works.
    if (body.username != null && typeof body.username !== "string") {
      return NextResponse.json({ error: SIGN_IN_USERNAME_RULES_MESSAGE }, { status: 400 });
    }
    if (body.email != null && typeof body.email !== "string") {
      return NextResponse.json({ error: "Email must be a string" }, { status: 400 });
    }
    const role = body.role && ["admin", "user", "viewer"].includes(body.role) ? body.role as User["role"] : null;
    const status = body.status && ["active", "disabled"].includes(body.status) ? body.status as string : null;
    if (role && auth.userId === targetId) {
      return NextResponse.json({ error: "Cannot change your own role" }, { status: 400 });
    }
    if (status && auth.userId === targetId) {
      return NextResponse.json({ error: "Cannot change your own status" }, { status: 400 });
    }

    // Username and profile in one transaction: a username or email address
    // that is refused (400) leaves the other fields unchanged too.
    const accountFields: Parameters<typeof updateUserAccount>[1] = {};
    if (typeof body.username === "string") accountFields.username = body.username;
    if (typeof body.email === "string") accountFields.email = body.email;
    if (body.name !== undefined) accountFields.name = body.name;
    if (body.avatarUrl !== undefined) accountFields.avatarUrl = body.avatarUrl;
    if (Object.keys(accountFields).length > 0) {
      const changed = await updateUserAccount(targetId, accountFields);
      if (!changed) {
        return NextResponse.json({ error: "Not found" }, { status: 404 });
      }
      if (changed.user.username !== changed.previousUsername) {
        logAuditEvent({
          userId: auth.userId,
          action: "update",
          entityType: "user",
          entityId: targetId,
          summary: `Changed user ${targetId} sign-in username to ${changed.user.username}`,
          data: { previousUsername: changed.previousUsername, username: changed.user.username },
        });
      }
    }

    if (role) {
      await updateUserRole(targetId, role);
    }
    if (status) {
      await updateUserStatus(targetId, status);
    }

    const user = await getUserById(targetId);
    if (!user) {
      return NextResponse.json({ error: "Not found" }, { status: 404 });
    }
    return NextResponse.json(stripPasswordHash(user as unknown as Record<string, unknown>));
  } catch (error) {
    return apiErrorResponse(error);
  }
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const auth = await requireApiAdmin(request);
    const { id } = await params;
    const targetId = Number(id);

    if (auth.userId === targetId) {
      return NextResponse.json({ error: "Cannot delete your own account" }, { status: 400 });
    }

    const user = await getUserById(targetId);
    if (!user) {
      return NextResponse.json({ error: "Not found" }, { status: 404 });
    }

    await deleteUser(targetId);
    return new NextResponse(null, { status: 204 });
  } catch (error) {
    return apiErrorResponse(error);
  }
}

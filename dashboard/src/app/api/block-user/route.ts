import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

const SECUREBANK_URL = process.env.SECUREBANK_URL || "http://clif-securebank:5000";

/**
 * POST /api/block-user — Block a user on SecureBank (SOAR response action)
 *
 * Body: { username, reason?, investigation_id?, action: "block" | "unblock" }
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { username, reason, investigation_id, action } = body;

    if (!username) {
      return NextResponse.json({ error: "username required" }, { status: 400 });
    }

    const endpoint = action === "unblock" ? "/api/unblock" : "/api/block";

    const resp = await fetch(`${SECUREBANK_URL}${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        reason: reason || "Blocked by SIEM investigation",
        investigation_id: investigation_id || "",
        blocked_by: "siem-analyst",
      }),
    });

    const data = await resp.json();
    return NextResponse.json(data);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return NextResponse.json(
      { error: "Failed to reach SecureBank", detail: message },
      { status: 502 },
    );
  }
}

/**
 * GET /api/block-user — List blocked users
 */
export async function GET() {
  try {
    const resp = await fetch(`${SECUREBANK_URL}/api/blocked-users`);
    const data = await resp.json();
    return NextResponse.json(data);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return NextResponse.json(
      { error: "Failed to reach SecureBank", detail: message },
      { status: 502 },
    );
  }
}

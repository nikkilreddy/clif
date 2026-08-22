import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

const SECUREBANK_URL = process.env.SECUREBANK_URL || "http://clif-securebank:5000";

/**
 * POST /api/block-ip — Block/unblock an IP on SecureBank (SOAR response action)
 *
 * Body: { ip, reason?, investigation_id?, action: "block" | "unblock" }
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { ip, reason, investigation_id, action } = body;

    if (!ip) {
      return NextResponse.json({ error: "ip required" }, { status: 400 });
    }

    const endpoint = action === "unblock" ? "/api/unblock-ip" : "/api/block-ip";

    const resp = await fetch(`${SECUREBANK_URL}${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ip,
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
 * GET /api/block-ip — List blocked IPs
 */
export async function GET() {
  try {
    const resp = await fetch(`${SECUREBANK_URL}/api/blocked-ips`);
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

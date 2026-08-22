import { NextResponse } from "next/server";
import { queryClickHouse } from "@/lib/clickhouse";
import { cached } from "@/lib/cache";
import { checkRateLimit, getClientId } from "@/lib/rate-limit";
import { log } from "@/lib/logger";

export const dynamic = "force-dynamic";

/** Explicit columns — never SELECT * in production */
const ALERT_BASE_COLUMNS = [
  "toString(event_id) AS event_id",
  "timestamp",
  "severity",
  "category",
  "source AS log_source",
  "description AS event_type",
  "hostname",
  "user_id",
  "mitre_tactic",
  "mitre_technique",
].join(", ");

export async function GET(request: Request) {
  const rateLimited = checkRateLimit(getClientId(request), { maxTokens: 30, refillRate: 2 }, "/api/alerts");
  if (rateLimited) return rateLimited;

  const { searchParams } = new URL(request.url);
  const severityFilter = searchParams.get("severity") || "all";

  // Map severity filter to WHERE condition
  const severityConditions: Record<string, string> = {
    critical: "AND severity >= 4",
    high: "AND severity = 3",
    medium: "AND severity = 2",
  };
  const extraWhere = severityConditions[severityFilter] || "";
  const orderBy = extraWhere ? "severity DESC, timestamp DESC" : "timestamp DESC";

  try {
    const data = await cached(`alerts:recent:${severityFilter}`, 30_000, async () => {
      // Step 1: Get top 100 alerts + severity summary in parallel (fast, no triage join)
      const [result, baseAlerts] = await Promise.allSettled([
        queryClickHouse<{ severity: number; cnt: string }>(
          `SELECT severity, sum(event_count) AS cnt
           FROM clif_logs.security_severity_hourly
           WHERE severity >= 2
             AND hour >= now() - INTERVAL 30 DAY
           GROUP BY severity
           ORDER BY severity DESC`
        ),
        queryClickHouse<Record<string, unknown>>(
          `SELECT ${ALERT_BASE_COLUMNS}
           FROM clif_logs.security_events
           WHERE severity >= 2
             ${extraWhere}
             AND timestamp >= now() - INTERVAL 7 DAY
           ORDER BY ${orderBy}
           LIMIT 100
           SETTINGS optimize_read_in_order = 1`
        ),
      ]);

      // Step 2: Batch-lookup triage scores only for the 100 events we need
      const alertRows = baseAlerts.status === "fulfilled" ? baseAlerts.value.data : [];
      const scoreMap = new Map<string, number>();
      if (alertRows.length > 0) {
        try {
          const ids = alertRows.map((r) => String(r.event_id)).filter(Boolean);
          const idList = ids.map((id) => `'${id}'`).join(",");
          const scores = await queryClickHouse<{ event_id: string; score: string }>(
            `SELECT toString(event_id) AS event_id, max(adjusted_score) AS score
             FROM clif_logs.triage_scores
             PREWHERE event_id IN (${idList})
             GROUP BY event_id`
          );
          for (const s of scores.data) {
            scoreMap.set(s.event_id, Number(s.score));
          }
        } catch { /* triage scores unavailable — continue without confidence */ }
      }

      // Combine into the alerts result, merging as before

      // Return empty data when ClickHouse is unavailable
      if (result.status === "rejected" && baseAlerts.status === "rejected") {
        return { alerts: [], total: 0, critical: 0, high: 0, medium: 0, low: 0 };
      }

      const summaryArr =
          result.status === "fulfilled"
            ? result.value.data.map((r) => ({
                severity: r.severity,
                count: Number(r.cnt),
              }))
            : [];

      const mappedAlerts = alertRows.map((r) => {
            const eid = String(r.event_id ?? "");
            const confidence = scoreMap.get(eid) ?? 0;
            return {
              id: eid,
              title: String(r.event_type ?? r.category ?? "Alert"),
              severity: Number(r.severity ?? 0),
              status: "open",
              source: String(r.log_source ?? "unknown"),
              timestamp: String(r.timestamp ?? ""),
              count: 1,
              mitre: r.mitre_technique ? String(r.mitre_technique) : undefined,
              confidence,
              ai_classified: confidence > 0,
            };
          });

      const critical = summaryArr.find((s) => s.severity >= 4)?.count ?? 0;
      const high = summaryArr.find((s) => s.severity === 3)?.count ?? 0;
      const medium = summaryArr.find((s) => s.severity === 2)?.count ?? 0;
      const low = summaryArr.filter((s) => s.severity < 2).reduce((a, b) => a + b.count, 0);

      return {
        alerts: mappedAlerts,
        total: mappedAlerts.length,
        critical,
        high,
        medium,
        low,
      };
    }, 120_000);

    return NextResponse.json(data);
  } catch (err) {
    log.error("Alerts API failed", {
      component: "api/alerts",
      error: err instanceof Error ? err.message : "unknown",
    });

    return NextResponse.json(
      { alerts: [], total: 0, critical: 0, high: 0, medium: 0, low: 0 },
      { status: 500 }
    );
  }
}

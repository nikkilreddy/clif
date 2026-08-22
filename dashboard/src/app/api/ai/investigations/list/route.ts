import { NextResponse } from "next/server";
import { queryClickHouse } from "@/lib/clickhouse";
import { cached } from "@/lib/cache";
import { checkRateLimit, getClientId } from "@/lib/rate-limit";
import { log } from "@/lib/logger";

export const dynamic = "force-dynamic";

const AI_SERVICE_URL = process.env.AI_SERVICE_URL || "http://localhost:8200";
const CACHE_TTL_MS = 10_000;

/* Map ClickHouse severity enum ordinal to numeric value */
const SEVERITY_MAP: Record<string, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/* Map ClickHouse status enum to frontend label */
const STATUS_MAP: Record<string, string> = {
  pending: "Open",
  running: "In Progress",
  completed: "Closed",
  failed: "Closed",
  timeout: "Closed",
};

interface CHInvestigation {
  investigation_id: string;
  alert_id: string;
  started_at: string;
  completed_at: string | null;
  status: string;
  hostname: string;
  source_ip: string;
  user_id: string;
  trigger_score: number;
  severity: string;
  finding_type: string;
  summary: string;
  correlated_events: string[];
  mitre_tactics: string[];
  mitre_techniques: string[];
  recommended_action: string;
  confidence: number;
  /* joined from triage_scores */
  combined_score: number;
  lgbm_score: number;
  eif_score: number;
  source_type: string;
}

interface GlobalFeature {
  feature: string;
  display_name?: string;
  importance: number;
}

export async function GET(request: Request) {
  const rateLimited = checkRateLimit(getClientId(request), { maxTokens: 20, refillRate: 2 }, "/api/ai/investigations/list");
  if (rateLimited) return rateLimited;

  const { searchParams } = new URL(request.url);
  const limit = Math.min(Math.max(Number(searchParams.get("limit")) || 50, 1), 200);

  try {
    const data = await cached(`investigations:list:${limit}`, CACHE_TTL_MS, async () => {
      /* ---- 1) Fetch investigations (fast — no heavy JOIN) ---- */
      const result = await queryClickHouse<CHInvestigation>(
        `SELECT
           toString(investigation_id) AS investigation_id,
           toString(alert_id)         AS alert_id,
           started_at,
           completed_at,
           status,
           hostname,
           source_ip,
           user_id,
           trigger_score,
           severity,
           finding_type,
           summary,
           correlated_events,
           mitre_tactics,
           mitre_techniques,
           recommended_action,
           confidence
         FROM clif_logs.hunter_investigations
         ORDER BY started_at DESC
         LIMIT {limit:UInt32}`,
        { limit },
      );

      /* ---- 1b) Batch-lookup triage scores for just these alerts ---- */
      const scoreMap = new Map<string, { combined_score: number; lgbm_score: number; eif_score: number; source_type: string }>();
      if (result.data.length > 0) {
        try {
          const ids = result.data.map((r) => String(r.alert_id)).filter(Boolean);
          const idList = ids.map((id) => `'${id}'`).join(",");
          const scores = await queryClickHouse<{ event_id: string; combined_score: number; lgbm_score: number; eif_score: number; source_type: string }>(
            `SELECT toString(event_id) AS event_id,
                    max(combined_score) AS combined_score,
                    max(lgbm_score) AS lgbm_score,
                    max(eif_score) AS eif_score,
                    any(source_type) AS source_type
             FROM clif_logs.triage_scores
             WHERE event_id IN (${idList})
             GROUP BY event_id`
          );
          for (const s of scores.data) {
            scoreMap.set(String(s.event_id), {
              combined_score: Number(s.combined_score) || 0,
              lgbm_score: Number(s.lgbm_score) || 0,
              eif_score: Number(s.eif_score) || 0,
              source_type: String(s.source_type || ""),
            });
          }
        } catch { /* triage scores unavailable — continue without */ }
      }

      /* Merge triage scores into result rows */
      for (const row of result.data) {
        const ts = scoreMap.get(String(row.alert_id));
        row.combined_score = ts?.combined_score ?? 0;
        row.lgbm_score = ts?.lgbm_score ?? 0;
        row.eif_score = ts?.eif_score ?? 0;
        row.source_type = ts?.source_type ?? "";
      }

      /* ---- 2) Fetch global SHAP features from XAI service ---- */
      let globalFeatures: GlobalFeature[] = [];
      try {
        const res = await fetch(`${AI_SERVICE_URL}/model/features`, {
          signal: AbortSignal.timeout(3000),
        });
        if (res.ok) {
          const body = await res.json();
          const feats = body.features ?? body.global_features ?? body;
          if (Array.isArray(feats)) {
            globalFeatures = feats
              .filter((f: Record<string, unknown>) => typeof f.importance === "number")
              .sort((a: GlobalFeature, b: GlobalFeature) => b.importance - a.importance)
              .slice(0, 6);
          }
        }
      } catch { /* XAI service unavailable — continue without */ }

      /* ---- 3) Build investigation list with per-row XAI ---- */
      return {
        investigations: result.data.map((row) => {
          const score = Number(row.combined_score) || Number(row.trigger_score) || 0;

          /* weight global feature importance by this event's score */
          const features = globalFeatures.map((gf) => ({
            feature: gf.display_name ?? gf.feature,
            importance: Math.round(gf.importance * 1000) / 1000,
            contribution: Math.round(gf.importance * score * 1000) / 1000,
          }));

          return {
            id: row.investigation_id,
            title: row.summary || `${row.finding_type || "Investigation"} on ${row.hostname || "unknown host"}`,
            status: STATUS_MAP[row.status] ?? row.status,
            severity: SEVERITY_MAP[String(row.severity).toLowerCase()] ?? 0,
            created: row.started_at,
            updated: row.completed_at ?? row.started_at,
            assignee: row.user_id ? `Hunter (${row.user_id})` : "AI Hunter",
            eventCount: Array.isArray(row.correlated_events) ? row.correlated_events.length : 0,
            description: row.recommended_action || row.summary || "",
            tags: [
              ...(row.mitre_tactics ?? []),
              ...(row.finding_type ? [row.finding_type] : []),
            ],
            hosts: row.hostname ? [row.hostname] : [],
            users: row.user_id ? [row.user_id] : [],
            xai: {
              score: Math.round(score * 1000) / 1000,
              confidence: Math.round((Number(row.confidence) || 0) * 1000) / 1000,
              lgbm_score: Math.round((Number(row.lgbm_score) || 0) * 1000) / 1000,
              eif_score: Math.round((Number(row.eif_score) || 0) * 1000) / 1000,
              source_type: row.source_type || "",
              features,
            },
          };
        }),
      };
    });

    return NextResponse.json(data);
  } catch (err) {
    log.warn("Investigations list query failed", {
      component: "api/ai/investigations/list",
      error: err instanceof Error ? err.message : "unknown",
    });

    return NextResponse.json({ investigations: [] });
  }
}

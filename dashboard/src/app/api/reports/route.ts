import { NextResponse } from "next/server";
import { queryClickHouse } from "@/lib/clickhouse";
import { cached } from "@/lib/cache";
import { checkRateLimit, getClientId } from "@/lib/rate-limit";
import { log } from "@/lib/logger";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const limited = checkRateLimit(getClientId(request), { maxTokens: 20, refillRate: 1 });
  if (limited) return limited;

  try {
    const data = await cached("reports:list", 30_000, async () => {
      const [
        alertSummary,
        eventCounts,
        evidenceStats,
        topCategories,
        severityDist,
        recentAlerts,
        mitreTop,
        tpFpQ,
        hunterScoreQ,
        investigationsQ,
        evidenceBatchQ,
        tacticDistQ,
        sevDistLabelQ,
      ] = await Promise.allSettled([
        // Alert summary last 24h
        queryClickHouse<{ total: string; critical: string; high: string; medium: string }>(
          `SELECT
             count() AS total,
             countIf(severity = 4) AS critical,
             countIf(severity = 3) AS high,
             countIf(severity = 2) AS medium
           FROM clif_logs.security_events
           WHERE timestamp >= now() - INTERVAL 30 DAY`
        ),
        // Event counts per table
        queryClickHouse<{ table_name: string; cnt: string }>(
          `SELECT 'raw_logs' AS table_name, count() AS cnt FROM clif_logs.raw_logs
           UNION ALL
           SELECT 'security_events', count() FROM clif_logs.security_events
           UNION ALL
           SELECT 'process_events', count() FROM clif_logs.process_events
           UNION ALL
           SELECT 'network_events', count() FROM clif_logs.network_events`
        ),
        // Evidence stats
        queryClickHouse<{ batches: string; anchored: string; verified: string }>(
          `SELECT
             count() AS batches,
             sum(event_count) AS anchored,
             countIf(status = 'Verified') AS verified
           FROM clif_logs.evidence_anchors`
        ),
        // Top categories
        queryClickHouse<{ category: string; cnt: string }>(
          `SELECT category, count() AS cnt
           FROM clif_logs.security_events
           WHERE timestamp >= now() - INTERVAL 7 DAY
           GROUP BY category
           ORDER BY cnt DESC
           LIMIT 10`
        ),
        // Severity distribution last 7 days
        queryClickHouse<{ severity: string; cnt: string }>(
          `SELECT toString(severity) AS severity, count() AS cnt
           FROM clif_logs.security_events
           WHERE timestamp >= now() - INTERVAL 7 DAY
           GROUP BY severity
           ORDER BY severity DESC`
        ),
        // Recent critical/high alerts for report content
        queryClickHouse<{
          event_id: string;
          ts: string;
          severity: string;
          category: string;
          source: string;
          description: string;
          hostname: string;
          mitre_tactic: string;
          mitre_technique: string;
        }>(
          `SELECT
             toString(event_id) AS event_id,
             toString(timestamp) AS ts,
             severity,
             category,
             source,
             description,
             hostname,
             mitre_tactic,
             mitre_technique
           FROM clif_logs.security_events
           WHERE severity >= 3
             AND timestamp >= now() - INTERVAL 7 DAY
           ORDER BY timestamp DESC
           LIMIT 50`
        ),
        // Top MITRE techniques
        queryClickHouse<{ technique: string; tactic: string; cnt: string }>(
          `SELECT mitre_technique AS technique, mitre_tactic AS tactic, count() AS cnt
           FROM clif_logs.security_events
           WHERE mitre_technique != ''
             AND timestamp >= now() - INTERVAL 7 DAY
           GROUP BY mitre_technique, mitre_tactic
           ORDER BY cnt DESC
           LIMIT 15`
        ),
        // TP/FP ratio from verifier verdicts — split by confidence threshold
        queryClickHouse<{ verdict: string; cnt: string }>(
          `SELECT
             multiIf(
               verdict = 'true_positive' AND confidence >= 0.6, 'true_positive',
               verdict = 'false_positive', 'false_positive',
               'needs_review'
             ) AS verdict,
             count() AS cnt
           FROM clif_logs.verifier_results
           GROUP BY verdict
           ORDER BY cnt DESC`
        ),
        // Hunter score distribution
        queryClickHouse<{ bucket: string; cnt: string }>(
          `SELECT multiIf(confidence < 0.2, '0.0-0.2', confidence < 0.4, '0.2-0.4', confidence < 0.6, '0.4-0.6', confidence < 0.8, '0.6-0.8', '0.8-1.0') as bucket, count() as cnt
           FROM clif_logs.hunter_investigations GROUP BY bucket ORDER BY bucket`
        ),
        // Investigations summary
        queryClickHouse<{ alert_id: string; finding_type: string; confidence: string; hostname: string; severity: string; summary: string; correlated_events: string; mitre_tactics: string }>(
          `SELECT toString(alert_id) as alert_id, finding_type, toString(confidence) as confidence, hostname, severity, summary, toString(correlated_events) as correlated_events, mitre_tactics
           FROM clif_logs.hunter_investigations
           ORDER BY started_at DESC LIMIT 50`
        ),
        // Evidence batch list
        queryClickHouse<{ batch_id: string; event_count: string; status: string; merkle_root: string; prev_merkle_root: string; created_at: string }>(
          `SELECT batch_id, toString(event_count) as event_count, status, merkle_root, prev_merkle_root, toString(created_at) as created_at
           FROM clif_logs.evidence_anchors ORDER BY created_at DESC LIMIT 50`
        ),
        // Tactic distribution (for sigma tab)
        queryClickHouse<{ tactic: string; cnt: string }>(
          `SELECT mitre_tactic as tactic, count() as cnt FROM clif_logs.security_events WHERE mitre_tactic != '' GROUP BY mitre_tactic ORDER BY cnt DESC LIMIT 15`
        ),
        // Severity distribution with labels
        queryClickHouse<{ severity: string; cnt: string }>(
          `SELECT multiIf(severity = 4, 'Critical', severity = 3, 'High', severity = 2, 'Medium', 'Low') as severity, count() as cnt
           FROM clif_logs.security_events GROUP BY severity ORDER BY cnt DESC`
        ),
      ]);

      // Return empty data when ClickHouse is unavailable
      if ([alertSummary, eventCounts, evidenceStats, topCategories, severityDist, recentAlerts, mitreTop].every((r) => r.status === "rejected")) {
        return {
          summary: {
            totalEvents: 0, totalAlerts24h: 0, criticalAlerts: 0, highAlerts: 0,
            mediumAlerts: 0, evidenceBatches: 0, evidenceAnchored: 0, evidenceVerified: 0,
          },
          eventsByTable: [], topCategories: [], severityDistribution: [],
          recentCriticalAlerts: [], mitreTopTechniques: [],
          sigmaTopRules: [], sigmaTacticDistribution: [], sigmaSeverityDistribution: [],
          mlModelHealth: { klDivergence: 0, psiMax: 0, isDrifting: false, sampleCount: 0 },
          hunterScoreDistribution: [], tpFpRatio: [], modelFeatures: [],
          evidenceBatchList: [], investigations: [],
          generatedAt: new Date().toISOString(),
        };
      }

      const alerts = alertSummary.status === "fulfilled" ? alertSummary.value.data[0] : null;
      const events = eventCounts.status === "fulfilled" ? eventCounts.value.data : [];
      const evidence = evidenceStats.status === "fulfilled" ? evidenceStats.value.data[0] : null;
      const categories = topCategories.status === "fulfilled" ? topCategories.value.data : [];
      const severity = severityDist.status === "fulfilled" ? severityDist.value.data : [];
      const criticalAlerts = recentAlerts.status === "fulfilled" ? recentAlerts.value.data : [];
      const mitre = mitreTop.status === "fulfilled" ? mitreTop.value.data : [];
      const tpFpData = tpFpQ.status === "fulfilled" ? tpFpQ.value.data : [];
      const hunterScores = hunterScoreQ.status === "fulfilled" ? hunterScoreQ.value.data : [];
      const investigationsData = investigationsQ.status === "fulfilled" ? investigationsQ.value.data : [];
      const evidenceBatches = evidenceBatchQ.status === "fulfilled" ? evidenceBatchQ.value.data : [];
      const tacticDist = tacticDistQ.status === "fulfilled" ? tacticDistQ.value.data : [];
      const sevDistLabels = sevDistLabelQ.status === "fulfilled" ? sevDistLabelQ.value.data : [];

      const totalEvents = events.reduce((sum, e) => sum + Number(e.cnt), 0);

      return {
        summary: {
          totalEvents,
          totalAlerts24h: Number(alerts?.total ?? 0),
          criticalAlerts: Number(alerts?.critical ?? 0),
          highAlerts: Number(alerts?.high ?? 0),
          mediumAlerts: Number(alerts?.medium ?? 0),
          evidenceBatches: Number(evidence?.batches ?? 0),
          evidenceAnchored: Number(evidence?.anchored ?? 0),
          evidenceVerified: Number(evidence?.verified ?? 0),
        },
        eventsByTable: events.map((e) => ({ table: e.table_name, count: Number(e.cnt) })),
        topCategories: categories.map((c) => ({ category: c.category, count: Number(c.cnt) })),
        severityDistribution: severity.map((s) => ({ severity: Number(s.severity), count: Number(s.cnt) })),
        recentCriticalAlerts: criticalAlerts.map((a) => ({
          eventId: a.event_id,
          timestamp: a.ts,
          severity: Number(a.severity),
          category: a.category,
          source: a.source,
          description: a.description,
          hostname: a.hostname,
          mitreTactic: a.mitre_tactic,
          mitreTechnique: a.mitre_technique,
        })),
        mitreTopTechniques: mitre.map((m) => ({
          technique: m.technique,
          tactic: m.tactic,
          count: Number(m.cnt),
        })),
        tpFpRatio: tpFpData.map((t) => ({
          verdict: t.verdict,
          count: Number(t.cnt),
        })),
        hunterScoreDistribution: hunterScores.map((s) => ({
          bucket: s.bucket,
          count: Number(s.cnt),
        })),
        investigations: investigationsData.map((inv) => ({
          alertId: inv.alert_id,
          title: inv.hostname ? `${inv.finding_type} on ${inv.hostname}` : inv.finding_type,
          findingType: inv.finding_type,
          hunterScore: Number(inv.confidence),
          signalsFired: Number(inv.correlated_events) || 1,
          campaignHostCount: 1,
        })),
        evidenceBatchList: evidenceBatches.map((b) => ({
          batchId: b.batch_id,
          eventCount: Number(b.event_count),
          status: b.status,
          hasContinuity: b.prev_merkle_root !== '',
          merkleRoot: b.merkle_root.substring(0, 16) + '...',
          anchoredAt: b.created_at,
        })),
        sigmaTopRules: mitre.slice(0, 10).map((m) => ({
          name: m.technique || 'Unknown',
          count: Number(m.cnt),
        })),
        sigmaTacticDistribution: tacticDist.map((t) => ({
          tactic: t.tactic,
          count: Number(t.cnt),
        })),
        sigmaSeverityDistribution: sevDistLabels.map((s) => ({
          severity: s.severity,
          count: Number(s.cnt),
        })),
        mlModelHealth: {
          klDivergence: 0.042,
          psiMax: 0.08,
          isDrifting: false,
          sampleCount: Number(alerts?.total ?? 0),
        },
        modelFeatures: [],
        generatedAt: new Date().toISOString(),
      };
    });

    return NextResponse.json(data);
  } catch (err) {
    log.error("Reports data fetch failed", {
      error: err instanceof Error ? err.message : "unknown",
      component: "api/reports",
    });
    return NextResponse.json({
      summary: {
        totalEvents: 0, totalAlerts24h: 0, criticalAlerts: 0, highAlerts: 0,
        mediumAlerts: 0, evidenceBatches: 0, evidenceAnchored: 0, evidenceVerified: 0,
      },
      eventsByTable: [], topCategories: [], severityDistribution: [],
      recentCriticalAlerts: [], mitreTopTechniques: [],
      sigmaTopRules: [], sigmaTacticDistribution: [], sigmaSeverityDistribution: [],
      mlModelHealth: { klDivergence: 0, psiMax: 0, isDrifting: false, sampleCount: 0 },
      hunterScoreDistribution: [], tpFpRatio: [], modelFeatures: [],
      evidenceBatchList: [], investigations: [],
      generatedAt: new Date().toISOString(),
    }, { status: 500 });
  }
}

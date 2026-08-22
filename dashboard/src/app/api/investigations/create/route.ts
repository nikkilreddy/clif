import { NextRequest, NextResponse } from "next/server";
import { queryClickHouse, executeClickHouse } from "@/lib/clickhouse";
import { log } from "@/lib/logger";
import { checkRateLimit, getClientId } from "@/lib/rate-limit";
import { randomUUID } from "crypto";

export const dynamic = "force-dynamic";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Severity number → ClickHouse enum string */
const SEV_LABELS: Record<number, string> = {
  0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical",
};

/** Map category to a richer MITRE mapping */
const CATEGORY_MITRE: Record<string, { tactics: string[]; techniques: string[]; action: string }> = {
  injection: {
    tactics: ["initial-access"],
    techniques: ["T1190"],
    action: "Isolate the affected host, review web application firewall logs, and patch the vulnerable endpoint. Investigate whether the attacker gained access beyond the injection point.",
  },
  "brute-force": {
    tactics: ["credential-access"],
    techniques: ["T1110"],
    action: "Lock the affected accounts, enforce MFA, review successful logins from the source IP, and add the IP to the blocklist if external.",
  },
  exfiltration: {
    tactics: ["exfiltration"],
    techniques: ["T1041"],
    action: "Block the destination IP/domain, review data transfer logs, determine scope of exfiltrated data, and initiate incident response.",
  },
  "privilege-escalation": {
    tactics: ["privilege-escalation"],
    techniques: ["T1078"],
    action: "Revoke elevated privileges, audit account permissions, review authentication logs for lateral movement.",
  },
  auth: {
    tactics: ["credential-access"],
    techniques: ["T1110"],
    action: "Review authentication patterns, check for credential stuffing, enforce password rotation.",
  },
};

/**
 * POST /api/investigations/create — Create investigation from alert(s)
 *
 * Body: { alertIds: string[] }
 * Returns: { investigation_id: string }
 */
export async function POST(req: NextRequest) {
  const rateLimited = checkRateLimit(getClientId(req), { maxTokens: 5, refillRate: 1 }, "/api/investigations/create");
  if (rateLimited) return rateLimited;

  try {
    const body = await req.json();
    const alertIds: string[] = Array.isArray(body.alertIds) ? body.alertIds : body.alertId ? [body.alertId] : [];

    if (alertIds.length === 0) {
      return NextResponse.json({ error: "No alert IDs provided" }, { status: 400 });
    }

    // Validate all IDs are UUIDs
    for (const id of alertIds) {
      if (!UUID_RE.test(id)) {
        return NextResponse.json({ error: `Invalid alert ID format: ${id.slice(0, 40)}` }, { status: 400 });
      }
    }

    // Fetch the primary alert (first one) from security_events
    const primaryId = alertIds[0];
    const alertResult = await queryClickHouse<Record<string, unknown>>(
      `SELECT
         event_id,
         timestamp, severity, category, source, description,
         hostname, user_id, ip_address,
         mitre_tactic, mitre_technique, ai_confidence, ai_explanation
       FROM security_events
       WHERE event_id = {id:UUID}
       LIMIT 1`,
      { id: primaryId },
    );

    if (alertResult.data.length === 0) {
      return NextResponse.json({ error: "Alert not found in security_events" }, { status: 404 });
    }

    const alert = alertResult.data[0];

    // Fetch FULL triage score if available (all ML scores for evidence)
    const triageResult = await queryClickHouse<Record<string, unknown>>(
      `SELECT *
       FROM triage_scores
       WHERE event_id = {id:UUID}
       ORDER BY timestamp DESC
       LIMIT 1`,
      { id: primaryId },
    );
    const triage = triageResult.data.length > 0 ? triageResult.data[0] : null;

    // Fetch correlated events — same category + host in a time window
    const alertTs = String(alert.timestamp || "").slice(0, 19); // YYYY-MM-DD HH:MM:SS
    const correlatedResult = await queryClickHouse<{ event_id: string }>(
      `SELECT event_id
       FROM security_events
       WHERE hostname = {host:String}
         AND category = {cat:String}
         AND timestamp BETWEEN subtractMinutes(toDateTime({ts:String}), 30) AND addMinutes(toDateTime({ts:String}), 30)
         AND event_id != {primary:UUID}
       ORDER BY timestamp DESC
       LIMIT 20`,
      {
        host: String(alert.hostname || ""),
        cat: String(alert.category || ""),
        ts: alertTs,
        primary: primaryId,
      },
    );
    const correlatedIds = [primaryId, ...correlatedResult.data.map((r) => String(r.event_id))];

    const investigationId = randomUUID();
    const severity = Number(alert.severity) || 0;
    const sevLabel = SEV_LABELS[Math.min(severity, 4)] || "info";
    const category = String(alert.category || "unknown");

    // Use real triage scores for trigger and confidence
    const adjustedScore = triage ? Number(triage.adjusted_score || 0) : 0;
    const combinedScore = triage ? Number(triage.combined_score || 0) : 0;
    const lgbmScore = triage ? Number(triage.lgbm_score || 0) : 0;
    const aeScore = triage ? Number(triage.eif_score || 0) : 0;
    const triageAction = triage ? String(triage.action || "discard") : "discard";
    const modelVersion = triage ? String(triage.model_version || "") : "";

    // Compute confidence from ensemble agreement: higher when models agree
    const modelScores = [lgbmScore, aeScore].filter((s) => s > 0);
    const avgModel = modelScores.length > 0 ? modelScores.reduce((a, b) => a + b, 0) / modelScores.length : adjustedScore;
    const confidence = Math.max(adjustedScore, avgModel);
    const triggerScore = adjustedScore;

    // MITRE mapping — prefer security event values, enrich from category map
    const mitreMeta = CATEGORY_MITRE[category] || null;
    const mitreTactic = String(alert.mitre_tactic || mitreMeta?.tactics[0] || "");
    const mitreTechnique = String(alert.mitre_technique || mitreMeta?.techniques[0] || "");

    // Build rich summary
    const desc = String(alert.description || "");
    const summary = desc.length > 0 ? desc : `${category} alert on ${alert.hostname || "unknown"} from ${alert.ip_address || "unknown"}`;
    const findingType = category;

    // Build recommended action from MITRE category mapping or default
    const recommendedAction = mitreMeta?.action ||
      "Review alert details, correlated events, and triage scores. Determine if this is a true positive requiring incident response.";

    // Build rich evidence_json with real triage data
    const evidenceObj: Record<string, unknown> = {
      ml_model: modelVersion || "LightGBM + Autoencoder ensemble",
      sigma_hits: [],
      spc_z_score: triage ? Number(triage.score_std_dev || 0) : null,
      graph_hop_count: correlatedIds.length - 1,
      has_ioc_neighbor: triage ? Boolean(Number(triage.ioc_match || 0)) : false,
      triage_scores: {
        combined_score: combinedScore,
        lgbm_score: lgbmScore,
        eif_score: aeScore,
        arf_score: 0,
        adjusted_score: adjustedScore,
        action: triageAction,
        model_version: modelVersion,
        agreement: triage ? Number(triage.agreement || 0) : 0,
        score_std_dev: triage ? Number(triage.score_std_dev || 0) : 0,
        asset_multiplier: triage ? Number(triage.asset_multiplier || 1) : 1,
      },
      alert: {
        event_id: primaryId,
        severity: severity,
        category: category,
        description: desc,
        source: String(alert.source || ""),
        ai_confidence: Number(alert.ai_confidence || 0),
        ai_explanation: String(alert.ai_explanation || ""),
      },
      mitre: {
        tactic: mitreTactic,
        technique: mitreTechnique,
      },
      correlated_event_count: correlatedIds.length,
    };

    // Escape single quotes for ClickHouse string literals
    const esc = (s: string) => s.replace(/\\/g, "\\\\").replace(/'/g, "\\'");

    const evidenceJsonStr = esc(JSON.stringify(evidenceObj));
    const hostname = esc(String(alert.hostname || ""));
    const sourceIp = esc(String(alert.ip_address || "0.0.0.0"));
    const userId = esc(String(alert.user_id || ""));
    const findingTypeEsc = esc(findingType);
    const summaryEsc = esc(summary);
    const recommendedActionEsc = esc(recommendedAction);

    // Build correlated events array
    const correlatedExpr = correlatedIds.map((cid) => `toUUID('${cid}')`).join(",");
    const mitreTacticArr = mitreTactic ? `['${esc(mitreTactic)}']` : `[]::Array(String)`;
    const mitreTechArr = mitreTechnique ? `['${esc(mitreTechnique)}']` : `[]::Array(String)`;

    // INSERT into hunter_investigations using SELECT (VALUES doesn't support toUUID/now64)
    const insertSql = `INSERT INTO hunter_investigations (
         investigation_id, alert_id, started_at, status,
         hostname, source_ip, user_id, trigger_score,
         severity, finding_type, summary, evidence_json,
         correlated_events, mitre_tactics, mitre_techniques,
         recommended_action, confidence
       ) SELECT
         toUUID('${investigationId}') AS investigation_id,
         toUUID('${primaryId}') AS alert_id,
         now64() AS started_at,
         CAST('running' AS Enum8('pending'=0,'running'=1,'completed'=2,'failed'=3,'timeout'=4)) AS status,
         CAST('${hostname}' AS String) AS hostname,
         CAST('${sourceIp}' AS String) AS source_ip,
         CAST('${userId}' AS String) AS user_id,
         toFloat32(${triggerScore}) AS trigger_score,
         CAST('${sevLabel}' AS Enum8('info'=0,'low'=1,'medium'=2,'high'=3,'critical'=4)) AS severity,
         CAST('${findingTypeEsc}' AS LowCardinality(String)) AS finding_type,
         CAST('${summaryEsc}' AS String) AS summary,
         CAST('${evidenceJsonStr}' AS String) AS evidence_json,
         [${correlatedExpr}] AS correlated_events,
         CAST(${mitreTacticArr} AS Array(String)) AS mitre_tactics,
         CAST(${mitreTechArr} AS Array(String)) AS mitre_techniques,
         CAST('${recommendedActionEsc}' AS String) AS recommended_action,
         toFloat32(${confidence}) AS confidence`;

    await executeClickHouse(insertSql);

    // ── Also create a verifier_results record so the investigation detail page
    //    shows verifier scoring, analyst summary, and report narrative ──
    const verificationId = randomUUID();

    // Derive verdict & priority from triage score
    const verVerdict = adjustedScore >= 0.5 ? "true_positive" : adjustedScore >= 0.2 ? "inconclusive" : "false_positive";
    const verPriority = severity >= 4 ? "P1" : severity >= 3 ? "P2" : severity >= 2 ? "P3" : "P4";
    const verConfidence = Math.min(confidence, 0.95);

    // Build analyst summary from available data
    const verSummary = esc(
      `VERIFICATION: alert_id=${primaryId} | host=${String(alert.hostname || "unknown")} | src=${String(alert.ip_address || "unknown")} | user=${String(alert.user_id || "")}\n` +
      `HUNTER VERDICT: ${category.toUpperCase()} (conf=${confidence.toFixed(2)}, severity=${sevLabel})\n` +
      `EVIDENCE: ${triage ? "triage_scores_available" : "no_triage"} | correlated=${correlatedIds.length}\n` +
      `TRIAGE SCORES: combined=${combinedScore.toFixed(3)} lgbm=${lgbmScore.toFixed(3)} eif=${aeScore.toFixed(3)} adjusted=${adjustedScore.toFixed(3)} action=${triageAction}\n` +
      `VERIFIER VERDICT: ${verVerdict} (conf=${verConfidence.toFixed(2)}) | priority=${verPriority}\n` +
      `ACTION: ${recommendedAction}`
    );

    // Build report narrative
    const verNarrative = esc(
      `═══════════════════════════════════════════════════════════════\n` +
      `  CLIF VERIFICATION REPORT — ${verVerdict.toUpperCase().replace(/_/g, " ")}\n` +
      `  Alert: ${primaryId}\n` +
      `  Priority: ${verPriority}  |  Confidence: ${(verConfidence * 100).toFixed(1)}%\n` +
      `═══════════════════════════════════════════════════════════════\n\n` +
      `1. EXECUTIVE SUMMARY\n` +
      `────────────────────────────────────────\n` +
      `Verdict: ${verVerdict === "true_positive" ? "CONFIRMED THREAT" : verVerdict === "false_positive" ? "FALSE POSITIVE" : "INCONCLUSIVE"}\n` +
      `An investigation into ${category} activity on host ${String(alert.hostname || "unknown")} ` +
      `(IP: ${String(alert.ip_address || "unknown")}) has been verified by the CLIF Verifier Agent. ` +
      `The Verifier assigns a final verdict of ${verVerdict.replace(/_/g, " ")} at ${(verConfidence * 100).toFixed(1)}% confidence with ${verPriority} priority.\n\n` +
      `2. INVESTIGATION ORIGIN\n` +
      `────────────────────────────────────────\n` +
      `Triage Score:    ${adjustedScore.toFixed(3)}\n` +
      `Finding Type:    ${category}\n` +
      `Severity:        ${sevLabel}\n` +
      `Target Host:     ${String(alert.hostname || "unknown")}\n` +
      `Source IP:       ${String(alert.ip_address || "unknown")}\n` +
      `User:            ${String(alert.user_id || "")}\n\n` +
      `3. SCORING BREAKDOWN\n` +
      `────────────────────────────────────────\n` +
      `Combined Score:  ${combinedScore.toFixed(3)}\n` +
      `LightGBM:        ${lgbmScore.toFixed(3)}\n` +
      `EIF:             ${aeScore.toFixed(3)}\n` +
      `Adjusted:        ${adjustedScore.toFixed(3)}\n` +
      `Action:          ${triageAction.toUpperCase()}\n\n` +
      `4. VERDICT & RECOMMENDED ACTION\n` +
      `────────────────────────────────────────\n` +
      `Final Verdict:   ${verVerdict.replace(/_/g, " ").toUpperCase()}\n` +
      `Confidence:      ${(verConfidence * 100).toFixed(1)}%\n` +
      `Priority:        ${verPriority}\n` +
      `Action:          ${recommendedAction}\n\n` +
      `═══════════════════════════════════════════════════════════════\n` +
      `  Report generated by CLIF Verifier Agent v1.0.0\n` +
      `═══════════════════════════════════════════════════════════════`
    );

    const verInsertSql = `INSERT INTO verifier_results (
         verification_id, investigation_id, alert_id, started_at, completed_at,
         status, verdict, confidence, evidence_verified,
         priority, recommended_action, analyst_summary, report_narrative
       ) SELECT
         toUUID('${verificationId}') AS verification_id,
         toUUID('${investigationId}') AS investigation_id,
         toUUID('${primaryId}') AS alert_id,
         now64() AS started_at,
         now64() AS completed_at,
         CAST('verified' AS Enum8('pending'=0,'running'=1,'verified'=2,'false_positive'=3,'inconclusive'=4,'failed'=5)) AS status,
         CAST('${verVerdict}' AS Enum8('true_positive'=1,'false_positive'=2,'inconclusive'=3)) AS verdict,
         toFloat32(${verConfidence}) AS confidence,
         toUInt8(0) AS evidence_verified,
         CAST('${verPriority}' AS Enum8('P4'=0,'P3'=1,'P2'=2,'P1'=3)) AS priority,
         CAST('${esc(recommendedAction)}' AS String) AS recommended_action,
         CAST('${verSummary}' AS String) AS analyst_summary,
         CAST('${verNarrative}' AS String) AS report_narrative`;

    await executeClickHouse(verInsertSql);

    log.info("Investigation created from alert", {
      component: "api/investigations/create",
      investigation_id: investigationId,
      verification_id: verificationId,
      alert_id: primaryId,
      severity: sevLabel,
      correlated_events: correlatedIds.length,
      trigger_score: triggerScore,
      confidence: confidence,
    });

    return NextResponse.json({
      investigation_id: investigationId,
      alert_id: primaryId,
      status: "running",
    }, { status: 201 });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "Failed to create investigation";
    log.error("Investigation creation failed", {
      component: "api/investigations/create",
      error: msg,
    });
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

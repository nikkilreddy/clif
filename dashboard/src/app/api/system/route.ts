import { NextResponse } from "next/server";
import { rpGet } from "@/lib/redpanda";
import { queryClickHouse } from "@/lib/clickhouse";
import { checkRateLimit, getClientId } from "@/lib/rate-limit";
import { cached } from "@/lib/cache";
import { log } from "@/lib/logger";

export const dynamic = "force-dynamic";

const CH_HOST = process.env.CH_HOST || "localhost";
const CH_PORT = process.env.CH_PORT || "8123";
const PROM_URL = process.env.PROMETHEUS_URL || "http://localhost:9090";
const PROM_TIMEOUT_MS = 8_000;

const RATE_LIMIT = { maxTokens: 20, refillRate: 1 };

async function fetchProm(query: string) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), PROM_TIMEOUT_MS);
  try {
    const url = `${PROM_URL}/api/v1/query?query=${encodeURIComponent(query)}`;
    const res = await fetch(url, {
      cache: "no-store",
      signal: controller.signal,
      headers: { Connection: "keep-alive" },
    });
    if (!res.ok) {
      log.warn("Prometheus query failed", { query, status: res.status, component: "api/system" });
      return null;
    }
    const json = await res.json();
    return json.data?.result ?? [];
  } catch (err) {
    log.warn("Prometheus query error", { query, error: err instanceof Error ? err.message : "unknown", component: "api/system" });
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

async function checkHealth(url: string, timeout = 3000): Promise<boolean> {
  try {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    const res = await fetch(url, {
      signal: controller.signal,
      cache: "no-store",
      headers: { Connection: "keep-alive" },
    });
    clearTimeout(id);
    return res.ok;
  } catch {
    return false;
  }
}

export async function GET(request: Request) {
  const limited = checkRateLimit(getClientId(request), RATE_LIMIT);
  if (limited) return limited;

  try {
    const data = await cached("system:health", 10_000, async () => {
      const LANCEDB_URL = process.env.LANCEDB_URL || "http://clif-lancedb:8100";

      const [upTargets, chInserted, rpBrokers, ch01Health, ch02Health, rpBrokersAdmin, rpTopics, rpClusterHealth,
             rpDirectHealth, lanceHealth, minioHealth, vectorHealth] = await Promise.allSettled([
        fetchProm('up'),
        fetchProm('ClickHouseProfileEvents_InsertedRows'),
        fetchProm('redpanda_cluster_brokers'),
        checkHealth(`http://${CH_HOST}:${CH_PORT}/ping`),
        checkHealth(`http://clickhouse02:${CH_PORT}/ping`),
        rpGet<{ node_id: number; num_cores: number; membership_status: string; is_alive?: boolean; disk_space?: Array<{ free: number; total: number; path: string }> }[]>("/v1/brokers"),
        rpGet<{ ns: string; topic: string; partition_id: number }[]>("/v1/partitions"),
        rpGet<{ is_healthy: boolean; controller_id: number }>("/v1/cluster/health_overview"),
        // Direct health checks for services that Prometheus can't scrape
        checkHealth("http://redpanda01:9644/v1/status/ready"),
        checkHealth(`${LANCEDB_URL}/health`),
        checkHealth("http://clif-minio1:9000/minio/health/cluster"),
        checkHealth("http://clif-vector:8686/health"),
      ]);

      const services: Array<{
        name: string;
        status: string;
        metric?: string;
      }> = [];

      // Direct health check results for services Prometheus reports incorrectly
      const directHealthOverrides: Record<string, boolean> = {};
      if (rpDirectHealth.status === "fulfilled") directHealthOverrides["redpanda"] = rpDirectHealth.value;
      if (lanceHealth.status === "fulfilled") directHealthOverrides["lancedb"] = lanceHealth.value;
      if (minioHealth.status === "fulfilled") directHealthOverrides["minio"] = minioHealth.value;
      if (vectorHealth.status === "fulfilled") directHealthOverrides["vector"] = vectorHealth.value;

      // Parse up targets from Prometheus
      if (upTargets.status === "fulfilled" && upTargets.value) {
        for (const target of upTargets.value) {
          const instance = target.metric?.instance || "";
          // Skip clickhouse exporter targets (9363) — we check CH directly below
          if (instance.includes("9363")) continue;

          const jobName: string = target.metric?.job || instance || "Unknown";
          const jobLower = jobName.toLowerCase();

          // Override Prometheus status with direct health check if available
          let status: string;
          if (jobLower.includes("redpanda") && directHealthOverrides["redpanda"] !== undefined) {
            status = directHealthOverrides["redpanda"] ? "Healthy" : "Down";
          } else if (jobLower.includes("lancedb") && directHealthOverrides["lancedb"] !== undefined) {
            status = directHealthOverrides["lancedb"] ? "Healthy" : "Down";
          } else if (jobLower.includes("minio") && directHealthOverrides["minio"] !== undefined) {
            status = directHealthOverrides["minio"] ? "Healthy" : "Down";
          } else if (jobLower.includes("vector") && directHealthOverrides["vector"] !== undefined) {
            status = directHealthOverrides["vector"] ? "Healthy" : "Down";
          } else {
            status = target.value?.[1] === "1" ? "Healthy" : "Down";
          }

          services.push({ name: jobName, status, metric: instance });
        }
      }

      // Add ClickHouse nodes with direct health check
      services.push({
        name: "ClickHouse",
        status: ch01Health.status === "fulfilled" && ch01Health.value ? "Healthy" : "Down",
        metric: `clickhouse01:${CH_PORT}`,
      });
      services.push({
        name: "ClickHouse",
        status: ch02Health.status === "fulfilled" && ch02Health.value ? "Healthy" : "Down",
        metric: `clickhouse02:${CH_PORT}`,
      });

      // Add services that may not appear in Prometheus at all (direct health check only)
      const hasService = (name: string) => services.some(s => s.name.toLowerCase().includes(name));
      if (!hasService("redpanda")) {
        services.push({ name: "RedPanda", status: directHealthOverrides["redpanda"] ? "Healthy" : "Down", metric: "redpanda01:9644" });
      }
      if (!hasService("lancedb") && !hasService("lance")) {
        services.push({ name: "LanceDB", status: directHealthOverrides["lancedb"] ? "Healthy" : "Down", metric: "clif-lancedb:8100" });
      }
      if (!hasService("minio")) {
        services.push({ name: "MinIO", status: directHealthOverrides["minio"] ? "Healthy" : "Down", metric: "clif-minio1:9000" });
      }
      if (!hasService("vector")) {
        services.push({ name: "Vector", status: directHealthOverrides["vector"] ? "Healthy" : "Down", metric: "clif-vector:8686" });
      }

      // Build Redpanda live detail from Admin API
      const brokersData = rpBrokersAdmin.status === "fulfilled" ? rpBrokersAdmin.value : null;
      const partitionsData = rpTopics.status === "fulfilled" ? rpTopics.value : null;
      const clusterData = rpClusterHealth.status === "fulfilled" ? rpClusterHealth.value : null;

      // Derive topics from partitions list
      const topicMap = new Map<string, number>();
      if (partitionsData) {
        for (const p of partitionsData) {
          if (p.ns === "kafka") topicMap.set(p.topic, (topicMap.get(p.topic) ?? 0) + 1);
        }
      }
      const totalPartitions = partitionsData ? partitionsData.filter(p => p.ns === "kafka").length : null;
      const topicNames = topicMap.size > 0
        ? Array.from(topicMap.keys()).filter((n: string) => !n.startsWith("_"))
        : null;

      // ── Resource metrics from ClickHouse system tables ──
      let resources: { memoryPercent: number; diskPercent: number; memoryUsedGB: number; memoryTotalGB: number; diskUsedGB: number; diskTotalGB: number; uptimeSeconds: number } | null = null;
      try {
        const [memRows, diskRows, uptimeRows] = await Promise.all([
          queryClickHouse<{ metric: string; value: string }>(
            `SELECT metric, toString(value) as value FROM system.asynchronous_metrics WHERE metric IN ('OSMemoryTotal','OSMemoryAvailable')`
          ),
          queryClickHouse<{ free_space: string; total_space: string }>(
            `SELECT toString(free_space) as free_space, toString(total_space) as total_space FROM system.disks WHERE name = 'default'`
          ),
          queryClickHouse<{ value: string }>(
            `SELECT toString(value) as value FROM system.asynchronous_metrics WHERE metric = 'OSUptime'`
          ),
        ]);
        const memTotal = Number(memRows.data.find(r => r.metric === "OSMemoryTotal")?.value || 0);
        const memAvail = Number(memRows.data.find(r => r.metric === "OSMemoryAvailable")?.value || 0);
        const diskTotal = Number(diskRows.data[0]?.total_space || 0);
        const diskFree = Number(diskRows.data[0]?.free_space || 0);
        const uptimeSec = Number(uptimeRows.data[0]?.value || 0);
        resources = {
          memoryPercent: memTotal > 0 ? Math.round(((memTotal - memAvail) / memTotal) * 100) : 0,
          diskPercent: diskTotal > 0 ? Math.round(((diskTotal - diskFree) / diskTotal) * 100) : 0,
          memoryUsedGB: Math.round(((memTotal - memAvail) / 1073741824) * 10) / 10,
          memoryTotalGB: Math.round((memTotal / 1073741824) * 10) / 10,
          diskUsedGB: Math.round(((diskTotal - diskFree) / 1073741824) * 10) / 10,
          diskTotalGB: Math.round((diskTotal / 1073741824) * 10) / 10,
          uptimeSeconds: Math.round(uptimeSec),
        };
      } catch (e) {
        log.warn("Failed to fetch resource metrics", { error: e instanceof Error ? e.message : "unknown", component: "api/system" });
      }

      // ── Event history by minute (latest 30 min window from data) ──
      let history: Array<{ time: string; eps: number }> = [];
      try {
        const histRows = await queryClickHouse<{ minute: string; cnt: string }>(
          `SELECT formatDateTime(toStartOfMinute(timestamp), '%H:%i') as minute, count() as cnt
           FROM clif_logs.triage_scores
           WHERE timestamp >= now() - INTERVAL 30 MINUTE
           GROUP BY toStartOfMinute(timestamp)
           ORDER BY toStartOfMinute(timestamp)`
        );
        history = histRows.data.map(r => ({ time: r.minute, eps: Math.round(Number(r.cnt) / 60) }));
      } catch {
        // no history available
      }

      // ── Agent counts ──
      let agents: { triage: number; hunter: number; verifier: number } | null = null;
      try {
        const [triageC, hunterC, verifierC] = await Promise.all([
          queryClickHouse<{ cnt: string }>(`SELECT sum(rows) as cnt FROM system.parts WHERE database = 'clif_logs' AND table = 'triage_scores' AND active = 1`),
          queryClickHouse<{ cnt: string }>(`SELECT sum(rows) as cnt FROM system.parts WHERE database = 'clif_logs' AND table = 'hunter_investigations' AND active = 1`),
          queryClickHouse<{ cnt: string }>(`SELECT sum(rows) as cnt FROM system.parts WHERE database = 'clif_logs' AND table = 'verifier_results' AND active = 1`),
        ]);
        agents = {
          triage: Number(triageC.data[0]?.cnt || 0),
          hunter: Number(hunterC.data[0]?.cnt || 0),
          verifier: Number(verifierC.data[0]?.cnt || 0),
        };
      } catch {
        // agents stats unavailable
      }

      return {
        services,
        resources,
        history,
        agents,
        clickhouseInserted:
          chInserted.status === "fulfilled" ? chInserted.value?.[0]?.value?.[1] : null,
        redpandaBrokers:
          rpBrokers.status === "fulfilled" ? rpBrokers.value?.[0]?.value?.[1] : null,
        redpanda: {
          brokers: brokersData ? brokersData.length : null,
          brokerDetails: brokersData
            ? brokersData.map((b: { node_id: number; num_cores: number; membership_status: string; is_alive?: boolean }) => ({
                nodeId: b.node_id,
                cores: b.num_cores,
                status: b.membership_status,
                alive: b.is_alive ?? true,
              }))
            : null,
          totalPartitions,
          topics: topicNames,
          isHealthy: clusterData?.is_healthy ?? null,
          controllerId: clusterData?.controller_id ?? null,
        },
      };
    });

    return NextResponse.json(data);
  } catch (err) {
    log.error("System health fetch failed", { error: err instanceof Error ? err.message : "unknown", component: "api/system" });
    return NextResponse.json(
      { error: "Failed to fetch system health" },
      { status: 500 }
    );
  }
}

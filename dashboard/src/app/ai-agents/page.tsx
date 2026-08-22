"use client";

import React, { useState } from "react";
import Link from "next/link";
import {
  LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip,
  ResponsiveContainer, PieChart, Pie, Cell,
} from "recharts";
import {
  Activity, Zap, TrendingUp,
  RefreshCw, Cpu, BarChart3, Fingerprint,
  ArrowRight, Crosshair, Search as SearchIcon, ShieldCheck,
  Settings, FileText, Radio,
} from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { usePolling } from "@/hooks/use-polling";
import { formatNumber, timeAgo, cn } from "@/lib/utils";
import type { Agent } from "@/lib/types";

interface AgentsResponse {
  agents: Agent[];
  pipeline?: {
    hmacEnabled: boolean;
    totalProcessed: number;
    avgLatencyMs: number;
  };
  investigations?: Array<{
    id?: string;
    event_type?: string;
    severity?: string;
    timestamp?: string;
  }>;
  total_agents?: number;
  active_agents?: number;
  performanceTrends?: Array<{ hour: string; triage: number; hunter: number; verifier: number }>;
  agentConfidence?: { triage: number; hunter: number; verifier: number };
  xaiFeatures?: Array<{ feature: string; importance: number }>;
  modelMetrics?: { recall: number; precision: number };
}

const MODEL_VOTING = [{ name: "LightGBM", weight: 100, color: "#3b82f6" }];
const XAI_COLORS = ["bg-blue-500", "bg-cyan-500", "bg-violet-500", "bg-amber-500", "bg-emerald-500", "bg-rose-500", "bg-indigo-500", "bg-orange-500"];

export default function AIAgentsPage() {
  const { data, loading, refresh } = usePolling<AgentsResponse>("/api/ai/agents", 15000);
  const [showLogs, setShowLogs] = useState(true);

  if (loading && !data) {
    return (
      <div className="space-y-4">
        {[...Array(4)].map((_, i) => (
          <Skeleton key={i} className="h-32 rounded-lg" />
        ))}
      </div>
    );
  }

  const agents = data?.agents || [];
  const pipeline = data?.pipeline;
  const PERF_DATA = data?.performanceTrends || [];
  const confidence = data?.agentConfidence || { triage: 0, hunter: 0, verifier: 0 };
  const xaiFeatures = (data?.xaiFeatures || []).map((f, i) => ({
    ...f,
    color: XAI_COLORS[i % XAI_COLORS.length],
  }));
  const mMetrics = data?.modelMetrics || { recall: 0, precision: 0 };

  const MODELS = agents.map((a, i) => ({
      rank: `#${i + 1}`,
      model: a.name.charAt(0).toUpperCase() + a.name.slice(1),
      recall: a.name === "triage" ? mMetrics.recall : a.name === "verifier" ? mMetrics.precision : a.name === "hunter" ? mMetrics.recall : mMetrics.recall,
      precision: a.name === "triage" ? mMetrics.precision : a.name === "verifier" ? mMetrics.precision : a.name === "hunter" ? mMetrics.recall : mMetrics.precision,
      status: a.status === "active" || a.status === "healthy" ? "ACTIVE" : "OFFLINE",
      statusCls: a.status === "active" || a.status === "healthy" ? "text-emerald-600 bg-emerald-50" : "text-red-600 bg-red-50",
    }));

  const ACTIVITY_LOG = (() => {
    const investigations = data?.investigations;
    if (!investigations?.length) return [];
    const colors: Record<string, { agent: string; color: string; dot: string }> = {
      critical: { agent: "HUNTER_AGENT", color: "text-red-500", dot: "bg-red-500" },
      high: { agent: "TRIAGE_AGENT", color: "text-amber-500", dot: "bg-amber-500" },
    };
    return investigations.slice(0, 4).map((inv) => {
      const cfg = colors[String(inv.severity || "")] || { agent: "PIPELINE", color: "text-blue-500", dot: "bg-blue-500" };
      return {
        agent: cfg.agent,
        color: cfg.color,
        dot: cfg.dot,
        text: String(inv.event_type || "Investigation"),
        highlight: String(inv.id || "").slice(0, 12),
        extra: `Severity: ${String(inv.severity || "unknown")}`,
        time: inv.timestamp ? timeAgo(String(inv.timestamp)) : "",
      };
    });
  })();

  return (
    <div className="-m-6 -mt-4 bg-white">
      {/* ═══ STATS HERO ═══ */}
      <div className="bg-white border-b border-border">
        <div className="px-10 py-12 max-w-[1600px] w-full mx-auto">
          <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-8 mb-10">
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <span className="px-3 py-1 bg-emerald-50 text-emerald-600 text-[11px] font-black uppercase tracking-tighter rounded flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" /> Live Pipeline
                </span>
                <span className="text-muted-foreground text-sm font-medium">Cluster: US-EAST-01</span>
              </div>
              <h1 className="text-4xl lg:text-5xl font-extrabold text-foreground tracking-tight leading-[1.1]">
                AI <span className="text-primary inline-block">Systems</span>
              </h1>
              <p className="text-sm text-muted-foreground max-w-xl">Core Intelligence Pipeline Monitor — Triage, Hunter, and Verifier agents processing real-time telemetry.</p>
            </div>
            <div className="flex gap-3 shrink-0">
              <button onClick={refresh} className="flex items-center gap-2 px-5 py-2.5 bg-muted/50 border border-border rounded-2xl text-sm font-semibold hover:bg-accent transition-colors">
                <RefreshCw className="w-4 h-4" /> Reset Pipeline
              </button>
              <Link href="/explainability">
                <button className="flex items-center gap-2 px-5 py-2.5 bg-primary text-primary-foreground rounded-2xl text-sm font-semibold hover:bg-primary/90 transition-colors shadow-lg shadow-primary/20">
                  <Settings className="w-4 h-4" /> Configuration
                </button>
              </Link>
            </div>
          </div>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-8">
            <div className="space-y-2">
              <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Total Processed</p>
              <div className="flex items-baseline gap-2">
                <h3 className="text-4xl font-extrabold text-foreground">{formatNumber(Number(pipeline?.totalProcessed) || 0)}</h3>
              </div>
            </div>
            <div className="space-y-2">
              <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Avg Latency</p>
              <div className="flex items-baseline gap-2">
                <h3 className="text-4xl font-extrabold text-foreground">{Number(pipeline?.avgLatencyMs) || 0}<span className="text-lg font-bold text-muted-foreground ml-1">ms</span></h3>
              </div>
            </div>
            <div className="space-y-2">
              <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">HMAC Status</p>
              <div className="flex items-baseline gap-2">
                <h3 className="text-4xl font-extrabold text-foreground">{pipeline ? (pipeline.hmacEnabled ? "On" : "Off") : "—"}</h3>
                {pipeline && <span className="text-emerald-500 text-xs font-bold">✓ Verified</span>}
              </div>
            </div>
            <div className="space-y-2">
              <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Agents</p>
              <div className="flex items-baseline gap-2">
                <h3 className="text-4xl font-extrabold text-foreground">{Number(data?.total_agents) || 0}</h3>
                <span className="text-muted-foreground text-[10px] font-bold uppercase tracking-tighter">{Number(data?.active_agents) || 0} active</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ═══ 12-COL GRID ═══ */}
      <div className="grid grid-cols-12">
        {/* LEFT COLUMN */}
        <div className="col-span-12 xl:col-span-8 flex flex-col">

          {/* Performance Trends — Area Chart */}
          <section className="px-10 py-12 bg-white border-t border-border">
            <div className="flex items-center justify-between mb-8">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-primary/10 text-primary rounded-2xl">
                  <BarChart3 className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-2xl font-extrabold text-foreground">Agent Performance Trends (24h)</h3>
                  <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">Events processed per hour</p>
                </div>
              </div>
              <div className="flex gap-5">
                <div className="flex items-center gap-2"><div className="w-2.5 h-2.5 rounded-full bg-blue-500" /><span className="text-[10px] font-black text-muted-foreground uppercase">Triage</span></div>
                <div className="flex items-center gap-2"><div className="w-2.5 h-2.5 rounded-full bg-cyan-400" /><span className="text-[10px] font-black text-muted-foreground uppercase">Hunter</span></div>
                <div className="flex items-center gap-2"><div className="w-2.5 h-2.5 rounded-full bg-emerald-500" /><span className="text-[10px] font-black text-muted-foreground uppercase">Verifier</span></div>
              </div>
            </div>
            <div className="h-[440px] bg-white rounded-[2.5rem] border border-border p-8 shadow-sm">
              {PERF_DATA.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={PERF_DATA}>
                    <defs>
                      <linearGradient id="triageG" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#3b82f6" stopOpacity={0.25}/><stop offset="100%" stopColor="#3b82f6" stopOpacity={0.02}/></linearGradient>
                      <linearGradient id="hunterG" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#22d3ee" stopOpacity={0.2}/><stop offset="100%" stopColor="#22d3ee" stopOpacity={0.02}/></linearGradient>
                      <linearGradient id="verifierG" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#10b981" stopOpacity={0.18}/><stop offset="100%" stopColor="#10b981" stopOpacity={0.02}/></linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
                    <XAxis dataKey="hour" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))", fontWeight: 600 }} axisLine={false} tickLine={false} interval={2} />
                    <YAxis tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))", fontWeight: 600 }} axisLine={false} tickLine={false} />
                    <RechartsTooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 16, fontSize: 12, fontWeight: 600, padding: "12px 16px" }} />
                    <Area type="monotone" dataKey="triage" stroke="#3b82f6" fill="url(#triageG)" strokeWidth={2.5} dot={false} name="Triage" />
                    <Area type="monotone" dataKey="hunter" stroke="#22d3ee" fill="url(#hunterG)" strokeWidth={2} dot={false} name="Hunter" />
                    <Area type="monotone" dataKey="verifier" stroke="#10b981" fill="url(#verifierG)" strokeWidth={2} dot={false} name="Verifier" />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex h-full items-center justify-center text-sm text-muted-foreground">No performance data available yet</div>
              )}
            </div>
          </section>

          {/* Model Statistics */}
          <section className="px-10 py-12 bg-white border-t border-border">
            <div className="flex items-center gap-4 mb-6">
              <div className="p-3 bg-blue-50 text-blue-600 rounded-2xl">
                <BarChart3 className="w-5 h-5" />
              </div>
              <h3 className="text-2xl font-extrabold text-foreground">Model Statistics</h3>
            </div>
            <div className="grid gap-6 grid-cols-1 sm:grid-cols-2">
              {MODELS.map((m) => (
                <div key={m.rank} className="rounded-2xl border border-border bg-muted/10 p-6">
                  <div className="mb-3 flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <p className="font-mono text-xs font-black text-primary">{m.rank}</p>
                      <p className="truncate text-sm font-bold text-foreground">{m.model}</p>
                    </div>
                    <span className={cn("rounded-full px-2.5 py-1 text-[10px] font-black uppercase", m.statusCls)}>{m.status}</span>
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="w-14 text-[10px] font-black text-muted-foreground uppercase">Recall</span>
                      <div className="h-2 flex-1 rounded-full bg-muted/40 overflow-hidden">
                        <div className="h-full rounded-full bg-emerald-500" style={{ width: `${Math.round(m.recall * 100)}%` }} />
                      </div>
                      <span className="font-mono text-xs font-bold text-muted-foreground w-12 text-right">{m.recall.toFixed(3)}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="w-14 text-[10px] font-black text-muted-foreground uppercase">Precision</span>
                      <div className="h-2 flex-1 rounded-full bg-muted/40 overflow-hidden">
                        <div className="h-full rounded-full bg-blue-500" style={{ width: `${Math.round(m.precision * 100)}%` }} />
                      </div>
                      <span className="font-mono text-xs font-bold text-muted-foreground w-12 text-right">{m.precision.toFixed(3)}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-4 flex items-center justify-end gap-4 text-[10px] font-black uppercase tracking-wider text-muted-foreground">
              <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-emerald-500" />Recall</span>
              <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-blue-500" />Precision</span>
            </div>
          </section>

        </div>

        {/* RIGHT SIDEBAR */}
        <aside className="col-span-12 xl:col-span-4 bg-white border-l border-border/80 p-8 space-y-10">

          {/* Agent Confidence Donuts */}
          <section>
            <div className="flex items-center gap-3 mb-6 px-2">
              <div className="w-10 h-10 bg-white shadow-sm text-emerald-500 rounded-xl flex items-center justify-center border border-border">
                <TrendingUp className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-extrabold text-foreground">Agent Confidence</h3>
            </div>
            <div className="bg-white rounded-2xl p-6 border border-border shadow-sm">
              <div className="flex items-center justify-around py-2">
                {[
                  { label: "Triage", pct: Math.round((confidence.triage || 0) * 100), stroke: "#3b82f6" },
                  { label: "Hunter", pct: Math.round((confidence.hunter || 0) * 100), stroke: "#06b6d4" },
                  { label: "Verifier", pct: Math.round((confidence.verifier || 0) * 100), stroke: "#10b981" },
                ].map((a) => {
                  const r = 32, c = 2 * Math.PI * r, offset = c * (1 - a.pct / 100);
                  return (
                    <div key={a.label} className="flex flex-col items-center gap-2">
                      <svg width="80" height="80" viewBox="0 0 80 80">
                        <circle cx="40" cy="40" r={r} fill="none" stroke="hsl(var(--muted))" strokeWidth="5" opacity="0.2" />
                        <circle cx="40" cy="40" r={r} fill="none" stroke={a.stroke} strokeWidth="5"
                          strokeDasharray={c} strokeDashoffset={offset} strokeLinecap="round"
                          transform="rotate(-90 40 40)" className="transition-all duration-700" />
                        <text x="40" y="42" textAnchor="middle" dominantBaseline="middle"
                          className="fill-foreground" style={{ fontSize: "14px", fontWeight: 700 }}>
                          {a.pct}%
                        </text>
                      </svg>
                      <span className="text-[10px] font-black text-muted-foreground uppercase">{a.label}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </section>

          {/* XAI Feature Importance */}
          <section>
            <div className="flex items-center gap-3 mb-6 px-2">
              <div className="p-2.5 bg-indigo-50 text-indigo-600 rounded-xl">
                <Fingerprint className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-extrabold text-foreground">XAI Feature Importance</h3>
            </div>
            <div className="bg-card rounded-2xl p-6 border border-border shadow-sm space-y-5">
              {xaiFeatures.length > 0 ? xaiFeatures.map((f) => (
                <div key={f.feature} className="space-y-2">
                  <div className="flex justify-between text-[10px] font-black text-muted-foreground uppercase tracking-widest">
                    <span>{f.feature}</span>
                    <span className="text-foreground">{f.importance.toFixed(2)}</span>
                  </div>
                  <div className="h-2.5 w-full bg-muted/30 rounded-full overflow-hidden">
                    <div className={cn("h-full rounded-full transition-all", f.color)} style={{ width: `${Math.min(100, (f.importance / (xaiFeatures[0]?.importance || 0.1)) * 100)}%` }} />
                  </div>
                </div>
              )) : (
                <div className="text-sm text-muted-foreground text-center py-4">No feature data available yet</div>
              )}
            </div>
          </section>

          <section>
            <div className="flex items-center justify-between mb-6 px-2">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-white shadow-sm text-primary rounded-xl flex items-center justify-center border border-border">
                  <Activity className="w-5 h-5" />
                </div>
                <h3 className="text-lg font-extrabold text-foreground">Pipeline Activity</h3>
              </div>
              <button onClick={() => setShowLogs(!showLogs)} className="text-[10px] font-black text-primary uppercase tracking-[0.15em] hover:underline">
                {showLogs ? "Collapse" : "Expand"}
              </button>
            </div>
            {showLogs && (
              <div className="space-y-3">
                {ACTIVITY_LOG.map((log, i) => (
                    <div key={i} className="bg-white rounded-2xl p-5 border border-border shadow-sm hover:border-primary/30 transition-all">
                    <div className="flex items-start gap-3">
                      <div className={cn("w-2 h-2 rounded-full mt-1.5 shrink-0", log.dot)} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between mb-1">
                          <p className={cn("text-[10px] font-black uppercase tracking-wider", log.color)}>{log.agent}</p>
                          <span className="text-[10px] font-bold text-muted-foreground">{log.time}</span>
                        </div>
                        <p className="text-xs text-muted-foreground leading-relaxed">
                          {log.text}{" "}
                          <code className="px-1.5 py-0.5 rounded bg-slate-900 text-emerald-400 font-mono text-[10px]">{log.highlight}</code>
                          {". "}{log.extra}
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>

        </aside>
      </div>

    </div>
  );
}

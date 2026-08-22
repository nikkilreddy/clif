"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Activity } from "lucide-react";
import { severityLabel } from "@/lib/utils";

interface Alert {
    event_id: string;
    timestamp: string;
    severity: number;
    category: string;
    description: string;
    hostname: string;
}

interface RecentAlertsFeedProps {
    alerts: Alert[];
    loading?: boolean;
}

const SEVERITY_VARIANTS: Record<number, "critical" | "high" | "medium" | "low" | "info"> = {
    4: "critical",
    3: "high",
    2: "medium",
    1: "low",
    0: "info",
};

export function RecentAlertsFeed({ alerts, loading }: RecentAlertsFeedProps) {
    return (
        <Card className="h-full flex flex-col">
            <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2 text-sm font-medium">
                    <Activity className="h-4 w-4 text-primary" />
                    Recent Security Alerts
                    <Badge variant="outline" className="ml-auto">
                        Live Feed
                    </Badge>
                </CardTitle>
            </CardHeader>
            <CardContent className="flex-1 p-0">
                <ScrollArea className="h-[400px]">
                    {loading ? (
                        <div className="p-4 space-y-4">
                            <div className="h-12 bg-muted/50 rounded animate-pulse" />
                            <div className="h-12 bg-muted/50 rounded animate-pulse" />
                            <div className="h-12 bg-muted/50 rounded animate-pulse" />
                        </div>
                    ) : alerts.length === 0 ? (
                        <div className="p-8 text-center text-muted-foreground text-sm">
                            No recent security alerts. System is clean.
                        </div>
                    ) : (
                        <div className="divide-y divide-border/40">
                            {alerts.map((alert, i) => (
                                <div key={alert.event_id || i} className="p-4 hover:bg-muted/30 transition-colors">
                                    <div className="flex items-center justify-between mb-1">
                                        <Badge variant={SEVERITY_VARIANTS[alert.severity] ?? "info"} className="text-[10px] px-1.5 py-0 h-5">
                                            {severityLabel(alert.severity)}
                                        </Badge>
                                        <span className="text-[10px] text-muted-foreground font-mono">
                                            {new Date(alert.timestamp).toLocaleTimeString()}
                                        </span>
                                    </div>
                                    <p className="text-xs font-medium mt-1.5 mb-0.5 line-clamp-1">
                                        {alert.category}
                                    </p>
                                    <p className="text-[11px] text-muted-foreground line-clamp-2 leading-relaxed">
                                        {alert.description}
                                    </p>
                                    {alert.hostname && (
                                        <div className="mt-2 flex items-center gap-1.5">
                                            <div className="h-1 w-1 rounded-full bg-primary/50" />
                                            <span className="text-[10px] text-muted-foreground font-mono">{alert.hostname}</span>
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>
                    )}
                </ScrollArea>
            </CardContent>
        </Card>
    );
}

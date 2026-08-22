"use client";

import React from "react";

interface ErrorBoundaryProps {
  children: React.ReactNode;
  fallback?: React.ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    // Log full details for debugging
    console.error("[ErrorBoundary] Error:", error.message);
    console.error("[ErrorBoundary] Stack:", error.stack);
    console.error("[ErrorBoundary] Component Stack:", errorInfo.componentStack);
  }

  render() {
    if (this.state.hasError) {
      return (
        this.props.fallback || (
          <div className="flex min-h-[200px] items-center justify-center p-6">
            <div className="max-w-lg rounded-lg border border-destructive/30 bg-destructive/5 p-6 text-center">
              <div className="mb-2 text-sm font-semibold text-destructive">Component Error</div>
              <p className="text-xs text-muted-foreground">
                {this.state.error?.message || "An unexpected error occurred"}
              </p>
              <pre className="mt-3 max-h-40 overflow-auto rounded bg-slate-900 p-3 text-left text-[10px] text-slate-300 whitespace-pre-wrap">
                {this.state.error?.stack || "No stack trace"}
              </pre>
              <button
                className="mt-4 rounded-md bg-primary px-3 py-1.5 text-xs text-primary-foreground hover:bg-primary/90"
                onClick={() => this.setState({ hasError: false, error: null })}
              >
                Try Again
              </button>
            </div>
          </div>
        )
      );
    }

    return this.props.children;
  }
}

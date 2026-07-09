import { Component, type ErrorInfo, type ReactNode } from "react";

type Props = {
  children: ReactNode;
};

type State = {
  error: Error | null;
};

/**
 * Catches lazy-route load failures and render errors so a single surface
 * does not blank the whole SOC shell.
 */
export class RouteErrorBoundary extends Component<Props, State> {
  public state: State = { error: null };

  public static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  public componentDidCatch(error: Error, info: ErrorInfo): void {
    // Console only — fail-closed UI still shows the recovery panel.
    console.error("RouteErrorBoundary", error, info.componentStack);
  }

  public render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;

    return (
      <div
        className="panel-card max-w-lg space-y-3"
        role="alert"
        aria-live="assertive"
      >
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--sev-high)]">
          View failed to load
        </h2>
        <p className="text-xs text-[var(--text-secondary)]">
          {error.message || "Unexpected error while rendering this surface."}
        </p>
        <button
          type="button"
          className="btn-primary"
          onClick={() => {
            this.setState({ error: null });
            window.location.assign("/dashboard/");
          }}
        >
          Back to Overview
        </button>
      </div>
    );
  }
}

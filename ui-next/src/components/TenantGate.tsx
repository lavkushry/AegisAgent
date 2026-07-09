import { Link } from "react-router-dom";

export function TenantGate({
  title = "Select a tenant",
}: {
  title?: string;
}) {
  return (
    <div className="panel-card max-w-lg space-y-3">
      <h1 className="text-sm font-bold">{title}</h1>
      <p className="text-xs text-[var(--text-secondary)]">
        A tenant must be selected before calling the AegisAgent gateway. Open
        Settings and set Tenant ID + Bearer token (local demo: both are the
        tenant id).
      </p>
      <Link className="btn-primary inline-block" to="/settings">
        Open Settings
      </Link>
    </div>
  );
}

import {
  Fingerprint,
  LayoutDashboard,
  Search,
  Settings,
  Shield,
} from "lucide-react";
import { NavLink } from "react-router-dom";

const ITEMS = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/integrity", label: "Integrity", icon: Fingerprint, end: false },
  { to: "/explore", label: "Explore", icon: Search, end: false },
  { to: "/approvals", label: "Approvals", icon: Shield, end: false },
  { to: "/settings", label: "Settings", icon: Settings, end: false },
] as const;

export function SidebarNav() {
  return (
    <nav className="flex flex-col gap-0.5 p-2">
      {ITEMS.map(({ to, label, icon: Icon, end }) => (
        <NavLink
          key={to}
          to={to}
          end={end}
          className={({ isActive }) =>
            [
              "flex items-center gap-2 rounded-md px-3 py-2 text-xs font-medium transition-colors",
              isActive
                ? "bg-[var(--brand-subtle)] text-[var(--text-primary)]"
                : "text-[var(--text-secondary)] hover:bg-[var(--interactive-bg-hover)] hover:text-[var(--text-primary)]",
            ].join(" ")
          }
        >
          <Icon size={14} className="text-[var(--brand)]" />
          {label}
        </NavLink>
      ))}
    </nav>
  );
}

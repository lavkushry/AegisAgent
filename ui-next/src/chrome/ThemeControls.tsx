import { Moon, Sun, Monitor } from "lucide-react";
import { useAppStore, type Density, type Theme } from "@/app/store";

const THEMES: { id: Theme; label: string; icon: typeof Moon }[] = [
  { id: "dark-soc", label: "Dark SOC", icon: Moon },
  { id: "light", label: "Light", icon: Sun },
  { id: "oled", label: "OLED", icon: Monitor },
];

const DENSITIES: { id: Density; label: string }[] = [
  { id: "compact", label: "Compact" },
  { id: "cozy", label: "Cozy" },
];

export function ThemeControls() {
  const theme = useAppStore((s) => s.theme);
  const density = useAppStore((s) => s.density);
  const setTheme = useAppStore((s) => s.setTheme);
  const setDensity = useAppStore((s) => s.setDensity);

  return (
    <div className="flex flex-col gap-2 px-3 py-2">
      <div className="text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
        Theme
      </div>
      <div className="flex flex-wrap gap-1">
        {THEMES.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            title={label}
            aria-pressed={theme === id}
            onClick={() => setTheme(id)}
            className={[
              "inline-flex items-center gap-1 rounded-md px-2 py-1 text-[10px] font-medium transition-colors",
              theme === id
                ? "bg-[var(--brand-subtle)] text-[var(--text-primary)] ring-1 ring-[var(--border-active)]"
                : "bg-[var(--interactive-bg)] text-[var(--text-secondary)] hover:bg-[var(--interactive-bg-hover)]",
            ].join(" ")}
          >
            <Icon size={12} />
            {label}
          </button>
        ))}
      </div>
      <div className="text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
        Density
      </div>
      <div className="flex flex-wrap gap-1">
        {DENSITIES.map(({ id, label }) => (
          <button
            key={id}
            type="button"
            aria-pressed={density === id}
            onClick={() => setDensity(id)}
            className={[
              "rounded-md px-2 py-1 text-[10px] font-medium transition-colors",
              density === id
                ? "bg-[var(--brand-subtle)] text-[var(--text-primary)] ring-1 ring-[var(--border-active)]"
                : "bg-[var(--interactive-bg)] text-[var(--text-secondary)] hover:bg-[var(--interactive-bg-hover)]",
            ].join(" ")}
          >
            {label}
          </button>
        ))}
      </div>
    </div>
  );
}

# AegisAgent — SOC Console Design System & Frontend Architecture

> **Status:** Design (2026-06-24). **Document type:** Product Design System + Frontend Architecture.
> **Companion to** [`AegisAgent_SOC_Console_HLD_LLD.md`](AegisAgent_SOC_Console_HLD_LLD.md) (the engineering HLD/LLD: datasource, panel framework, dashboard schema, AQL, drilldown, performance) and [`AegisAgent_SOC_UI_Design.md`](AegisAgent_SOC_UI_Design.md) (the product/UX design).
> **This doc owns** the layers those two do not: **brand identity, theme tokens, design language, application shell, the component library, and the investigation/approval/timeline experiences**. Where architecture is already specified (panels do not fetch; `PanelRuntime` fetches; dashboard JSON controls composition), this doc references it and does not re-derive it.

---

## 1. Executive summary

The AegisAgent SOC Console is **not a monitoring dashboard**. It is a **mission-control surface for AI agent governance** — where a human operator watches autonomous agents act, approves the dangerous ones against cryptographically frozen evidence, and *proves* after the fact exactly what happened. Three things on this screen exist nowhere in Grafana, Kibana, Datadog, or Splunk: the **Approval Card** (a human binding their sign-off to exact bytes), the **Provable Timeline** (a hash-chained incident you can verify in one click), and the **Receipt Integrity** viewer (tamper detection as a first-class view).

The design system therefore optimizes for a specific operator: a security analyst scanning many low-signal streams for the few high-stakes moments, who must act fast and be *right*. That dictates everything downstream — **high information density, evidence-forward visual hierarchy, restrained motion, and a dark-first palette** where one accent color carries trust and severity carries meaning, never decoration.

This document specifies: the **Aegis visual identity** (§3), a three-theme token system (Light / Dark SOC / OLED, §3.4), the **design language** (density, hierarchy, motion, §2), the **application shell** (collapsible nav + Grafana-style control bar, §4), the **component library** with per-component HLD/LLD (§5–§6), the **frontend folder structure** (§7), the **panel catalog** including two new AegisAgent panels — *Agent Risk Map* and *Decision Graph* (§9), the **investigation / approval / timeline UX** (§8), **accessibility** (§10), and a **Phase 0→5 roadmap** reconciled with the HLD/LLD's U0–U6 (§11).

**Anti-template mandate:** every surface here must read as a deliberate security product, not a shadcn starter. The checklist in §12 enforces it.

---

## 2. Design language

### 2.1 The operating principle — *evidence over ornament*

Each pixel earns its place by helping an operator make or prove a decision. A panel that looks impressive but doesn't change what the analyst does next is removed. This is the inverse of a marketing dashboard.

### 2.2 Information density

SOC operators monitor many signals at once. The console uses a **compact density baseline**, denser than a typical SaaS app:

| Token | Value | Use |
|---|---|---|
| `--row-height-compact` | `28px` | table/feed rows (default) |
| `--row-height-cozy` | `36px` | investigation tables where payloads matter |
| `--space-panel-pad` | `12px` | inside panels (not 24px SaaS default) |
| `--space-grid-gap` | `12px` | between panels |
| `--font-size-data` | `12.5px` | tabular data, log lines |
| `--font-size-label` | `10.5px` / uppercase / `0.04em` tracking | panel titles, field labels |

A **density toggle** (Compact / Cozy) lives in the user menu and rewrites the `--row-height-*` and `--space-*` custom properties at the `:root` scope — no component re-render, pure CSS variable swap.

### 2.3 Visual hierarchy (four scales)

| Scale | Carries hierarchy through | Rule |
|---|---|---|
| **Page** | left-nav active state + breadcrumb + a single H1-equivalent (`--font-size-page`, 18px) | one page = one job; no competing titles |
| **Dashboard** | rows/tabs; a **stat row** always leads (the "vital signs"), detail panels below | the most decision-relevant number is top-left |
| **Panel** | a 10.5px uppercase title + a dominant value or chart; chrome recedes (`--text-muted`) | the data is the brightest thing in the panel |
| **Alert / severity** | color + icon + weight, never color alone | critical = `rose`, filled; lower severities = outline |

Hierarchy is built from **scale contrast and weight**, not boxes-within-boxes. Elevation (surface layering, §3.4) separates concerns; borders are hairline and recede.

### 2.4 Motion

Motion is **functional only**. It communicates state change or progress; it never decorates.

| Allowed | Duration / easing | Why |
|---|---|---|
| Live event arrival (feed row slides in + brief highlight fade) | `--duration-fast 120ms`, `ease-out` | draws the eye to *new* evidence |
| State transition (decision badge allow→deny, agent active→frozen) | `150ms` cross-fade | confirms the system changed |
| Verification progress (chain walk, indeterminate → resolved) | stepped, `--duration-normal 240ms` per link | makes proof feel earned, not instant-magic |
| Drawer / command palette open | `180ms` transform+opacity | spatial continuity |

**Forbidden:** parallax, decorative gradients-in-motion, looping ambient animation, springy bounce on data, skeleton shimmer longer than 400ms. All motion respects `prefers-reduced-motion` (collapses to instant state swaps; progress becomes a static stepped indicator). Animate **only** compositor-friendly properties (`transform`, `opacity`) — never layout-bound ones.

---

## 3. Visual identity — the Aegis brand

### 3.1 Brand personality

| Trait | What it means on screen | Why it fits AegisAgent |
|---|---|---|
| **Secure** | locked-down chrome, no playful affordances, fail-closed empty states | the product *is* a security control |
| **Evidence-driven** | hashes, receipts, and provenance are visible first-class data, not metadata | the moat is *provability* (Gap Reassessment §3) |
| **Autonomous** | the UI watches machines acting on their own; agents are first-class "citizens" with status/risk | the subject is autonomous agents, not human users |
| **Defensive** | severity and trust drive color; the resting state is calm, alarms are loud | a SOC is calm until it isn't |
| **Enterprise / technical** | dense, keyboard-first, monospace for all identifiers | the buyer is a security engineer, not a consumer |

The personality resolves a tension: the product must feel **trustworthy and calm** (you stake production agent actions on it) while making **threats unmistakable** (an injection attempt must scream). The answer: a low-chroma, high-contrast resting palette where a single saturated accent and the severity ramp are the *only* loud colors — so when they appear, they mean something.

### 3.2 The Aegis Mark (logo direction — not a generic shield)

The mark encodes the three things that make AegisAgent unique — the **gate** (authorization boundary), the **chain** (receipt provenance), and **oversight** (the human watching) — in one glyph.

```
        ╭───────────╮              Concept: "The Verified Aperture"
       ╱  ◜─────◝   ╲
      │  ╱   ▲   ╲   │   ◀ outer hexagon = the gate (the authorization boundary)
      │ │   ╱ ╲   │  │   ◀ inner aperture = oversight (an eye / a lens, watching)
      │  ╲  ▼  ╱   ╱     ◀ the aperture's lower notch resolves into a ✓ when state = verified
       ╲  ◟─────◞ ╱
        ╰────●────╯       ◀ the single anchor node = the genesis link of the receipt chain
```

- **Primary logo:** the Mark + `AegisAgent` wordmark (geometric grotesque, see §3.3), the word "Agent" set in `--text-secondary` so "Aegis" leads.
- **Icon / app favicon:** the Mark alone — a hexagonal aperture. At 16px it reads as a faceted ring with a center dot (the chain's genesis node).
- **Collapsed sidebar icon:** the Mark at 24px, monochrome `--brand`; the aperture's notch animates to a ✓ for ~600ms on a successful global verify (the only place the logo ever animates — a deliberate, rare "all clear" signal).
- **Symbol meaning:** hexagon = a sealed boundary (six sides nod to the **six trust levels**); aperture = human oversight (Article 14); the anchor node + implied links = the hash chain; the notch-to-check = verifiability. **No sword, no padlock, no generic shield silhouette.**
- **Motion signature:** on receipt-chain verification anywhere in the app, the Mark briefly draws its chain links left-to-right (stepped, reduced-motion-safe) — the brand *is* the verification gesture.

### 3.3 Typography

Two families, deliberately paired:

| Role | Family | Rationale |
|---|---|---|
| **Display / UI** | **Geist** (or Inter Tight as fallback) — geometric grotesque | technical, neutral, excellent at small sizes & dense tables |
| **Mono / evidence** | **Geist Mono** (or JetBrains Mono) | **every identifier** — `action_hash`, `receipt_hash`, agent IDs, payloads, AQL — is monospace; evidence must be unambiguous and copy-exact |

Type scale (`clamp()` for the few responsive sizes; fixed px for dense data):

```css
--font-size-page:   18px;  /* page H1 */
--font-size-section:14px;  /* row/section titles */
--font-size-body:   13px;
--font-size-data:   12.5px;/* tables, logs */
--font-size-label:  10.5px;/* uppercase field labels, 0.04em tracking */
--font-size-hero-stat: clamp(28px, 2vw + 1rem, 40px); /* the big stat number */
```

Rule: **max two families**, `font-display: swap`, subset to Latin + the box-drawing/symbol glyphs the timeline uses, preload only the one critical weight (UI Medium 500).

### 3.4 Color system & themes

Tokens are defined in **OKLCH** (perceptually uniform — severity ramps stay legible across themes) and exposed as CSS custom properties. Three themes share one token *contract*; only values change.

**Semantic token contract (theme-independent names):**

```css
/* Brand */
--brand            /* AegisAgent indigo — the ONE saturated accent */
--brand-emphasis   /* hover/active brand */
--brand-subtle     /* brand at low alpha for fills/selection */

/* Interactive */
--interactive-fg, --interactive-bg, --interactive-bg-hover, --focus-ring

/* SOC severity & decision ramp (meaning, never decoration) */
--sev-critical  /* rose  */   --decision-deny      /* red    */
--sev-high      /* red   */   --decision-approval  /* amber  */
--sev-medium    /* amber */   --decision-allow     /* green  */
--sev-low       /* sky   */   --state-verified     /* emerald*/
--sev-info      /* slate */   --state-failed       /* rose   */
                              --state-pending      /* amber, pulsing dot */

/* Trust-provenance ramp (the 6 levels — a dedicated, ordered scale) */
--trust-internal-signed   /* emerald */   --trust-external      /* red   */
--trust-internal-unsigned /* sky     */   --trust-malicious     /* rose, bold */
--trust-customer          /* amber   */   --trust-unknown       /* slate */

/* Surface elevation (4 layers — depth via surface, not shadow) */
--surface-app      /* deepest — page background */
--surface-panel    /* panel background */
--surface-elevated /* popover/drawer/hover-row */
--surface-modal    /* modal/dialog */
--surface-overlay  /* scrim */

/* Text */
--text-primary, --text-secondary, --text-muted, --text-on-brand

/* Borders (hairline; recede) */
--border-default, --border-hover, --border-active, --border-focus
```

**Theme value tables** (representative anchors; full ramp generated from these):

| Token | Light | **Dark SOC (default)** | OLED |
|---|---|---|---|
| `--surface-app` | `oklch(98.5% 0 0)` | `oklch(20% 0.02 255)` ≈ `#0f172a` | `oklch(0% 0 0)` `#000000` |
| `--surface-panel` | `oklch(100% 0 0)` | `oklch(24% 0.02 255)` ≈ `#111827` | `oklch(8% 0.01 255)` |
| `--surface-elevated` | `oklch(97% 0 0)` | `oklch(28% 0.02 255)` | `oklch(13% 0.01 255)` |
| `--text-primary` | `oklch(22% 0.02 255)` | `oklch(92% 0.01 255)` ≈ `#e2e8f0` | `oklch(96% 0 0)` |
| `--text-muted` | `oklch(55% 0.02 255)` | `oklch(60% 0.02 255)` ≈ `#64748b` | `oklch(58% 0.02 255)` |
| `--border-default` | `oklch(90% 0.01 255)` | `oklch(34% 0.02 255)` ≈ `#334155` | `oklch(18% 0.01 255)` |
| `--brand` | `oklch(55% 0.20 270)` | `oklch(62% 0.20 270)` (indigo-500/600) | `oklch(64% 0.21 270)` |
| `--decision-deny` | `oklch(58% 0.20 25)` | `oklch(64% 0.21 25)` | `oklch(66% 0.22 25)` |
| `--decision-allow` | `oklch(60% 0.16 150)` | `oklch(70% 0.17 150)` | `oklch(72% 0.18 150)` |
| `--state-verified` | `oklch(60% 0.15 160)` | `oklch(72% 0.16 160)` | `oklch(74% 0.17 160)` |
| `--trust-malicious` | `oklch(55% 0.22 15)` | `oklch(62% 0.24 15)` | `oklch(64% 0.25 15)` |

Notes:
- The **Dark SOC** theme is the default and matches the existing `ui/` palette (`#0f172a` / `#e2e8f0` / `#334155`) — adopting it means **zero visual regression** on the current console while formalizing the tokens.
- **OLED** is true-black for 24/7 wall displays and battery; it *raises* panel surfaces slightly so panels read as objects floating on black, and slightly boosts severity chroma to survive the higher contrast.
- **Light** exists for daytime/print/evidence-export readability; it is held to the same WCAG AA contrast (§10) and is **not** an afterthought (Design-Quality rule: both themes must feel intentional).
- Depth comes from the **four surface layers**, not heavy shadows. Shadows are a single hairline `--border-default` + at most one soft elevation shadow on `--surface-elevated`/`modal`.
- **Severity and trust are reserved palettes.** No UI chrome may use the severity ramp decoratively. This is what makes a red row *mean* something.

---

## 4. Application shell

The shell is the persistent frame around every page: **left navigation** + **top control bar** + the routed content region. Implemented as `ui/src/chrome/AppShell.tsx`; replaces today's monolithic `page.tsx` switch.

### 4.1 Left navigation

```
┌──────────────┐        Expanded (240px)         Collapsed (56px)
│ ◈ AegisAgent │  ◀ Mark + wordmark              ◈  ◀ Mark only
│ ──────────── │
│ ▦ Overview   │  active: --brand-subtle bg,     ▦  ◀ icon only; tooltip on hover
│ ⌕ Explore    │          left 2px --brand bar,   ⌕      (Radix tooltip, 400ms delay)
│ ◭ Incidents  │          --text-primary           ◭
│ ◮ Detections │  badge:  count chip (deny/      ◮•  ◀ badge becomes a dot
│ �ស Approvals  3│         pending) right-aligned   ⏸③
│ ⬡ Agents     │                                  ⬡
│ ⛁ MCP        │                                  ⛁
│ ⛓ Receipts   │                                  ⛓
│ ▤ Dashboards │                                  ▤
│ ──────────── │
│ ⚙ Settings   │                                  ⚙
│ « collapse   │  ◀ pin/collapse toggle           »
└──────────────┘
```

- **State ownership:** `consoleStore.navCollapsed` (Zustand, persisted to `localStorage`); collapse is a CSS-grid column-width change, not a remount.
- **Active state:** route-derived (`usePathname`), never local state — deep links light the correct item.
- **Badges:** live counts from the SSE stream (`Approvals` pending, `Detections` firing). Collapsed → badge degrades to a colored dot. Badge color = the relevant severity/state token.
- **Keyboard shortcuts:** `g` then a letter (Gmail-style chord) — `g o` Overview, `g e` Explore, `g i` Incidents, `g a` Approvals, etc.; `[` toggles collapse; `?` opens the shortcut cheatsheet. Registered centrally in `useGlobalHotkeys()` so they're discoverable and conflict-free.
- **Icons:** `lucide-react` (already a dependency), one consistent stroke weight; the nav never mixes filled/outline.

### 4.2 Top control bar (`chrome/ControlsBar.tsx` + `chrome/TimeRangePicker.tsx`)

Grafana/Kibana-style global controls. **The single most important shell decision: these controls own global query context, and changing any of them invalidates every `PanelRuntime` query key** (see HLD/LLD §7.4).

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ [tenant ▾] │ $agent ▾  $env ▾ │  ⌕ search… (⌘K)  │  [◷ Last 24h ▾] [⟳ 10s ▾] [● Live] │ 🔔③ │ ◐ │ 𝗨 ▾ │
└────────────────────────────────────────────────────────────────────────────────────────┘
   tenant     template vars        command palette        time range / refresh / live   notif theme user
```

| Control | Component API (props) | State owner | Behavior |
|---|---|---|---|
| Tenant selector | `<TenantSelect value onChange options>` | `consoleStore.tenant` | lists only entitled tenants; switching clears all caches (no cross-tenant bleed) |
| Template variables | `<VariableControl def value onChange>` | `consoleStore.variables[name]` | chained vars re-query when their parent changes; URL-synced |
| Global search / palette | `<CommandPalette>` (⌘K/Ctrl K) | local + `consoleStore` | fuzzy: pages, agents, incidents, "verify receipt …", "freeze agent …" — actions, not just nav |
| Time range | `<TimeRangePicker value onChange>` | `consoleStore.timeRange` | relative tokens (`now-24h`) + absolute; quick presets; URL-synced |
| Refresh interval | `<RefreshSelect>` | `consoleStore.refreshSec` | off/5s/10s/30s/1m; drives `refetchInterval` |
| Live toggle | `<LiveToggle>` | `consoleStore.live` | turns on SSE subscriptions (`feed` panels, badges); pulsing `--state-pending` dot when active |
| Notifications | `<NotificationsBell count>` | SSE | opens a drawer of recent alerts/approvals |
| Theme | `<ThemeToggle>` | `consoleStore.theme` | Light / Dark SOC / OLED; writes `data-theme` on `<html>` |
| User menu | `<UserMenu role>` | session | role, density toggle, sign-out, shortcut cheatsheet |

All control-bar state is **URL-synced** (search params) so any view is a shareable link — the Grafana/Kibana "state in the URL" pattern and the repo's "URL as state" web rule.

---

## 5. Component library — HLD

### 5.1 Folder structure (`ui/src/`)

```
ui/src/
├── app/                      # Next.js App Router ent
│   ├── layout.tsx            # providers + AppShell mount
│   ├── (console)/…/page.tsx  # one route per nav item → renders a Dashboard or a Page
│   └── providers.tsx         # TanStack Query, theme, hotkeys
├── chrome/                   # the shell
│   ├── AppShell.tsx  LeftNav.tsx  ControlsBar.tsx  TimeRangePicker.tsx
│   ├── CommandPalette.tsx  NotificationsDrawer.tsx  UserMenu.tsx
├── design-system/            # tokens + primitives (the "ui/" layer)
│   ├── tokens.css            # all CSS custom properties, per-theme blocks
│   ├── Button.tsx Badge.tsx Card.tsx Input.tsx Select.tsx
│   ├── Drawer.tsx Modal.tsx Tooltip.tsx Toast.tsx Tabs.tsx Skeleton.tsx
│   └── primitives/           # Radix wrappers (a11y baked in)
├── components/
│   ├── security/             # AegisAgent-specific shared UI
│   │   ├── HashChip.tsx TrustBadge.tsx DecisionBadge.tsx SeverityTag.tsx
│   │   ├── CanonicalActionView.tsx VerifyButton.tsx ExpiryCountdown.tsx
│   ├── tables/               # DataGrid (TanStack Table + virtual) + cell renderers
│   ├── charts/               # chart adapters (Recharts now; uPlot/ECharts later)
│   └── filters/              # FilterBuilder, AqlInput, FieldSidebar
├── panels/                   # PANEL FRAMEWORK — see HLD/LLD §7
│   ├── PanelRuntime.tsx PanelContainer.tsx registry.ts types.ts
│   ├── standard/             # Stat TimeSeries Table Heatmap Status Feed
│   └── differentiators/      # ApprovalCard ProvableTimeline ReceiptIntegrity
│       │                     #   AgentRiskMap DecisionGraph
├── dashboards/               # DASHBOARD MODEL — see HLD/LLD §7.3
│   ├── DashboardLoader.tsx schema.ts drilldown.ts
│   └── system/               # curated dashboards-as-code (overview.ts, fleet.ts, …)
├── datasources/              # DATASOURCE LAYER — see HLD/LLD §5
│   ├── types.ts gatewayEntity.ts socQuery.ts receipt.ts stream.ts registry.ts
│   └── aql/                  # parser, autocomplete, AST→params
├── pages/                    # non-dashboard pages (Explore, Rules, Settings)
├── state/                    # consoleStore.ts (Zustand) + url-sync.ts
├── hooks/                    # useSocStream useDrilldownRouter useGlobalHotkeys useTheme
└── lib/                      # format.ts (hash/time/bytes) color.ts validate.ts (zod)
```

Folder responsibilities: **`design-system/`** = brand primitives, zero domain knowledge (a `Button` knows nothing about receipts). **`components/security/`** = the reusable AegisAgent vocabulary (`HashChip`, `TrustBadge`) shared by panels and pages. **`panels/`, `dashboards/`, `datasources/`** = the framework (specified in the HLD/LLD doc). **`pages/`** = the few surfaces that are *not* dashboards (Explore, Rules, Settings). This is feature/surface organization, not file-type organization (repo web coding-style rule).

### 5.2 Component HLD table

| Component | Layer | Purpose | Built on |
|---|---|---|---|
| `Button` | design-system | all actions; variants encode intent | Radix Slot |
| `Badge` / `SeverityTag` | design-system / security | status & severity, **icon + label always** | — |
| `Card` / `PanelContainer` | design-system / panels | the panel frame: title, toolbar, state slots | — |
| `MetricCard` (Stat) | panels/standard | a single decision-relevant number | Recharts spark |
| `DataGrid` | tables | virtualized high-row-count tables | TanStack Table + react-virtual |
| `Timeline` / `ProvableTimeline` | security / panels | ordered events; provable variant adds receipt+verify | — |
| `SearchBar` / `AqlInput` | filters | AQL query entry + autocomplete | — |
| `FilterBuilder` | filters | click-to-build field:value filters | — |
| `FieldSidebar` | filters | Discover-style facet sidebar | datasource `fields()` |
| `CommandPalette` | chrome | ⌘K nav + actions | Radix Dialog + cmdk |
| `Drawer` / `Modal` | design-system | side context / blocking confirm | Radix Dialog |
| `Toast` | design-system | non-blocking action feedback | Radix Toast |
| `Tooltip` | design-system | dense-mode disclosure | Radix Tooltip |
| `HashChip` | security | truncated mono hash + copy + drilldown | — |
| `TrustBadge` / `DecisionBadge` | security | the 6 trust levels / decision ramp | — |
| `CanonicalActionView` | security | the exact bytes an approval covers | — |
| `VerifyButton` | security | trigger + render chain verification | datasource `verifyReceipt()` |

---

## 6. Component library — LLD (representative contracts)

Every component obeys the repo TypeScript/React rules: named `type Props`, destructured params, explicit public types, no `any`, presentational components are pure (data in, JSX out). Each defines its **states** (loading / empty / error / success where applicable) and **variants**.

### 6.1 `Button`

```ts
type ButtonProps = {
  variant?: "primary" | "secondary" | "ghost" | "danger" | "verify";
  size?: "sm" | "md";
  isLoading?: boolean;
  disabled?: boolean;
  disabledReason?: string;     // renders as a tooltip — never silently disable a security action
  leftIcon?: React.ReactNode;
  onClick?: () => void;
  children: React.ReactNode;
};
```
- **Variants:** `primary` = `--brand`; `danger` = `--decision-deny` (freeze/revoke/reject); `verify` = `--state-verified` outline (the receipt-verify gesture has its own visual identity). 
- **States:** `isLoading` shows an inline spinner and blocks re-click; `disabled` **must** pair with `disabledReason` for any security action (RBAC gating shows *why*, per §8.4 / HLD §9).
- **A11y:** real `<button>`, focus ring `--border-focus`, `aria-busy` when loading.

### 6.2 `HashChip` (the most-used security primitive)

```ts
type HashChipProps = {
  hash: string;                 // full sha256 (e.g. "sha256:9af1…")
  kind: "action" | "receipt" | "manifest";
  truncate?: number;            // default 8 head + 4 tail
  onDrilldown?: () => void;     // e.g. open Receipt Integrity at this hash
};
```
- Renders mono, `--text-secondary`, with a copy affordance on hover (copies the **full** hash, not the truncated display — evidence integrity). `kind` sets a 1px left accent (action=brand, receipt=verified, manifest=sky). Click → `onDrilldown`. Never wraps; never shows raw secrets.

### 6.3 `DataGrid` (high-row-count tables)

```ts
type DataGridProps<TRow> = {
  data: DataFrame;                          // columnar — from PanelRuntime, never fetched here
  columns: ColumnDef<TRow>[];               // TanStack Table defs
  rowKey: (row: TRow) => string;            // stable key — never index
  onRowClick?: (row: TRow) => void;
  density?: "compact" | "cozy";
  emptyLabel?: string;
  isLoading?: boolean;
  error?: string;
};
```
- **Virtualized** (`@tanstack/react-virtual`) — renders only visible rows; handles 1,000+ rows at 60fps. Cell renderers map `Field.format` → `HashChip` / `TrustBadge` / `DecisionBadge` / relative-time. **States:** loading = 8 skeleton rows; empty = `emptyLabel` + a hint; error = inline `--state-failed` banner with the message (never a blank grid). Column sort is client-side for the loaded page, server-side for full-dataset sort (cursor).

### 6.4 `CanonicalActionView` (approval safety)

```ts
type CanonicalActionViewProps = {
  action: CanonicalAction;     // the exact, frozen, hashed bytes
  actionHash: string;
  edited?: { diff: ActionDiff }; // when an approver edited; shows a before/after diff
};
```
- Renders the canonical action **exactly as hashed**, monospace, with the `action_hash` shown adjacent via `HashChip`. If `edited`, shows a **diff** and a banner: *"Editing re-hashes and re-evaluates — you are approving the new bytes."* This component is the literal embodiment of the approval-integrity moat; it must never render a "friendly" summary that diverges from the bytes (the render-vs-bytes attack).

### 6.5 `VerifyButton` + verification states

```ts
type VerifyButtonProps = {
  receiptId: string;
  range?: { fromId: string; toId: string };   // verify a chain segment
  onResult?: (r: VerifyResult) => void;
};
// VerifyResult from HLD/LLD §5.1: { ok, brokenAtRow?, message, chainHead? }
```
- **States:** idle (`verify` variant) → walking (stepped progress, one tick per link, reduced-motion = static "verifying N links") → `ok` (`--state-verified` "tamper-free `…a1b2 → …c3d4`") → `failed` (`--state-failed` "broken at event 42", with a jump-to-row action). The button's result is also surfaced on the row(s) it covers.

---

## 7. Frontend architecture (HLD)

```
                      Browser (Next.js App Router)
                               │
        ┌──────────────────────▼───────────────────────┐
        │  AppShell  (LeftNav · ControlsBar · routes)   │  owns global query context
        └──────────────────────┬───────────────────────┘
                               │ consoleStore (tenant, timeRange, variables, live, theme, role)
            ┌──────────────────┼─────────────────────────┐
            ▼                  ▼                          ▼
   DashboardLoader        Page (Explore/Rules/Settings)   CommandPalette
   (schema → grid)             │                          (nav + actions)
            │                  │
            ▼                  ▼
       PanelRuntime  ◀── the ONLY data-fetching layer (TanStack Query) ──▶
            │   builds QueryRequest from (panel.query + timeRange + variables)
            ▼
        Panel component  ◀── pure: (DataFrame, state) → JSX; never fetches
            │   emits onDrilldown → useDrilldownRouter
            ▼
       Datasource layer  (GatewayEntity · SocQuery/AQL · Receipt · Stream)
            │   tenant context attached; AQL sent as structured AST (no interpolation)
            ▼
       AegisAgent Gateway (Rust/Axum) — tenant-scoped, fail-closed, parameterized SQL
```

**Responsibility boundaries (the load-bearing rule):**
- **AppShell / consoleStore** own *global query context*. Nothing else writes time/tenant/vars.
- **DashboardLoader** owns *composition* — it reads a `DashboardSchema` and lays out `PanelRuntime`s. It knows nothing about data.
- **PanelRuntime** owns *fetching* — the single place TanStack Query is called for panels. Cache key = `[panelId, query, timeRange, variables, tenant]`.
- **Panels** own *rendering only*. A panel that calls `fetch` is a bug.
- **Datasources** own *transport + shape* — they turn requests into gateway calls and responses into `DataFrame`s. The only layer that knows REST paths.

This is the invariant the user emphasized and it is enforced by the folder boundaries (`panels/standard/*` may not import from `datasources/` except types; only `PanelRuntime` imports the registry).

### 7.1 Event & rendering flow (LLD)

```
1. User changes time range  → consoleStore.timeRange updates → URL syncs
2. consoleStore change       → every PanelRuntime's TanStack Query key changes
3. PanelRuntime              → builds QueryRequest, calls datasource.query(req) (deduped/cached)
4. Datasource                → gateway call → DataFrame
5. PanelRuntime              → passes DataFrame + {isLoading,error} to Panel component
6. Panel                     → renders; user clicks a row
7. Panel                     → onDrilldown(link, row) → useDrilldownRouter
8. Drilldown router          → maps vars, navigates (e.g. Explore filtered to agent_id) — context preserved
9. SSE (if live)             → useSocStream pushes deltas → feed panels + nav badges update (advisory)
```

State models: **server state** = TanStack Query (never copied into Zustand); **global UI state** = Zustand (`consoleStore`); **URL state** = search params (filters, time, tab, selected entity); **local component state** = `useState`. No server data is duplicated into the store (repo state rule).

---

## 8. Investigation, approval & timeline experiences

### 8.1 The investigation spine (navigation model)

The console's superpower is that every object links to its evidence. The canonical path:

```
Detection ──▶ Incident ──▶ Agent ──▶ Decision ──▶ Action ──▶ Receipt ──▶ Verification
   (alert)     (case)     (entity)   (allow/deny) (bytes)   (hash)    (proof / break)
```

- **Drilldown system:** every arrow is a `DrilldownLink` (HLD/LLD §7.5). Clicking a detection opens the incident; the incident's timeline rows drill to the agent or to the receipt; an agent drills to its decisions in Explore.
- **Breadcrumbs:** the shell renders a context breadcrumb (`Incidents / inc_01J / read_issue #391 / receipt …a1b2`) so the analyst never loses the trail. Breadcrumb segments are themselves links (back up the spine).
- **Context preservation:** drilldowns carry the time range and relevant variables; opening a side `Drawer` (e.g. agent detail) keeps the underlying list in place. Back navigation restores scroll + expansion state (URL state, not remount).

### 8.2 Approval experience (the product's trust story, made visible)

The `ApprovalCard` panel (HLD/LLD §7.2) is the most carefully designed surface in the product.

```
┌ Approval required ────────────────────────── ⏱ expires 04:52 ┐
│ ⬡ coding-agent-prod   ▸ run r_8f2…   group platform-leads     │
│ trust  ⬤ untrusted_external     risk  ███████░░ 78  composite │
│ ───────────────────────────────────────────────────────────── │
│ action  github.merge_pull_request → payments-service/main      │
│ ┌ canonical payload (exact bytes you approve) ──────────────┐  │
│ │ { "base_branch": "main", "pr_number": 482, "merge_method"  │  │
│ │   : "squash" }                                             │  │
│ └────────────────────────────────────────────────────────────┘ │
│ action_hash  sha256:9af1c8…b3   📋    reason  PR merge after CI │
│ ───────────────────────────────────────────────────────────── │
│ [ Approve ]   [ Reject ]   [ Edit & re-evaluate ]   [ Escalate ]│
└────────────────────────────────────────────────────────────────┘
```

**UX safety rules (non-negotiable):**
1. **Bytes, not a summary.** The payload shown is the canonical hashed action, verbatim. No prettified divergence (defeats render-vs-bytes).
2. **Edit re-hashes + re-evaluates.** Editing shows a diff and a warning; it produces a *new* `action_hash` and re-runs policy — it never patches the approved hash. If the gateway lacks `PUT /v1/approvals/:id`, **Edit is disabled with a tooltip**, never faked (fail-closed UX).
3. **Expiry is loud.** The countdown turns `--state-pending` → `--decision-deny` under 60s; an expired card cannot be approved (the button disables with reason).
4. **Separation of duties.** Approve/Reject are enabled only for `role === "approver"` (and never the agent's owner); others see them disabled-with-reason. Server enforces too.
5. **Trust is front-and-center.** The `TrustBadge` for `untrusted_external` / `malicious_suspected` is the brightest non-action element — the analyst sees *why* approval was required before they see the action.
6. **Every approval action emits its own receipt** (the console is inside the evidence boundary).

### 8.3 Provable Timeline experience

```
┌ inc_01J  Prompt injection → high-risk action   [critical] [contained]  [⛓ Verify chain] ┐
│ ● 10:02  read_issue #391 (public)            trust ⬤ untrusted_external      rcpt …a1b2 ✓ │
│ │ 10:03  ⛨ AEG-1002 confused-deputy (L12)    ATLAS AML.T0051                            │
│ │ 10:05  ⛔ merge → main  forbid-untrusted    decision deny                  rcpt …c3d4 ✓ │
│ │ 10:05  ⛔ approve-then-swap → SDK fail-closed (T-A1)                        rcpt …c3d4 ✓ │
│ ● 10:05  🛡 Active Response: agent FROZEN · Slack #agent-security              contained   │
│ ───────────────────────────────────────────────────────────────────────────────────────── │
│ Chain  …a1b2 → …c3d4   ✓ tamper-free (5/5 links)     [Freeze ▾] [Revoke] [Export pack]     │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

- Each row carries its `receipt_hash` (`HashChip`) and a per-row verify tick. **Verify chain** walks the segment (`VerifyButton`, §6.5): success = green "tamper-free (N/N links)"; failure = red "**broken at event 42**" with the offending link rendered in `--state-failed` and a jump-to-row. A break also exists as a `receipt-chain-broken` P1 detection.
- Rows are virtualized (incidents can be long); the verify walk is stepped + reduced-motion-safe.

### 8.4 Explore page (Kibana Discover equivalent) — `pages/Explore.tsx`

```
┌ ⌕ agent_id:coding-agent-prod AND decision:deny AND @time:[now-24h TO now]   [Search] [Save] ┐
├──────────────┬──────────────────────────────────────────────────────────────────────────────┤
│ FIELDS       │  ▁▂▅▇▅▃▂▁  histogram (count over time, click-drag to zoom the range)          │
│ ◔ decision   │ ─────────────────────────────────────────────────────────────────────────────│
│   deny    52 │  time      decision  tool            agent              trust         receipt  │
│   allow  311 │  10:05:12  ⛔ deny    github.merge    coding-agent-prod  ⬤ untrusted   …c3d4 ▸ │
│ ◔ source_trust│  10:04:58  ⛔ deny    db.write        coding-agent-prod  ⬤ untrusted   …b8e1 ▸ │
│   untrusted 7│  …  (virtualized doc table; click a row → expand)                              │
│ ◔ tool       │  ┌ expanded row ───────────────────────────────────────────────────────────┐ │
│ ◔ agent_id   │  │ full ASE JSON · action_hash …9af1 · [Verify receipt] · [Open in timeline] │ │
│ ◔ event_type │  └──────────────────────────────────────────────────────────────────────────┘ │
└──────────────┴──────────────────────────────────────────────────────────────────────────────┘
```

- **`AqlInput`** with field-aware autocomplete (from `datasource.fields()`), error squiggles (client-side parse), and structured-AST submission (no string interpolation).
- **`FieldSidebar`** facets are clickable → append to the query (KQL-style). Counts come from the aggregate query.
- **Histogram** = a `timeseries` panel bound to `count_over_time`; drag-to-zoom writes `consoleStore.timeRange`.
- **Doc table** = `DataGrid`, virtualized; row-expand reuses today's `ExploreTab` inspector JSX; the row's `action_hash`/`receipt_hash` are one-click verifiable; "Open in timeline" drills to the incident.
- **Save** persists a named search (server-side, `tenant_id`-keyed); saved searches can be pinned as a `feed`/`table` panel.

---

## 9. Panel architecture catalog

All panels implement `PanelProps` (HLD/LLD §7.1), declare the four states, and never fetch. Standard panels first, then the AegisAgent-unique panels (including two new ones).

### 9.1 Standard panels

| Panel | Purpose / UX | Data contract (`DataFrame` fields) | States |
|---|---|---|---|
| **Stat** | one decision number + spark + threshold color | `[time, value]` or scalar + optional series | loading=number skeleton; empty="no data"; error=inline; success=value + sparkline |
| **Time series** | decisions/min, denies/agent | `time` + ≥1 `number` series | same; empty=flat baseline with hint |
| **Table** | top risky agents, recent denies | N typed fields (uses `DataGrid`) | per §6.3 |
| **Heatmap** | provenance × hour, detection density | `x` (time) × `y` (category) × `number` | success=ECharts heatmap; empty=grid ghost |
| **Status** | receipt-chain ✓/✗, agent statuses | `label` + `state` enum | success=status pills; error=`--state-failed` |
| **Feed** | live ASE stream (Discover-lite) | streamed rows (virtualized) | live dot when streaming; empty="awaiting events" |

### 9.2 AegisAgent panels (the differentiators)

| Panel | Purpose / UX | Data contract | States |
|---|---|---|---|
| **Approval Card** | frozen action + Approve/Reject/Edit/Escalate (§8.2) | one `approval` (action, hash, trust, expiry, params, risk) | loading=card skeleton; empty="no pending approvals" (a *good* empty state); error; success=card |
| **Provable Timeline** | hash-chained incident, one-click verify (§8.3) | ordered events each w/ `receipt_hash` | verify sub-states (§6.5); empty="no events"; error |
| **Receipt Integrity** | browse chain, verify range, visualize break | paginated receipts (cursor) + chain links | success=chain; break=red connector; error |
| **Agent Risk Map** *(new)* | the fleet at a glance: agents positioned by **risk tier × trust exposure**, sized by recent action volume, colored by status (active/frozen/quarantined). A spatial "mission control" of the fleet | `agent` rows: `risk_score`, `status`, `trust_exposure`, `action_count`, `open_alerts` | loading=ghost nodes; empty="no agents"; success=interactive map; click→agent drilldown |
| **Decision Graph** *(new)* | the **confused-deputy view**: a directed graph of *untrusted source → agent → attempted action*, edges colored by decision (deny/approval/allow). Makes provenance attacks legible at a glance | nodes (`source`, `agent`, `action`) + edges (`decision`, `count`) | loading=graph skeleton; empty="no flows"; success=force/sankey graph (ECharts); edge click→Explore |

The two new panels are **defensible by construction**: *Agent Risk Map* visualizes the fleet's risk posture; *Decision Graph* visualizes trust-provenance gating — both ride the moat (Gap B) rather than being generic charts. They are registry entries like any other panel, composable into dashboards.

---

## 10. Accessibility

- **Keyboard:** every action reachable without a mouse. Global chords (§4.1); `Tab`/`Shift+Tab` order follows visual order; tables support arrow-key row nav + `Enter` to expand; `Esc` closes drawers/modals/palette. Focus is never trapped except in modals (where it's intentionally trapped + restored on close).
- **ARIA:** Radix primitives provide correct roles/`aria-*` for menus, dialogs, tabs, tooltips. Live regions: new critical detections announce via `aria-live="assertive"`; the approval queue badge via `aria-live="polite"`. The verify result is announced (`role="status"`).
- **Color independence (color-blind safe):** **status is never color-only** — every severity/decision/trust token pairs with an icon and a text label (the existing badges already do this). The severity ramp is chosen to remain distinguishable under deuteranopia/protanopia (rose vs red separated by lightness + icon; allow/deny carry ✓/⛔ glyphs).
- **Contrast:** all themes meet **WCAG 2.2 AA** for text (≥4.5:1 body, ≥3:1 large/UI) — OKLCH lightness anchors in §3.4 are chosen to satisfy this; Light theme is held to the same bar as Dark.
- **Screen reader:** the `CanonicalActionView` exposes the payload as readable text (not an image); `HashChip` has an `aria-label` with the full hash + kind; charts provide a visually-hidden data table fallback.
- **Reduced motion:** `prefers-reduced-motion` collapses all §2.4 motion to instant state changes; verification becomes a static stepped count.

---

## 11. Implementation roadmap (reconciled with HLD/LLD U0–U6)

The design-system phases map onto — and front-load — the HLD/LLD's build phases. Each phase ships something usable.

| Phase | Design-system deliverable | HLD/LLD phase | Exit criteria |
|---|---|---|---|
| **P0 — Foundation** | `tokens.css` (3 themes), `design-system/` primitives, typography, the Aegis Mark, density system | U0 | a themed `Button/Badge/Card/HashChip/TrustBadge` set renders; Storybook (or a `/kitchen-sink` route) green |
| **P1 — SOC shell** | `AppShell`, `LeftNav` (collapse + badges + hotkeys), `ControlsBar`, `TimeRangePicker`, `CommandPalette`, theme/density toggles, URL-sync | U0–U1 | navigate all pages; global query context drives a single live panel |
| **P2 — Panel framework** | `PanelRuntime`, registry, `PanelContainer` states, standard panels (Stat/TimeSeries/Table/Status/Feed) on Recharts + `DataGrid` | U1 | a `DashboardSchema` renders a real Overview from JSON; panels don't fetch |
| **P3 — Dashboards + differentiator panels** | `DashboardLoader`, curated `system/` dashboards, **ApprovalCard**, **ProvableTimeline**, **ReceiptIntegrity**, SSE live | U1–U2 (MVP) | Overview + Live feed + **Approval queue** + **Provable timeline w/ verify** working end-to-end |
| **P4 — Investigation** | Explore (AqlInput, FieldSidebar, histogram, doc table), drilldown router, breadcrumbs, Detections/Rules, Incidents | U3–U4 | the full Detection→…→Verification spine is click-navigable; saved searches |
| **P5 — Advanced** | **Agent Risk Map**, **Decision Graph**, Analytics dashboards, uPlot/ECharts swap for hot panels, OffscreenCanvas/Wasm perf (HLD/LLD §12), in-app dashboard editor, RBAC settings | U5–U6 | fleet/MCP/active-response; editor writes `DashboardSchema`; perf targets met |

**MVP = P0–P3** (= U0–U2): the shell, the panel framework, the Overview, the live feed, and the two surfaces neither Grafana nor Kibana can show — the **Approval Queue** and the **Provable Timeline**. Everything before P3 is scaffolding to make those two feel inevitable.

---

## 12. Anti-template acceptance checklist

Before any surface ships, it must satisfy the design-quality bar (no shadcn-default look):

- [ ] Uses the **four surface layers** for depth, not uniform cards-on-gray.
- [ ] Severity/trust palette used **only** semantically; chrome stays low-chroma.
- [ ] Hierarchy from **scale + weight**, not nested boxes; one clear focal point per panel.
- [ ] Every identifier is **monospace + copyable**; hashes never wrap or truncate the copied value.
- [ ] Hover/focus/active states are **designed** (the verify gesture, the approval expiry ramp), not browser defaults.
- [ ] Both Light and Dark SOC themes feel **intentional**; OLED is a real wall-display mode, not inverted dark.
- [ ] No decorative motion; all motion is functional and reduced-motion-safe.
- [ ] The screen would be **believable in a real SOC product screenshot** — it reads as AegisAgent, not "a dashboard template."

---

## 13. Summary

This design system turns the AegisAgent SOC Console into a product that looks and behaves like the *next-generation* of Grafana + Kibana + Elastic Security — but is unmistakably AegisAgent because its center of gravity is **provable AI-agent governance**, not metrics. It specifies a deliberate **visual identity** (the Verified Aperture mark, a reserved severity/trust palette, three real themes), a **dense, evidence-forward design language**, a **keyboard-first mission-control shell**, a **layered component library** with the framework boundary the architecture demands (*panels render, `PanelRuntime` fetches, dashboard JSON composes*), and the **investigation, approval, and provable-timeline experiences** that are the product's reason to exist. The roadmap front-loads the foundation and the shell so the two irreplaceable surfaces — the **Approval Queue** and the **Provable Timeline** — ship as the MVP, exactly where the moat lives.

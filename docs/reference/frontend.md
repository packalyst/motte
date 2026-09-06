# Frontend Reference

The admin panel UI is a **Svelte 5 (runes) single-page app** built by **Vite**, styled with
**Tailwind CSS v4 + KTUI**, shipped as a **PWA**, served by **nginx**, and reached through
**Traefik**. All source lives under `ui/`.

This document explains how the frontend is laid out, the conventions it actually uses, how views
talk to the API, the reusable component/composable library, the charting approach, timezone and
format helpers, the PWA/service-worker bits, and the build/serve setup — enough to rebuild it or
know where to change things.

Related docs: [architecture.md](architecture.md), [api-surface.md](api-surface.md),
[backend.md](backend.md), [security.md](security.md), [deployment.md](deployment.md),
[coding-standards.md](coding-standards.md), [rebuild-from-scratch.md](rebuild-from-scratch.md).

---

## 1. Tech stack and entry points

- **Svelte 5** in runes mode (`svelte@^5.43.8`), **Vite 7**, **Tailwind v4** (`@tailwindcss/vite`).
- **KTUI** (`@keenthemes/ktui`) supplies the CSS design system (`kt-*` classes) and three JS
  widgets (Modal, Toast, Tooltip). Dependencies: `ui/package.json`.
- **uPlot** for time-series charts; **Leaflet** for maps; hand-rolled SVG for donuts/gauges/sparklines.
- Icons: **Tabler** via `@iconify/tailwind4` (class names like `icon-[tabler--check]`).

Boot sequence:

1. `ui/index.html` — static shell. Loads `/src/main.js` as a module, links the manifest at
   `/api/manifest.json` (backend-served, see §9), and the apple-touch/theme-color meta. It carries
   **no inline scripts** so the CSP can use `script-src 'self'` (`ui/index.html:14-18`).
2. `ui/src/main.js` — imports `app.css`, registers the three KTUI globals on `window`
   (`window.KTModal/KTToast/KTTooltip`), starts a `MutationObserver` that auto-inits any
   `[data-kt-tooltip]` element added to the DOM, `mount()`s `App.svelte`, and registers the
   service worker `/sw.js` (`ui/src/main.js:37-45`). Registering the SW here (not inline in HTML)
   is what keeps the page inline-script-free.
3. `ui/src/App.svelte` — top-level gate: setup wizard vs. login vs. dashboard (see §4).

---

## 2. Directory layout (`ui/src`)

```
ui/src/
  main.js              # bootstrap: KTUI globals, tooltip observer, mount, SW register
  App.svelte           # auth gate (setup / login / dashboard) + global overlays
  app.css              # Tailwind import, icon safelist, KTUI imports, theme tokens
  views/               # one .svelte per top-level page (lazy-loaded, see §3)
  components/           # ~60 reusable presentational components
  stores/              # app.js (router+api+toast+confirm), websocket.js, geo/pwa/network/helpers
  lib/
    utils/             # format.js, data.js, clipboard.js, array.js, domains.js
    composables/       # *.svelte.js rune-based hooks (see §6)
    pwa/               # permissions.js, push.js, index.js
    glossary.js, fleet.js, reputation.js, worldPath.js   # page-specific data helpers
  data/                # static JSON (blocklists.json)
ui/public/             # sw.js, manifest.json_ (see §9 caveat), icons, static assets
```

Naming conventions:
- **Views** (`views/*.svelte`) are page-level; each is a lazy-import chunk registered in the
  Dashboard's `views` map (`ui/src/views/Dashboard.svelte:12-34`).
- **Components** (`components/*.svelte`) are presentational and mostly stateless.
- **Composables** live in `lib/composables/*.svelte.js` — the `.svelte.js` extension is required so
  the Svelte compiler processes runes (`$state`, `$derived`, `$effect`) inside plain JS modules.
- `$lib` is aliased to `./src/lib` in `ui/vite.config.js:8-12` (imports like
  `import { withTz } from '$lib/utils/format.js'`).

---

## 3. Routing model (path-based, `pushState`/`replaceState`)

Routing lives entirely in **`ui/src/stores/app.js`** — there is no router library.

- `validViews` (`app.js:18-20`) is the whitelist of route ids (`overview`, `nodes`, `firewall`,
  `server`, `fleet`, `settings`, …). Anything not in this list is ignored.
- `currentView` is a Svelte `writable` store. On boot its value is chosen **URL path → localStorage
  (`hs_view`) → `'overview'`** (`app.js:38-41`).
- **Subscribing to `currentView` syncs the URL** (`app.js:46-63`): it saves to `localStorage` and
  updates the address bar to `/<view>`. It uses `replaceState` when `history.length <= 1` (fresh
  tab / standalone PWA — avoids a Chrome pushState-in-trivial-history warning) and `pushState`
  otherwise so browser back/forward works.
- A `popstate` listener (`app.js:66-74`) reads `event.state.view` (or re-derives from the path) and
  sets `currentView`, guarded by a `handlingPopstate` flag so the subscribe handler doesn't
  re-push while restoring history.
- Initial history state is seeded with `replaceState`, preserving the URL hash (used for
  **per-view tab persistence**: `getInitialTab(defaultTab, validTabs)` reads `?tab=` from the hash,
  `app.js:23-29`).
- **Navigation** happens by calling `currentView.set('nodes')`. `App.svelte` also installs a global
  `window` click handler (`App.svelte:47-56, 125`) that intercepts internal `<a href="/...">` links
  whose target is a valid view and routes them client-side instead of doing a full reload.

The **Dashboard** (`views/Dashboard.svelte`) is the shell that renders the current view:

- `views` map (`Dashboard.svelte:12-34`) maps each id to a **dynamic `import()`**, so every view is
  a **separate Vite chunk** loaded on demand.
- The content area does `{#await views[$currentView]?.() then module}`, then
  `{@const Component = module.default}` and renders `<Component bind:loading {onLogout} />`
  (`Dashboard.svelte:501-510`). Views receive `loading` as a **bindable prop** — the shell shows its
  spinner until the view flips it false.
- Sidebar nav is data-driven from `navItems` (`Dashboard.svelte:118-165`) with collapsible groups
  (`menuGroups`, accordion behavior in `toggleMenu`). Some views (`iplookup`, `settings`, `about`,
  `profile`) are reachable only from the topbar, not the sidebar.
- **Reload-on-visible** is gated to installed-PWA mode (`Dashboard.svelte:93-101`): Alt-tabbing back
  in a normal browser tab must not wipe and refetch the view; a PWA re-becoming visible does.

---

## 4. The app store (`ui/src/stores/app.js`)

This module is the frontend's spine. It exports:

**Theme** — `theme` writable, initialized from `localStorage['hs_theme']` (default `dark`). A
subscriber toggles `.dark` on `<html>` and persists the choice (`app.js:3-15`). Palette tokens live
in `app.css` (`:root` light, `.dark` dark) as OKLCH CSS variables (`app.css:31-80`).

**Router** — `currentView`, `validViews`, `getInitialTab` (see §3).

**Toast** — `toast(message, type)` where `type ∈ success|error|warning|info` (`app.js:117-136`).
Wraps `window.KTToast.show`. Variant→icon/color maps are module-level constants. **Security note:**
KTToast injects `message` via `innerHTML`, so `toast()` runs everything through `escapeHtml()`
(`app.js:103-114`) — this closes a stored-XSS sink for **all 200+ call sites at once** (machine
names, error strings, IP-lookup results, CVE titles). Do not bypass it.

**Global confirm modal** — a store-driven, promise-returning dialog (see §5.1):
- `confirmModalStore` writable holds dialog state (`app.js:139-154`).
- `confirm(options)` returns a `Promise`. Without a checkbox it resolves to a **boolean**; with
  `options.checkbox` it resolves to `{ confirmed, checked }` (`app.js:159-178`).
- `closeConfirmModal`, `setConfirmCheckbox`, `setConfirmLoading` are called by the `ConfirmModal`
  component. A single `<ConfirmModal />` is mounted once in `App.svelte:140`.

**API client** — all HTTP goes through one private `api()` (`app.js:221-249`):
- `getAuthHeaders()` reads `localStorage['session_token']` and adds `Authorization: Bearer <token>`
  (`app.js:201-206`). *(Moving the token to an HttpOnly cookie is a tracked security follow-up.)*
- On `res.ok` it parses JSON (empty body → `{}`).
- On **401** it clears session tokens and calls the **global logout handler** (registered by
  `App.svelte` via `setGlobalLogoutHandler`) — except for the login/setup endpoints — then throws
  (`app.js:234-245`). This is how an expired session anywhere in the app bounces the user to login.
- On other errors it throws `new Error(<response text or statusText>)`.
- Exported helpers: `apiGet`, `apiPost`, `apiPut`, `apiDelete` (JSON), plus `apiGetText`,
  `apiGetBlob` (QR codes/images), and `apiPostBlob` (file downloads — resolves `{ blob, filename }`
  read from `Content-Disposition`) (`app.js:252-284`).
- `clearSessionTokens()` removes `session_token` + `session_expires`.

**Misc** — `generateAdguardCredentials()` builds random credentials with `crypto.getRandomValues`
(`app.js:287-305`).

### 4.1 Auth flow (`App.svelte`)

`App.svelte` decides what to render (`App.svelte:127-137`): a spinner while `checking`, then
`SetupWizard` / `Dashboard` / `Login`. Key decisions (`App.svelte:58-98`):

- On mount it calls `/api/setup/status`; if setup isn't complete it shows the wizard.
- **Session validity is decided by REST (`/api/auth/me`), not the WebSocket.** A WS hiccup must not
  clear a valid session (otherwise refresh logs you out). The WS is *only* for live updates. Once
  `/api/auth/me` succeeds it applies the display timezone (`/api/settings`) and then `wsConnect()`s.
- `setGlobalLogoutHandler` wires 401s to disconnect the WS and null the user.

### 4.2 WebSocket store (`ui/src/stores/websocket.js`)

Separate from the app store. One shared `WebSocket` to `/api/ws` (`ws://` or `wss://` chosen from
`window.location.protocol`, `websocket.js:66-67`). Notable design:

- Channel → Svelte store map (`storeMap`, `websocket.js:27-37`): `generalInfoStore`,
  `serverStatsStore`, `containerStatsStore`, `fleetStore`, `dockerLogsStore`, `statsStore`, etc.
  Views read live data by subscribing to these stores.
- **Ref-counted subscriptions** (`subscribe`/`unsubscribe`, `websocket.js:183-234`): `subRefs`
  counts callers per channel; the server is only told to (un)subscribe on the first/last caller, so
  an app-wide `server_stats` subscription and a page that also reads it don't tear each other down.
- On (re)connect the server sends an `init` message with the user; the client then resubscribes to
  all `activeSubscriptions` (`websocket.js:118-136`).
- Auto-reconnect with backoff, but **not** on clean close (1000) or auth errors (code 4001 /
  reason matching `auth|invalid|expired|unauthorized`) (`websocket.js:90-104`).
- Messages can be **newline-batched**; the handler splits on `\n` and parses each
  (`websocket.js:76-88`). Some `general_info` events are re-dispatched as `window` CustomEvents
  (firewall zone progress, port-scan progress) for views that prefer event listeners.

---

## 5. Svelte 5 runes conventions actually used

The codebase is fully on runes. Patterns you'll see everywhere:

- **`$props()` with destructuring + defaults** for component inputs; `class: className` renames the
  reserved `class` prop; `...restProps` forwards leftovers to the root element (e.g. `Button`,
  `Select`, `Checkbox`).
- **`$bindable()`** for two-way props: `let { loading = $bindable(true) } = $props()`
  (`SettingsView.svelte:17`), `checked = $bindable(false)` (`Checkbox.svelte:5`), `open =
  $bindable(false)` (`Modal.svelte`), `hidden = $bindable({})` (`UPlotChart.svelte:20`).
- **`$state()`** for local mutable state — including deep-reactive objects/arrays that are mutated
  in place (`traefikForm.ipAllowlist = [...]`, `SettingsView.svelte:487-497`).
- **`$derived` / `$derived.by(() => …)`** for computed values. `$derived.by` is used when the
  computation is multi-line (e.g. change-detection `traefikHasChanges`,
  `SettingsView.svelte:334-344`; `sortedPorts`, `:872-876`).
- **`$effect()`** for side effects that track their reads: persisting to localStorage
  (`usePersistentState.svelte.js:45-51`), syncing derived change-flags
  (`SettingsView.svelte:305-319`), pushing live data into a uPlot instance
  (`UPlotChart.svelte:234-236`). Guard against unwanted loops by reading only what you must.
- **Snippets** (`{#snippet name()}` + `{@render name()}`) replace slots. `Modal` accepts `children`,
  `header`, `footer` snippets (`Modal.svelte:101-124`); `ConfirmModal` passes a `{#snippet footer()}`
  to `Modal` (`ConfirmModal.svelte:120-130`); `ContentBlock` renders `children`, `descriptionSlot`,
  `labelAction` snippets. Optional snippets are invoked as `{@render children?.()}`.
- **`svelte:window` / `svelte:document`** for global listeners (`App.svelte:125`,
  `SearchableSelect.svelte:80-81`, `Dashboard.svelte:220`).
- **`untrack`** (from `svelte`) is used to break unwanted effect dependencies — the recurring idiom
  is *"read these deps, then run this work without subscribing to what the work touches."* Examples:
  appending a live sample to a `samples` array on each `$statsStore` push, where `push/shift` read
  `samples` internally and would otherwise self-loop (`OverviewView.svelte:59-66`); firing a loader
  when only the filter deps change (`$effect(() => { period; selectedType; untrack(() => loadAll())
  })`, `AnalyticsView.svelte:107`); and `NodesView.svelte:542`.
- Stores are still **Svelte writables** (`svelte/store`), consumed with the `$store` auto-subscribe
  syntax (`$theme`, `$currentView`, `$confirmModalStore`, `$generalInfoStore`). Runes and classic
  stores coexist deliberately: cross-cutting singletons (theme, router, WS channels) are stores;
  component-local state is runes.

### 5.1 The confirm pattern (async, promise-based)

`confirm()` returns a Promise — you **must `await`** it. A bare `if (!confirm('...'))` never fires
because a Promise is always truthy (called out in a code comment at `SettingsView.svelte:794-796`).
Canonical usage (`SettingsView.svelte:797-810`):

```js
const confirmed = await confirm({
  title: 'Delete jail',
  message: `Delete jail "${jail.name}"?`,
  description: 'Its ban rules will be removed.',
  confirmText: 'Delete'        // variant defaults to 'destructive'
})
if (!confirmed) return
await apiDelete(`/api/fw/jails/${jail.name}`)
```

---

## 6. Composables (`ui/src/lib/composables`)

Rune-based hooks in `.svelte.js` files, re-exported from `composables/index.js`. They return
objects with **getters** (so the caller reads live reactive values) rather than raw variables.

- **`usePersistentState(key, default)`** — localStorage-backed `$state` (prefixed
  `vpn_panel_<key>`). Loads on init (merging stored object with defaults so new fields appear), and
  a `$effect` writes on every change. Returns `{ value (get/set), reset, clear }`. All storage
  access is wrapped in try/catch (`usePersistentState.svelte.js:21-68`).
- **`usePersistentToggle(key, default)`** — boolean variant with `toggle`/`set` (`:85-124`).
- **`usePersistentSort(key, {field,dir})`** — table sort state with `toggle(field)` and
  `indicator(field)` (`:142-169`).
- **`usePaginatedState(key, defaultFilters, defaultPerPage)`** — page/perPage/search/filters with a
  computed `offset`; default per-page comes from `localStorage['settings_items_per_page']`
  (`:193-292`).
- **`useDataLoader(sources, options)`** — loads on `onMount`, manages `loading`/`error`, toasts on
  failure. Single-source (`{ extract, isArray, errorMsg }`) or multi-source (array of
  `{ fn, key, extract, isArray, default }`, each failing independently). Returns `{ data, loading,
  error, reload }` (`useDataLoader.svelte.js:23-86`). `useAsync()` is the lighter variant that just
  wraps one async op with loading/error/toast (`:95-119`).
- **`useModalForm(options)`** — create/edit modal state: `openCreate`/`openEdit(item)`/`close`/
  `submit`, `formData`, `mode`, `isEdit`. `submit` calls `onSubmit(data, mode, editId)`, toasts, and
  closes (`useModalForm.svelte.js:38-133`). `useModal()` and `useInlineEdit()` are simpler siblings.
- **`useFilter(items, {fields, debounce})`** — debounced client-side search over dot-notation
  fields; accepts an array or a getter for reactive sources (`useFilter.svelte.js:21-60`).
  `useSelectFilter` and `useMultiFilter` cover dropdown/compound filtering.

Note: not every view uses these — `SettingsView` hand-rolls its loading/state because it aggregates
many independent resources; simpler CRUD views lean on the composables.

---

## 7. Reusable components (`ui/src/components`)

~60 components. The load-bearing ones:

### Overlays
- **`Modal.svelte`** — thin wrapper over KTUI's `KTModal`. Bindable `open`; `size ∈ sm|md|lg|xl`
  (max-width map, `Modal.svelte:21-26`); `dismissible` (backdrop click), `showClose`. Snippets:
  `header`, `children` (body), `footer`. It bridges KTUI's `hide.kt.modal` DOM events back to the
  `open` prop / `onclose` callback (`Modal.svelte:31-79`).
- **`ConfirmModal.svelte`** — the single global instance bound to `confirmModalStore`
  (`ConfirmModal.svelte`). Renders inside a `Modal`. **Variant maps** translate one `variant`
  (`destructive|danger|warning|primary|success`) into icon / text-color / bg / kt-alert / button
  variant (`iconMap`, `colorMap`, `bgMap`, `alertMap`, `buttonVariantMap`, `:10-50`). `'danger'` is
  an accepted **alias** for `'destructive'` so callers using either render correctly. Supports an
  `alert` layout, structured `details` (array of `{label,value}`, auto-escaped by Svelte `{}` — no
  `{@html}` sink), a `warning` box, an optional `checkbox`, and a `loading` state.

### Forms & primitives
- **`Button.svelte`** — `kt-btn` wrapper. `variant` (primary/secondary/destructive/success/outline/
  ghost/mono), `size` (default/sm/xs), `icon`, `iconOnly`, `loading` (renders a spinner), and a
  built-in **`copyText`** mode that copies + flashes a checkmark + toasts (`Button.svelte:57-66`).
- **`Checkbox.svelte`** — three variants via one prop: `default` (kt-checkbox), **`switch`**
  (kt-switch toggle — the panel's ubiquitous on/off control), and `chip` (button-like pill with
  color map). Bindable `checked`, `onchange` callback, `labelPosition` auto-defaults (left for
  switch, right otherwise) (`Checkbox.svelte`).
- **`Select.svelte`** — native `<select>` wrapper; `options=[{value,label}]` or slotted children,
  bindable `value`, optional label/helper (`Select.svelte`).
- **`SearchableSelect.svelte`** — combobox with a filter box for long lists (e.g. the IANA timezone
  list). Mirrors `Select`'s API so it drops in. The menu is **`position:fixed`, positioned from the
  button's viewport rect** (`positionMenu`, `SearchableSelect.svelte:31-39`) so a card's
  `overflow:hidden` or a sibling's stacking context can't clip it; it flips up when there's no room
  below and reflows on scroll/resize. Full keyboard nav (`SearchableSelect.svelte:62-75`).
- **`Input.svelte`, `OtpInput.svelte`, `Toolbar.svelte`, `Tabs.svelte`, `Pagination.svelte`,
  `DropdownButton.svelte`, `OptionCard.svelte`** — the rest of the form/layout kit.

### Display
- **`ContentBlock.svelte`** — the panel's workhorse layout primitive. One component, **six
  variants** via `variant` (`ContentBlock.svelte:9-37`): `row` (default; icon + title/desc + action,
  with active/inactive green/red styling), `box`, `header`, `status`, `indicator` (colored
  bg/border by `color`), and **`data`** (label + value with optional copy button, mono font,
  secondary right label/value). Padding via a `paddings` map (`sm|md|lg`). Copy uses
  `copyWithToast` and flashes a checkmark (`:79-87`). Used heavily in Settings for read-only value
  displays.
- **`InfoCard.svelte`, `StatCard.svelte`, `Badge.svelte`, `EmptyState.svelte`,
  `LoadingSpinner.svelte`, `Icon.svelte`** — cards, badges, empty/loading states.
- **`Icon.svelte`** — trivial but universal: renders `<span class="icon-[tabler--{name}] …">` sized
  by inline width/height (`Icon.svelte`). **Every icon name must be safelisted** in `app.css`'s
  `@source inline(...)` block (`app.css:7`) because Tailwind can't see dynamic class names — adding
  a new icon means adding it there.

### Charts (see §8)
- **`UPlotChart.svelte`, `Donut.svelte`, `Gauge.svelte`, `Sparkline.svelte`, `BarChart.svelte`,
  `AreaChart.svelte`, `BarList.svelte`, `ChartLegend.svelte`**.

### Domain components
- `WorldMap.svelte`, `LocationMap.svelte` (Leaflet), `MachineDetail.svelte`, `MachineCVEs.svelte`,
  `SecurityGlance.svelte`, `ActivityFeed.svelte`, `IpBadge.svelte`, `IpLookup.svelte`,
  `PublicVisitors.svelte`, `BlockedByLayer.svelte`, `PWASettings.svelte`, `InstallPrompt.svelte`,
  `OfflineOverlay.svelte`, `PullToRefresh.svelte` — larger, page-specific building blocks.

---

## 8. Charting approach

Charts are **theme-aware, tooltip-portaled, and generic**. The reference implementation is
**`UPlotChart.svelte`**.

- **Columnar data**: pass `data` in uPlot's shape `[xVals(unix seconds), series1, series2, …]` and a
  `series` descriptor `[{ label, stroke:'--cpu', width?, fill? }]` (`UPlotChart.svelte:11-22`). The
  chart is intentionally generic — any page drops it in (ServerView is the live example).
- **Theme colors via CSS vars**: strokes are given as CSS custom-property names (`--cpu`, `--rx`);
  `css()` resolves them from `getComputedStyle` at draw time (`:29-31`). Because canvas colors are
  baked at draw time, a **`MutationObserver` on `<html>`'s `class`/`data-theme` rebuilds the whole
  chart on theme change** (`:212-215`). The clickable legend keeps the CSS var so its swatch
  re-themes for free.
- **Custom axis/range**:
  - Y auto-range **scans the live `up.data` every time** (`autoYRange`, `:172-187`) because uPlot's
    per-series min/max cache doesn't recompute on a full data swap (switching to a peer with
    orders-of-magnitude larger traffic would otherwise clip spikes). Always includes the 0 baseline.
  - X axis labels adapt: **dates for a multi-day range, clock time for intraday** (`fmtTime`,
    `:138-147`), read live from `up.data` so it re-adapts without a rebuild.
  - Y gutter width grows to fit formatted labels like "45.7 GB" (`yAxisSize`, `:192-195`).
- **Tooltip portaled to `<body>`**: `tooltipPlugin` creates a `.uchart-tip` div appended to
  `document.body` (not inside `.u-over`) and positions it in **viewport coordinates
  (`position:fixed`)** from the plot's bounding rect + cursor, flipping/clamping so it never spills
  offscreen (`:66-115, 97-107`). This is the same clip-avoidance strategy used by `SearchableSelect`
  and the SVG charts — a recurring pattern in this codebase: **anything that overflows a card is
  portaled/fixed-positioned to escape `overflow:hidden` and stacking contexts.**
- **Live updates are cheap**: a `$effect` calls `u.setData(data)` (no rebuild) when `data` changes
  (`:234-236`); a `ResizeObserver` calls `u.setSize`. Series show/hide is driven by the bindable
  `hidden` map so a parent can drive the legend.
- **Timezone**: every time formatter routes Intl options through `withTz()` (see §9) so charts honor
  the panel's display-timezone setting (`:89, 144-145`).

**`Donut.svelte`** and **`Gauge.svelte`** are hand-rolled **SVG** (no library):
- Donut renders stroke-dasharray arcs with a 2px gap, a centered total, an inline legend, and a
  `position:fixed` hover tooltip (`Donut.svelte`). Segments: `[{ label, count, color }]` where color
  is any CSS color (e.g. `'var(--success)'`).
- Gauge is an open-bottom 270° arc with tick labels and threshold-driven color (good/warn/crit) or a
  pinned color (`Gauge.svelte`). Used for the CPU/host gauges on ServerView.

Chart series colors are defined once as tokens in `app.css` (`--cpu`, `--mem`, `--rx`, `--tx`,
`app.css:65-71`), documented as CVD-safe pairs.

---

## 9. Timezone & format utilities (`ui/src/lib/utils/format.js`)

A single module owns display formatting. Two ideas:

**App-wide display timezone** (`format.js:5-25`): a module-level `_displayTz` holds the chosen IANA
zone (or `undefined` = the browser's own zone). `setDisplayTimezone(tz)` sets it; `withTz(opts)`
merges `{ timeZone: _displayTz }` into any Intl options (no-op in browser mode). **Every absolute-
time formatter routes its Intl options through `withTz()`** so the choice applies consistently
across the panel and the charts. Relative times ("5m ago") are zone-independent and left untouched.
It's set at startup in `App.svelte` from `/api/settings` and on save in `SettingsView`
(`setDisplayTimezone`, plus the `TZ_OPTIONS` built from `Intl.supportedValuesOf('timeZone')`,
`SettingsView.svelte:79-83, 244`).

**Formatters** (all null-safe, return `'-'`/`'Never'` on bad input):
- Numbers: `formatNumber` (K/M suffix), `formatBytes` (1024-based, B…TB).
- Durations: `formatDuration` (nanoseconds → ms/s), `formatBanTime` (seconds → s/m/h/d),
  `formatTime`.
- Dates: `formatDate`, `formatDateShort`, `formatRelativeDate` ("Today"/"Dec 21"), `timeAgo`,
  `formatExpiryDate`.
- Parsing: `parseDate` handles Date, protobuf `{seconds}`, unix seconds-vs-ms heuristic, and
  zero/empty strings (`format.js:170-195`); plus `isExpired`, `isExpiringSoon`,
  `getDaysUntilExpiry`.

Other `lib/utils`: `data.js` (`debounce`, `filterByFields`, sorting), `clipboard.js`
(`copyToClipboard` — wrapped by `copyWithToast` in `stores/helpers.js`), `array.js`, `domains.js`.

---

## 10. PWA & service worker

**Service worker** — `ui/public/sw.js` (registered in `main.js`, cache version `v3`):
- Precaches only the **app shell** (`/index.html`) on install so a failed SPA navigation still boots
  the app instead of the browser's network-error page. **No dynamic/API data is cached** — the shell
  loads the SPA bundle, which makes its own fresh `/api/` calls (`sw.js:5-20`).
- **`/api/*` and the WebSocket are deliberately NOT intercepted** (`sw.js:39-47`): the `fetch`
  handler returns early for same-origin `/api/` requests so the browser handles them natively. This
  is essential — it means live data and `/api/ws` are never pinned to a stale kept-alive connection
  when the panel switches between its public (Cloudflare) IP and its VPN IP.
- **Navigation fallback**: navigations are network-first, falling back to the cached shell on
  failure (or a mid-navigation IP switch), keeping the cached shell fresh while online
  (`sw.js:50-63`). Everything else is plain pass-through with `.catch(() => Response.error())`.
- **Push notifications**: `push` handler always calls `event.waitUntil` (iOS requires it), parses
  JSON with a plain-text fallback, and shows a PNG-icon notification (iOS doesn't support SVG here)
  (`sw.js:72-103`). `notificationclick` focuses an existing window or opens one, honoring action
  buttons (`sw.js:106-147`).

**Push/permission client** — `ui/src/lib/pwa/`:
- `push.js` — Web Push subscription lifecycle against `/api/pwa/*`: `getVapidPublicKey`,
  `subscribeToPush` (requests permission, converts the VAPID key with `urlBase64ToUint8Array`,
  subscribes, POSTs keys to the server), `unsubscribeFromPush`, `getSubscriptions`,
  `getPreferences`/`updatePreferences`, `sendTestNotification`, plus a location-tracking API
  (`storeLocation`/`getLocations`/`deleteLocations`). `getDeviceName()` derives a friendly name
  from the UA.
- `permissions.js` — cross-platform permission/capability manager: `detectPlatform`,
  `isInstalledPWA` (display-mode / iOS `navigator.standalone` / Android TWA referrer),
  `getPermissionStatus`/`requestPermission` for notifications/geolocation/camera/mic/clipboard/
  storage with graceful fallbacks, `beforeinstallprompt` capture (`setupInstallPrompt`,
  `promptInstall`, `canInstall`), and `getPlatformCapabilities` with iOS-16.4+ push special-casing.
- `index.js` re-exports both.

**Manifest** — `index.html` links **`/api/manifest.json`** (backend-served, so it can inject
runtime values). **Caveat/flag:** the file in `ui/public/` is named **`manifest.json_`** (trailing
underscore, `ui/public/manifest.json_`) so Vite/nginx do **not** serve it at `/manifest.json`; the
authoritative manifest is the backend route. If you're rebuilding, don't assume the static file is
live — the app points at the API. (Content: name "Wire Panel", `display: standalone`,
`theme/background #16161a`, 192/512 PNG + SVG icons.)

---

## 11. Build & serve

**Vite** (`ui/vite.config.js`):
- Plugins: `@sveltejs/vite-plugin-svelte`, `@tailwindcss/vite`, `rollup-plugin-visualizer` (writes
  `dist/stats.html`).
- `$lib` alias → `./src/lib`; `base: '/'`.
- Dev server on `0.0.0.0:80`, `allowedHosts: true`, with a **proxy** so dev traffic for
  `/api/v1`, `/api/wg`, `/api/traefik`, `/api/adguard`, `/api/fw` is forwarded to `http://traefik`
  (`vite.config.js:19-50`). Other `/api/*` paths are served by whatever the dev host points at.
- Views are code-split automatically because the Dashboard imports them dynamically (§3), so each
  page is its own chunk.

**Dockerfile** (`ui/Dockerfile`) — multi-stage:
- `builder` (node:22-alpine): `npm install`, `npm run build` → `/app/dist`.
- `production` (nginx:alpine, **default target**): copies `dist` to nginx html root and `nginx.conf`
  to `/etc/nginx/conf.d/default.conf`.
- `development`: runs `vite` with hot reload on 3000.

**nginx** (`ui/nginx.conf`):
- SPA fallback: `location /` → `try_files $uri $uri/ /index.html` (so any client route serves the
  shell and the SPA router takes over).
- Serves WireGuard config files read-only from a mounted volume at `/wg-configs/`, restricted to
  `.conf`/`.png` and returned as `text/plain` (`nginx.conf:11-19`).
- Note nginx here does **not** proxy `/api` — in production that's Traefik's job (see
  [networking-firewall.md](networking-firewall.md) / [deployment.md](deployment.md)); the dev proxy
  in `vite.config.js` covers the dev case.

**Styling** (`ui/src/app.css`): `@import "tailwindcss"`, the Iconify Tabler plugin, the **icon
safelist** (`@source inline(...)`), a curated list of KTUI component CSS imports, and the OKLCH
theme tokens for `:root` (light) and `.dark`. Adding a new KTUI widget means adding its CSS import
here; adding a new Tabler icon means adding it to the safelist.

---

## 12. Worked example — add a new settings toggle end-to-end

Say you want a **"Compact tables"** switch in Settings backed by `GET/PUT /api/settings` (field
`compact_tables`). This mirrors the existing `fwBlockEnabled`/`adguardDashboardEnabled` patterns in
`SettingsView.svelte`.

**1. Declare state** (top of `SettingsView.svelte`'s `<script>`):

```js
let compactTables = $state(false)
let compactSaving = $state(false)
```

**2. Load it** inside `loadSettings()` where the aggregated `/api/settings` response is unpacked
(alongside `vpnOnlyMode = settings.vpn_only_mode || 'off'`, `SettingsView.svelte:189`):

```js
compactTables = settings.compact_tables === true
```

**3. Write a handler** with a save flag (and a confirm if the change is destructive/security-
sensitive — copy the `setApiDirectAccess` shape at `:639-660` for the confirm case; a plain toggle
like this doesn't need one):

```js
async function setCompactTables(enabled) {
  compactSaving = true
  try {
    await apiPut('/api/settings', { compact_tables: enabled })
    compactTables = enabled
    toast(enabled ? 'Compact tables on' : 'Compact tables off', 'success')
  } catch (e) {
    compactTables = !enabled            // revert the switch on failure
    toast(e.message || 'Failed to update', 'error')
  } finally {
    compactSaving = false
  }
}
```

**4. Render it** in a `kt-panel` body. Use `ContentBlock variant="row"` for the label/description
and a `Checkbox variant="switch"` for the control — the exact pattern used for the AdGuard
"Dashboard Access" toggle (`SettingsView.svelte:1145-1151`):

```svelte
<ContentBlock variant="row" title="Compact tables" description="Denser rows across list views">
  <Checkbox
    variant="switch"
    checked={compactTables}
    disabled={compactSaving}
    onchange={(e) => setCompactTables(e.target.checked)}
  />
</ContentBlock>
```

Notes that make it idiomatic here:
- The switch is **not** `bind:checked` to the source of truth; the handler flips it and **reverts on
  error** — every security/network toggle in Settings does this (`setFWBlock`, `setApiDirectAccess`,
  `setWebCloudflareOnly`).
- `toast`/`apiPut` come from `../stores/app.js`; `ContentBlock`/`Checkbox` from `../components/`.
- If instead you wanted a **UI-only** preference (no backend), store it via
  `usePersistentState('compact_tables', false)` (§6) or `localStorage['settings_*']` like
  `itemsPerPage` (`SettingsView.svelte:500-503`) and skip the API call.
- If the toggle needs an "are you sure?", `await confirm({...})` first and `return`/revert on
  `false` (§5.1).

---

## 13. Gotchas / things to know before changing the frontend

- **New icons must be safelisted** in `app.css` `@source inline(...)` or they render blank
  (Tailwind can't see dynamic class names).
- **`confirm()` is async** — always `await`; a bare `if (!confirm(...))` silently proceeds.
- **`toast()` escapes HTML** for you; never route untrusted text around it into `{@html}`.
- **Session is REST-authoritative, WS is live-only** — don't gate auth on the WebSocket.
- **`/api/*` and `/api/ws` bypass the service worker on purpose** — don't add caching for them (it
  breaks the Cloudflare↔VPN IP switch).
- **Popups/menus/tooltips are `position:fixed` and portaled** to escape card `overflow:hidden`;
  follow that when adding overflowing UI.
- **Views are lazy chunks** registered in `Dashboard.svelte`'s `views` map and whitelisted in
  `validViews` (`app.js`) — a new page needs an entry in both (and usually a `navItems` entry).
- **Use `untrack` to stop self-looping effects** — when an effect both reads and writes the same
  `$state` (e.g. push/shift on an array it also reads), wrap the write in `untrack(() => …)` or you
  get `effect_update_depth_exceeded`. See `OverviewView.svelte` / `AnalyticsView.svelte`.

---

## Unverified / flags

- I documented **`SettingsView.svelte`** from its first ~1400 lines (the file is ~2218 lines); the
  state/loader/handler/ContentBlock patterns and the worked example are all verified against that
  range. Sections further down (jail modal markup, backup/import UI beyond `applyImport`) were not
  read line-by-line but follow the same idioms.
- The **manifest naming** (`ui/public/manifest.json_` vs. the `/api/manifest.json` link in
  `index.html`) is real and called out in §10 — verify the backend actually serves
  `/api/manifest.json` in [api-surface.md](api-surface.md)/[backend.md](backend.md).
- nginx **not proxying `/api`** is inferred from `ui/nginx.conf` containing no `/api` location;
  confirm the production Traefik routing in [networking-firewall.md](networking-firewall.md).
</content>
</invoke>

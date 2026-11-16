# HybridSec dashboard - how the frontend works

The dashboard is the browser side of HybridSec. It is a single HTML page served by the
FastAPI backend at `/`, with its stylesheet and script served from `/static/`. It talks to
the backend only through the JSON API under `/api/`. There is no build step and no
framework: plain HTML, CSS and JavaScript, so everything can be read as-is.

## 1. Files

| File | Role |
| --- | --- |
| `dashboard/index.html` | The page skeleton. One `<section class="view">` per screen, a sidebar for navigation, plus two shared components at the end of `<body>`: the toast stack and the confirm `<dialog>`. Containers that the script fills carry an `id` (for example `#runs-table`, `#run-detail`). |
| `dashboard/styles.css` | The dark "security operations" theme. The palette, spacing scale and radii are custom properties on `:root`; one-off tints (hover and translucent shades, notice text, code/log/JSON text colours) are written where they are used. A table of contents at the top of the file lists its sections. |
| `dashboard/app.js` | All behaviour. It is one self-contained function (an IIFE) with twelve numbered sections; see below. |

### Sections of `app.js`

| # | Section | What it owns |
| --- | --- | --- |
| 1 | Utilities | `$`/`$$` DOM shortcuts, `esc()` HTML escaping, date/number formatting, the `api()` fetch wrapper, toasts, button busy states, the confirm dialog, client-side downloads. |
| 2 | Shared renderers and state | Small HTML building blocks used by several screens (status pills, risk bar, KPI tile, chips, empty state) and the single `state` object with cached loaders (`loadTools`, `loadHealth`, `loadRuns`). `loadTools` joins the built-in tools with the custom tools from `/api/tools/custom` (marked `custom: true`); another machine gets 403 there and simply sees the built-in tools. |
| 3 | Router | Reads the URL hash, shows one view section, calls that view's render function, manages the route sequence token and focus. |
| 4 | Overview | Health card, tool cards (built-in tools only, with a link to the Custom tools page), KPI tiles, recent runs. |
| 5 | AI Planner | Plan request form, saved plans, plan detail panel, "Execute this plan", refinement. |
| 6 | New Run | The run form; one row per tool with its checkbox and a drop-down of the tool's profiles (the preset option sets `/api/tools` lists, with a hint explaining the chosen one); optional plan attachment; server limits. The request carries `profiles: {tool: key}` for the ticked tools. Custom tools appear after the built-in tools with their scope and no profile; with a plan attached they are shown as "not in plan" and cannot be ticked. A tool whose program is found but refused on this machine (`blocked`) cannot be ticked for a live run ("program refused") but can still be simulated. |
| 7 | Runs | Table of the runs, newest first (up to 1,000; a note says when older runs are not listed; a run whose stored document cannot be read shows the status *unreadable* and can only be deleted) (a completed run with gaps, because a stage ran out of time, a tool produced nothing or a later stage failed, carries an amber *partial* pill next to its status), delete, select two runs to compare. |
| 8 | Run detail | Header (with the *partial* pill when it applies), six tabs, plus a *Tool output* tab for a run that used custom tools (`runTabs()`: the set never changes while the run is polled; each call's output is escaped text in its own focusable pane; `outputStatus()` says how the call ended: "exit N" only when the program exited by itself, otherwise "stopped at its time limit", "stopped for printing too much", "stopped by the server shutdown", "could not start" or "simulated, not started"; a call whose output the run's limit on custom-tool output cut (`run_limit`) carries a *truncated* pill and a note under its pane, or, when nothing of it was kept, says so in the pane), live polling with incremental updates. The Summary tab opens with a *Partial results* notice listing the notes of the stages with gaps (custom stages are left out, as in the reports). |
| 9 | Compare | Two run selects and the diff panel, with a warning when either run failed, is still executing or has partial results, when a tool ran in only one of the runs (what it found then shows as added or removed although the other run never looked), or when the runs used different profiles for a shared tool. Only a completed run shows a risk score, and the risk delta is shown only when both runs completed (the server sends `risk_delta` null otherwise, and the page says "Not scored"). |
| 10 | Settings | AI provider/keys/models and scanning limits, written to `.env` by the backend. |
| 11 | Custom tools | The `#tools` page: the registration form (name, program with the allowed programs as suggestions, exactly as the server lists them, arguments split on spaces and previewed as one chip per argument, scope, time limit, description), the list of registered tools with their install status (*refused* when the definition no longer passes the rules or the program is found but refused, `blocked`) and a Delete button behind the confirm dialog, after them each stored tool whose definition can no longer be read (`unreadable`) with an *unreadable* pill and a Delete button, and a notice instead of the form when the server answers 403 (another machine). Every rule is checked by the server, whose message is shown in a toast. |
| 12 | Boot | Chooses the first route and starts the app. |

Function names follow a few prefixes. `render<Screen>(..., seq)` is the router's entry point
for one screen: it fetches, checks `isCurrent(seq)` and fills the section. Other `render*`
functions build one region or item and either return the HTML (`renderPortsTab`,
`renderTimeline`) or write it into their own container (`renderRunsTable` fills
`#runs-table`). `*Html` helpers return run-detail fragments, most of them shared by the first
paint and the poller. `paint*` draws the run page or its tab panel from scratch, `patch*`
rewrites only what changed, `update*` refreshes elements already on the page, `load*` fetches
with a cache (`loadPlanInto` fetches a plan, then renders it) and `apply*` copies server data
into existing form controls.

## 2. The request / render cycle

Every screen follows the same five steps.

```
   user clicks a link or the hash changes
                  |
                  v
   route()  ---- reads location.hash, bumps routeSeq, shows the <section>
                  |
                  v
   renderXxx(params, seq)  ---- const data = await api("/api/...")
                  |
                  v
   if (!isCurrent(seq)) return   <-- a newer navigation happened: stop quietly
                  |
                  v
   html = build string, every value wrapped in esc()
   element.innerHTML = html;  bind event handlers
```

Notes:

* `api()` is the only function that calls `fetch`. It sends and receives JSON and, on a
  non-2xx response, throws an `Error` whose message is the server's `detail` text. Views
  show that message as a toast or as an inline "empty state". Nothing is logged to the
  console.
* `esc()` escapes `& < > " '`. Every string that comes from the server or from the user is
  passed through it before it is placed in HTML, so a hostile banner, title or log line
  cannot inject markup. Ids that go into URLs pass through `encode()` instead.

## 3. Routing

The page never reloads. Navigation changes the part of the URL after `#`, the browser fires
`hashchange`, and `route()` decides what to render. A hash has the shape
`#name/param?query`:

| Hash | View | Parameters |
| --- | --- | --- |
| `#overview` | Overview | - |
| `#planner` | AI Planner | `?plan=<id>` opens that plan and scrolls to it |
| `#new-run` | New Run | `?plan_id=<id>&tools=a,b` attaches a plan (the tools list is only a fallback; the plan's workflow is fetched) |
| `#runs` | Runs | - |
| `#run/<id>` | Run detail | the run id is the path segment |
| `#compare` | Compare | `?base=<id>&other=<id>` runs the comparison |
| `#tools` | Custom tools | - |
| `#settings` | Settings | - |
| `#about` | About / Help | - |
| anything else | Not found | - |

The URL is the source of truth: forms that "navigate" (Compare, the planner's Execute
button, saved-plan links) simply set the hash and let `route()` do the work. Because of
that, every screen can be bookmarked and the Back button works.

Two small safety details live in the router: percent-decoding is wrapped in a try/catch so a
malformed hash such as `#compare?base=50%` cannot crash the page, and the redirect from a
bare `#run/` uses `location.replace` so Back does not loop.

## 4. Run-detail polling and why it is safe

While a run is `queued` or `running`, the detail page asks the server for the run every two
seconds. Three things make this robust:

1. **Route sequence token.** `route()` increments `routeSeq` on every navigation. The poller
   remembers the value it was started with and, after each response, checks
   `isCurrent(seq)`. A response that arrives after the user has moved to another page is
   simply ignored. The same check protects every other asynchronous renderer.
2. **AbortController.** The poller owns an `AbortController` and passes its `signal` to
   `api()`. Leaving the page (or deleting the run) calls `stop()`, which aborts the request
   in flight and clears the timer. Only one poller exists at a time; `route()` always stops
   the previous one before rendering anything.
3. **Single self-rescheduling timer.** Instead of `setInterval`, the poller schedules the
   next `setTimeout` only after the previous response was handled, so requests never
   overlap and an old "running" response can never paint over a newer "completed" one. The
   timer handle is a local variable of that poller, so stopping one poller cannot clear
   another's timer.

If a request fails (network hiccup, server restart) the poller does not die silently: the
blue "live updates" notice turns into "Live updates paused" with a Retry button.

### Patch, do not rebuild

Rebuilding the whole page every two seconds would throw away keyboard focus, text
selection and scroll positions. `updateRunDetail()` therefore compares the previous and the
new run object and rewrites only the regions whose data changed: status pills, the
duration, tab counts, the KPI tiles, the stage timeline, and so on. The Log tab appends only
the new lines and follows the tail only if the reader was already at the bottom. The Raw
JSON tab keeps its scroll position.

## 5. Settings: saving only what changed

The Settings page loads a `SettingsView` from `GET /api/settings` and keeps it in
`state.settings` as a baseline. When a Save button is pressed, the script compares each
control with the baseline and sends **only the fields that differ** in a `PUT /api/settings`.
Two consequences:

* A page that was opened an hour ago cannot silently revert an `.env` edit made in the
  meantime, because unchanged fields are not re-sent.
* An empty model or base URL is a real value (it means "use the default"), so it is sent as
  `""` when it differs from the baseline.

After a save, only the saved card is repainted from the server's response, so unsaved edits
in the other card survive. API keys are special: the server never returns their value, only
a `*_key_configured` flag, and the password inputs are never prefilled. A pasted key is sent
once and the input is emptied afterwards.

## 6. Accessibility

* Every screen heading receives keyboard focus after navigation, so screen-reader users
  hear where they are. Empty states use a focusable heading for the same reason.
* Run titles are real links and saved plans are links, so everything that opens a page can
  be reached with the keyboard; clicking the rest of a table row is an extra, not the only
  way.
* The run-detail tabs follow the WAI-ARIA tabs pattern: `role="tablist"`/`tab`/`tabpanel`,
  `aria-selected`, a roving `tabindex` and Arrow/Home/End keys.
* Checkbox groups are `<fieldset>`/`<legend>`; every input has a label; row checkboxes and
  Delete buttons carry names that include the run ("Delete run lab-web-01"). Each profile
  drop-down on the New Run form has a visually hidden label naming its tool ("Nmap profile"),
  is disabled while the tool is unticked, and is followed by a hint that reads out the chosen
  profile's description and flags.
* On the Custom tools page the scope radios are a `<fieldset>` with a legend, the argument preview is a polite
  live region, each Delete button names its tool ("Delete custom tool hdrcheck", or for a stored tool that can
  no longer be read "Delete unreadable custom tool ..."), and after a delete focus moves to the next Delete
  button or to the empty state's heading. Each pane on the Tool output tab is focusable and
  labelled with its tool and target, so its text can be scrolled with the keyboard.
* Toasts are announced (`role="status"`, errors `role="alert"`); the confirm dialog has
  `aria-labelledby`/`aria-describedby`; the mobile menu button exposes `aria-expanded`.
* Colour is never the only signal: pills carry text ("nmap installed"), the gauge and risk
  bars have `aria-label`s, and the active nav item is marked with `aria-current="page"`.

## 7. Responsive rules

* Above 900px the sidebar is a sticky 240px column; at 900px and below it becomes a top bar
  with a menu button, and every multi-column grid collapses to one column using
  `minmax(0, 1fr)` so a wide child can never stretch the page.
* Wide content always scrolls inside its own box, never the page: tables sit in
  `.table-wrap`, the tab strip scrolls horizontally, command lines and log panes have
  their own overflow. The body hides horizontal overflow on phones as a final guard.
* Button rows (`.view-actions`, `.download-row`, `.form-actions`, `.input-group`) wrap;
  long ids and URLs use `overflow-wrap: anywhere`.

## 8. How to explain it in two minutes

"The dashboard is a single page with one `<section>` per screen. The URL hash says which
screen is open; a tiny router shows that section and calls its render function. A render
function fetches JSON from the FastAPI backend through one `api()` helper, builds HTML with
every value escaped, and writes it into the section. Each screen lives in its own numbered
part of `app.js`, and they share one `state` object. The run page polls every two seconds
with a single abortable timer and only patches what changed, and a sequence token makes
sure a slow response from a page you already left can never paint over the one you are
looking at. Settings sends only the fields you changed. Everything is keyboard accessible
and collapses to one column on a phone."

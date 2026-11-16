# HybridSec testing guide

This guide takes a tester through the installation, the automated checks and a manual checklist.
It takes about 45 minutes to work through completely.

## 1. Install and start (5 minutes)

1. Download or clone this repository into a folder without spaces in its path, for example `C:\hybridsec` or `~/hybridsec`.
2. Install Python 3.10 or newer if it is missing (`python --version`).
3. Start the application:
   - Windows PowerShell: `.\run.ps1` (if PowerShell refuses to run scripts, start `run.cmd` instead)
   - Linux, macOS or WSL: `chmod +x run.sh && ./run.sh`
   The first start creates a virtual environment, installs the dependencies and creates `.env` from
   `.env.example`. It then prints the two addresses below.
4. Open http://127.0.0.1:8000/ (the dashboard) and http://127.0.0.1:8000/docs (the API).

The repository does not contain an API key. On a machine without Anthropic or OpenAI credentials in the
environment the AI planner therefore runs in **rules** mode: plans are generated deterministically, and
Refine creates a new revision that repeats the plan with a note that refinement needs an AI provider. If
you have your own Anthropic or OpenAI key you can add it on the Settings page; never commit or share it.

The scanners (Nmap, WhatWeb, Nikto) are optional. Without them, turn on **Simulation mode** in New Run:
the whole pipeline runs on realistic synthetic data and every result is labelled "simulated".
On Ubuntu, Kali or WSL you can install them with `sudo apt install nmap whatweb nikto` and test live
runs against `127.0.0.1` or a lab machine you own.

## 2. Automated checks (2 minutes)

Run both commands from the project folder and paste their last lines into your report:

```bash
.venv/bin/python -m pytest -q            # Windows: .venv\Scripts\python -m pytest -q      -> expect "655 passed"
.venv/bin/python scripts/preflight.py    # Windows: .venv\Scripts\python scripts\preflight.py -> expect "Ready to present"
```

Optional lint check: install `requirements-dev.txt` into the virtual environment and run `.venv/bin/python -m ruff check .`
(Windows: `.venv\Scripts\python -m ruff check .`); expect "All checks passed!".

## 3. Manual test checklist (30 minutes)

Tick each box and note anything unexpected. "Simulation" means the Simulation switch on New Run is on.

### Dashboard basics
- [ ] M-01 Overview shows health "ok", the AI provider, and each tool as installed or not installed with an install hint.
- [ ] M-02 AI Planner: generate a plan for Nmap, WhatWeb and Nikto with the default objective. Expect a plan with three steps in order (nmap, whatweb, nikto), "Authorization required", and provider "rules" (or your model if you added a key).
- [ ] M-03 Click a saved plan in the list: the page URL changes to `#planner?plan=<id>` and the plan opens. The browser Back button returns to the previous view.
- [ ] M-04 If you added a key: type feedback under the plan and click Refine. Expect a new revision (Rev 2) linked to its parent. Without AI credentials: expect a note that refinement needs an AI provider.

### Runs
- [ ] M-05 Click "Execute this plan", enter target `127.0.0.1`, tick the authorization box, keep Simulation on, click Execute run. Expect the run page with live progress, then status "completed", three "simulated" stages and a risk score of 83.
- [ ] M-06 On the run page open every tab: Summary, Ports, Web Technologies, Vulnerabilities, Log, Raw JSON. Download JSON, CSV, HTML and Markdown; open the HTML report and confirm it says the data is simulated.
- [ ] M-07 Start a second simulated run against `127.0.0.1` with only Nmap and WhatWeb (clear the plan first). In Runs, tick both runs and click Compare selected. Expect: no port or technology changes, nine findings removed or added, risk delta of 30, and a note that Nikto ran in only one of the runs.
- [ ] M-07a Tool profiles. In New Run (no plan attached) tick Nmap, WhatWeb and Nikto, choose "Quick port scan" in the drop-down under Nmap and "Injection checks" under Nikto, run against `127.0.0.1` in simulation. Expect the stage timeline to name both profiles next to the tools, an Nmap command line without `-sV`, empty Product and Version columns on the Ports tab, and only the two missing-header findings per web service. Untick a tool: its drop-down greys out. Compare this run with the M-05 run: the comparison warns that the runs used different profiles.
- [ ] M-07b Custom tools. On the Custom tools page add `hdrcheck`: program `curl`, arguments `-sI --max-time 20 {url}`, "Once per web URL", time limit 30. Expect it in the list as installed (or "not installed" with a hint when curl is missing; simulation still works). Try the program `powershell` or `bash` instead: expect a refusal that says it is a shell. Try the arguments `-sI {url} 10.0.0.1:8080` (a fixed address) and `-x 127.0.0.1:3128 {url}` (a proxy): expect a refusal for each. In New Run (no plan attached) tick Nmap, WhatWeb and hdrcheck and run against `127.0.0.1` in simulation: the run page has a Tool output tab with one entry per web URL, each marked "simulated, not started" and saying what would have run, and the risk score is the same as without hdrcheck. Attach a plan in New Run: hdrcheck shows "not in plan" and cannot be ticked. Delete hdrcheck (confirm dialog): the run that used it still shows its output.
- [ ] M-08 In New Run try these targets and confirm each is refused with a clear message: `10.0.0.0/16`, `10.0-255.0.1`, `127.0.0.1;id`, `http://example.com`, `a b`.
- [ ] M-09 Leave the authorization box unticked and click Execute run: the form must not submit.
- [ ] M-10 Change the target after ticking the authorization box: the box must clear itself.
- [ ] M-11 Delete a finished run from the Runs table (confirm dialog). While a run is still executing its Delete button is disabled with the tooltip "Runs can be deleted once they have finished"; simulated runs finish in well under a second, so that state is only visible during a live run (the API's 409 "still executing" answer is covered by the automated tests).

### Settings
- [ ] M-12 Settings shows the active planner and the `.env` path. Set Allowed targets to `127.0.0.1`, save, then try a run against `10.10.10.10`: expect "outside the allowed scope". Clear the list and save again.
- [ ] M-13 Change Max timeout to 600 and Default timeout to 300 and save; New Run should show the new default and limit. Set Default timeout above Max timeout: expect an error.
- [ ] M-14 Click "Test planner": expect a result panel (rules engine, or your model).
- [ ] M-15 If you added a key: the key field is empty after saving and the pill says Configured; Clear returns it to Not set. A key that the server's own environment sets (an exported `ANTHROPIC_API_KEY`) shows "Set in environment", and its Clear button is disabled; clearing a key that is in both places warns that the environment's key stays in use.

### Robustness
- [ ] M-16 Restart recovery. Simulated runs finish too quickly to interrupt by hand, so this is covered by the automated test `test_interrupted_runs_are_failed_on_startup`. With a live run on a Linux machine you are allowed to test, stop the server (Ctrl+C) while the run is executing and start it again: the run must show as failed with "The server shut down before this run finished." (after a crash or a killed process: "The server restarted before this run finished."), with its counts matching its tabs, never as running forever.
- [ ] M-17 Concurrency cap. Start four simulated runs quickly (New Run four times); all of them must finish. Simulated runs complete in well under a second, so the cap itself (a fourth concurrent run is refused with "runs are already executing") is only observable with live runs and is covered by the automated tests.
- [ ] M-18 Narrow the browser window to phone width: the sidebar becomes a top bar, tables scroll inside their boxes, and the run tabs scroll horizontally.
- [ ] M-19 Use only the keyboard: Tab to the run tabs, use the arrow keys to switch tabs, open a run from the Runs table with Enter.
- [ ] M-20 Refresh the page on every view (`#overview`, `#planner`, `#new-run`, `#runs`, `#compare`, `#tools`, `#settings`, `#about`): each view loads directly.

### Live runs (only with the scanners installed, only against systems you own)
- [ ] L-01 Nmap only against `127.0.0.1`: the port scan completes and lists real open ports.
- [ ] L-02 Nmap and WhatWeb: web services found by Nmap are fingerprinted (run a local web server first if none is running).
- [ ] L-03 Full pipeline with the default budget: Nikto findings appear with severities.
- [ ] L-04 Full pipeline with a 60 second budget: Nikto still receives at least its 20 second minimum and scans at least one URL.
- [ ] L-05 Target `nohost.invalid`: the Nmap stage fails with "could not resolve" and the run is marked failed.

## 4. How to report a bug

Open a GitHub issue with:

1. **Title**: one line, for example "Compare page shows the same run twice".
2. **Steps**: numbered, exactly what you clicked or typed, including the target and whether Simulation was on.
3. **Expected** and **actual** result.
4. **Evidence**: a screenshot; the browser console (F12, Console tab) if the page misbehaves; the server log from the terminal; and for a run problem the Raw JSON tab or the JSON download of the run.
5. **Environment**: operating system, Python version, whether the scanners are installed, and the output of `scripts/preflight.py`.

Where things live when you need to look deeper:

| What | Where |
|---|---|
| Server log | The terminal that runs `run.ps1` / `run.sh` |
| Database (plans and runs) | `data/hybridsec.db` (SQLite) |
| Configuration | `.env` in the project folder |
| Code map | `docs/ARCHITECTURE.md` (backend), `docs/DASHBOARD.md` (dashboard) |
| Automated tests | `tests/` (twelve modules, 655 cases: `test_adversarial_qa.py`, `test_api.py`, `test_detailed_api_reports_compare.py`, `test_detailed_config_envfile_storage.py`, `test_detailed_pipeline_planner.py`, `test_detailed_security_parsers.py`, `test_nmap_review_fixes.py`, `test_quality_fixes.py`, `test_review_fixes_round2.py`, `test_review_fixes_round3_backend.py`, `test_review_fixes_round3_dashboard.py`, `test_tool_profiles.py`) |

## 5. Known limitations (not bugs)

- WhatWeb and Nikto are Linux tools; on Windows, live runs need WSL. Simulation mode works everywhere.
- Service versions come from banners and can be wrong or hidden.
- The risk score is a transparent heuristic for comparing runs of the same host, not a calibrated measure.
- The AI model may decline a security prompt; the plan then records the fallback model that answered, or the rules engine answers with a note.
- There is no PDF export and no user login; the server is meant to run on the operator's own machine, bound to 127.0.0.1.

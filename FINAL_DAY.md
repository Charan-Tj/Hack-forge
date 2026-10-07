# FINAL DAY — how to run (read this one file)

## What you receive from the jury
- `source.tar.gz` (the app's source) · an IP:port + SSH login to a Linux box · `restart.sh`

## 0. Get KavachForge onto the box (2 min)
```bash
scp kavachforge-final.zip user@<box-ip>:~/          # from your laptop (zip is in the GitHub release)
ssh user@<box-ip>
unzip -q kavachforge-final.zip -d kavachforge && cd kavachforge
```

## 1. ONE command (starts everything, ~20 min, unattended)
```bash
./run_final.sh ~/source.tar.gz
```
It prints 6 steps: python → analyzer → **downloads & starts our model (phi4:14b)** → self-check → run → deliverables.
Nothing else to type. If the box has < 12 GB RAM it switches to `phi4-mini:3.8b` by itself.

Only if the organizers insist on their endpoint instead of our model:
```bash
./run_final.sh ~/source.tar.gz --endpoint http://192.168.1.103:8000/v1 --model codellama-7b
```

## 2. What comes out (artifacts/final/)
| file | what |
|---|---|
| `report.csv` / `report.md` | **the jury table**: S.No · Vulnerability title · Severity · Vulnerable file / function / location · Steps taken |
| `dashboard.html` | full evidence: severity, CWE classes, types, six-gate workflow per patch (`http://<box-ip>:8777/final/dashboard.html`) |
| `pr/<id>/fix.patch` + `PR.md` | one verified patch per fixed bug |
| `evidence.json`, `manifest.json` | machine-readable proof + integrity hashes |

The report is rewritten at every stage, so it exists even if the window closes mid-run.

## 3. Apply the verified patches to the live app, restart (last 3 min)
```bash
./apply_patches.sh /path/to/app-source /path/to/restart.sh
```
Dry-runs each patch first; skips anything that does not apply cleanly (then apply by hand from `PR.md`).

## 4. Submit
`artifacts/final/report.csv` (and `report.md`). Open `dashboard.html` for the judges if they ask "why do you trust this patch".

---

## Knobs (environment variables, all optional)
`DEADLINE_MIN=20` `MAX_FINDINGS=8` `PRECISION=balanced|strict|recall` `BUDGET=auto` `MODEL=phi4:14b` `NAME=final`
Example: `DEADLINE_MIN=15 PRECISION=strict ./run_final.sh ~/source.tar.gz`

## If something is off
| symptom | do |
|---|---|
| "python 3.8+ not found" | `sudo apt install python3` (or ask the organizers) |
| model download slow / no internet | the run continues with the offline brain (findings + mechanical fixes); or bring the bundle built with `./make_bundle.sh --with-model` |
| "semgrep unavailable" | fine — 36 built-in rules + model review still run |
| run killed | `cat artifacts/final/report.md` — it is already written |
| dashboard not opening | `python3 -m kavachforge serve --port 8777` |

## Building the zip yourself (laptop, needs internet)
```bash
./make_bundle.sh                 # ~250 MB: code + cached rule packs + offline semgrep wheels
./make_bundle.sh --with-model    # + Ollama + phi4:14b files (~11 GB) for a box with NO internet
```

# Ctrl+Alt+Delulu 

**Part 01 — Core Scanner** (`core/scanner.py`)
Wraps the Semgrep OSS CLI. Runs it on any file/folder and returns clean,
structured findings instead of raw Semgrep JSON.

**Part 02 — AI Explanation Layer** (`ai-layer/explain.py`)
Takes those findings and calls an AI API to turn each one into a
beginner-friendly explanation: what's wrong, why it matters, and exactly
how to fix it. Defaults to **NVIDIA NIM (free)** — Anthropic/Claude is
supported as a drop-in alternate.

---

## 1. Test it locally

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Get a free NVIDIA API key (no credit card needed):
1. Go to **https://build.nvidia.com**, sign up / sign in (free).
2. Open any model (e.g. Llama 3.3 70B Instruct), click **Get API Key**.
3. Copy the key — it starts with `nvapi-`.

Set it up locally:
```bash
cp .env.example .env
# then open .env and paste your key into NVIDIA_API_KEY=...
```

Run the full pipeline against the included vulnerable sample file:
```bash
python main.py sample_target/ --config core/rules/basic-security.yaml
```

You should see each finding printed with a plain-language explanation, and
two files get written: `findings.json` (Part 01 output) and
`explanations.json` (Part 02 output).

Once you've confirmed it works, switch to Semgrep's full registry for real
scans (needs normal internet — the sandbox I built this in blocked it, but
your machine won't):
```bash
python main.py path/to/real/codebase
```

### Run each part on its own
```bash
python core/scanner.py path/to/codebase        # Part 01 only
python ai-layer/explain.py findings.json       # Part 02 only
```

### Switching to Claude instead of NVIDIA
Edit `.env`:
```
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=your-key-here
```

---

## 2. Put it on GitHub

From inside this project folder:

```bash
git init
git add .
git commit -m "Part 01: Core Scanner + Part 02: AI Explanation Layer"
```

Then on GitHub.com:
1. Go to your team org (`ctrl-alt-delulu`, or create it: **New → Organization**).
2. Click **New repository** → name it (e.g. `ctrl-alt-delulu`) → **Create**.
3. GitHub will show you commands like these — run them:
   ```bash
   git remote add origin https://github.com/ctrl-alt-delulu/ctrl-alt-delulu.git
   git branch -M main
   git push -u origin main
   ```

If the org doesn't exist yet, you (or Rabia, as lead) can create it free at
**github.com/account/organizations/new**, then invite Rabia and Tasneem as
members so everyone can push.

Since your team's plan is `main` → `dev` → `feature/your-name` branches:
```bash
git checkout -b dev
git push -u origin dev
git checkout -b feature/sumaira
git push -u origin feature/sumaira
```
Do your work on `feature/sumaira`, then open a pull request into `dev` when ready.

**Never commit your real `.env` file** — it's already in `.gitignore`, so
`git add .` won't pick it up. Only `.env.example` (no real key) goes to GitHub.

---

## 3. Codespaces or local VS Code — either works

**GitHub Codespaces (easiest, zero local setup):**
1. Push the repo to GitHub (above).
2. On the repo page, click **Code → Codespaces → Create codespace on main**.
3. It opens a full VS Code in your browser with the repo already there.
4. Open the terminal inside it and just run the setup commands from Step 1
   (`python3 -m venv venv`, `pip install -r requirements.txt`, etc).
5. Paste your NVIDIA key into `.env` inside the Codespace the same way.

Nothing in this project needs anything beyond Python + pip, so Codespaces
works out of the box with no extra config.

**Local VS Code:**
1. Clone the repo: `git clone https://github.com/ctrl-alt-delulu/ctrl-alt-delulu.git`
2. Open the folder in VS Code.
3. Install the Python extension if you don't have it.
4. Open VS Code's terminal (`` Ctrl+` ``) and run the same Step 1 commands.
5. Select the `venv` interpreter when VS Code prompts you (bottom-right, or
   `Ctrl+Shift+P` → "Python: Select Interpreter" → pick `./venv/bin/python`).

Both are fine — Codespaces is faster to start from any machine; local VS Code
is better once you're integrating with Part 03 (the VS Code extension itself).

---

## About `core/rules/basic-security.yaml`

A small local ruleset (hardcoded secrets, string-concat SQL, unsafe
`os.system()`) I used to verify the scanner without registry access. Use
`--config auto` instead for the real hackathon demo — it pulls Semgrep's
full rule registry automatically. Feel free to keep, extend, or delete
this file.

## Tested against

`sample_target/app.py` — a deliberately vulnerable file with a hardcoded
API key, a SQL injection, and a command injection, used to verify both
parts end-to-end. Delete it once you're integrating with real project code.

## Notes for the team

- Part 03 (VS Code Extension) should call `scan()` from `core/scanner.py`
  on save, then pass results into `explain_finding()` for inline messages.
- Part 06 (Summary Card) can reuse the `Finding`/`Explanation` dataclasses —
  they already have `.to_dict()` for easy JSON serialization.
- Update the Task Tracker: "Decide on AI API" → **NVIDIA NIM (free)**.

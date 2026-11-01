# CyberTrace — Teammate & Developer Quickstart Guide

Welcome to **CyberTrace**! This guide is designed to get you up and running locally in under 5 minutes so you can test, develop, and collaborate seamlessly.

---

## 1. Branch Strategy & Repository Clone

CyberTrace maintains `main` as the stable baseline, while active product development happens on dedicated feature branches:

```bash
# 1. Clone the repository
git clone https://github.com/PrathviSahu/CyberTrace.git
cd CyberTrace

# 2. Checkout the latest active feature branch (contains Phase 4 & Phase 5)
git checkout feature/phase-4-soc-frontend

# 3. Confirm your branch
git status --short --branch
# Expected: ## feature/phase-4-soc-frontend...origin/feature/phase-4-soc-frontend
```

---

## 2. Environment Prerequisites

Ensure you have the following installed on your machine:
- **Python**: `3.11` or `3.12` (`python3 --version`)
- **Node.js**: `18.x` or higher (`node --version`)
- **npm**: `9.x` or higher (`npm --version`)
- **Git**: (`git --version`)

---

## 3. Backend Setup & Startup

The backend is built with **FastAPI**, **SQLAlchemy 2.x (async)**, and **Alembic**.

```bash
# 1. Create and activate a Python virtual environment
python3 -m venv backend/.venv
source backend/.venv/bin/activate

# 2. Install dependencies
pip install -r backend/requirements.txt

# 3. Configure environment variables
cp backend/.env.example backend/.env

# Optional: Add your BharatCode API key to backend/.env if testing live AI model
# BHARATCODE_API_KEY="your-key-here"
# Note: If no key is provided, CyberTrace automatically uses its Deterministic Fallback Engine!

# 4. Run database migrations to initialize SQLite
cd backend
alembic upgrade head
cd ..

# 5. Run the automated test suite (94 tests)
PYTHONPATH=backend pytest backend/tests -v

# 6. Start the FastAPI development server
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

The API documentation is interactively accessible at:
- **Swagger UI**: `http://localhost:8000/docs`
- **Health Check**: `http://localhost:8000/api/v1/health`

---

## 4. Frontend Setup & Startup

The frontend is a dark SOC interface built with **React 18**, **TypeScript**, **Tailwind CSS**, and **@xyflow/react**.

In a new terminal tab:

```bash
# 1. Navigate to the frontend directory
cd frontend

# 2. Install npm dependencies
npm install

# 3. Verify TypeScript and production build
npm run build

# 4. Launch the Vite development server
npm run dev
```

Open your browser to: **`http://localhost:5173`**

The Vite development server is pre-configured with an automatic reverse proxy: any requests to `/api/*` are transparently proxied to `http://localhost:8000/api/*`.

---

## 5. End-to-End Workflow Walkthrough

### Step A: Ingest Security Logs
1. Click the **"Ingest Log"** button in the top navigation bar or press `⌘K` $\to$ select "Ingest Security Log".
2. Drag and drop or browse to select a sample log from `backend/app/data/sample_logs/`:
   - `multi_stage_attack.json` (Triggers brute-force, logon success, privilege escalation, and exfiltration)
   - `benign_activity.json` (Clean administrative baseline)
3. Click **"Ingest & Correlate"**.
4. The system parses raw logs into Common Event Schema (CES), evaluates detection rules, correlates entities, and persists the incident.

### Step B: Investigate Incident in the 3-Panel Workspace
1. In the Command Centre incident table, click **"Investigate"** on `INC-001` (or navigate to `http://localhost:5173/incidents/INC-001`).
2. **Left Panel**: Inspect the chronological event sequence and extracted entities.
3. **Center Panel**: Interact with the Adversary Attack Graph powered by `@xyflow/react`. Click on any node or edge to inspect relationships.
4. **Right Panel**: Click **"Run AI Investigation"** to trigger BharatCode Qwen 27B (or Deterministic Fallback).
5. Click any **`[evt_...]`** evidence citation to open the slide-over **Evidence Drawer** showing the exact normalized log entry and ingestion SHA-256 hash.
6. Under **Recommended Actions**, test the **Human-in-the-Loop** approval workflow by clicking **"Approve Action"**.

### Step C: Test ThreatLab Benchmark Replay
1. Click **"ThreatLab Benchmark"** in the sidebar (or navigate to `http://localhost:5173/threatlab`).
2. Select any scenario (`SCN-001` to `SCN-004`).
3. Click **"Replay Scenario"** to execute the isolated in-memory benchmark harness.
4. Observe the calculated confusion matrix ($TP, FP, FN, TN$), precision ($100\%$), recall ($100\%$), and $F_1$-score ($1.00$).

---

## 6. How to Report Bugs & Submit Code

1. **Before pushing**:
   - Run backend tests: `PYTHONPATH=backend pytest backend/tests` (Ensure 74/74 pass).
   - Run frontend build: `cd frontend && npm run build` (Ensure 0 TypeScript errors).
   - Check git whitespace: `git diff --check`.
2. **Branch naming**:
   - `feat/feature-name` for new capabilities.
   - `fix/issue-description` for bug fixes.
3. **Submitting changes**:
   - Push to your branch and open a Pull Request targeting `feature/phase-4-soc-frontend` (or `main` when instructed).
   - Use the Pull Request Template provided in `.github/PULL_REQUEST_TEMPLATE.md`.


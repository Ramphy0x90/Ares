# ARES

**Automated Reconnaissance & Exploitation System**

A modern, modular penetration testing platform with a FastAPI backend, Angular frontend, and a plugin-based scanner architecture. Ares specializes in traditional infrastructure and web vulnerability scanning **plus LLM/AI security testing** — a key differentiator for assessing modern AI-powered applications.

> **Disclaimer:** Ares is intended for authorized security testing, penetration testing engagements, CTF competitions, and educational purposes only. Always obtain proper authorization before scanning any target.

---

## Key Features

- **Plugin-based scanner architecture** — modular scanners that can be composed per engagement
- **Network scanning** — port scanning, service fingerprinting, banner grabbing, default credential detection
- **Web vulnerability scanning** — OWASP Top 10 coverage: SQLi, XSS, directory traversal, CSRF, header analysis, CORS misconfiguration
- **LLM/AI security testing** — prompt injection, jailbreak resistance, data exfiltration, system prompt leakage, excessive agency detection (OWASP LLM Top 10)
- **API security scanning** — Swagger/OpenAPI discovery, BOLA/IDOR, JWT attacks, rate limiting, parameter pollution
- **SSL/TLS analysis** — certificate validation, cipher suite checks, protocol version auditing
- **Credential testing** — multi-protocol brute force (SSH, HTTP, FTP), default credential databases
- **Real-time scan updates** via WebSocket
- **Report generation** — HTML, PDF, and JSON export with executive summaries, severity charts, and remediation checklists
- **Modern dashboard** — Angular Material UI with severity distribution charts and scan activity tracking

---

## Architecture

```
ares/
├── backend/          # FastAPI + SQLAlchemy (Python 3.12)
│   ├── app/
│   │   ├── api/v1/   # REST endpoints
│   │   ├── models/   # SQLAlchemy ORM models
│   │   ├── schemas/  # Pydantic request/response schemas
│   │   ├── scanners/ # Plugin scanner modules
│   │   ├── services/ # Scan orchestration, report generation
│   │   └── templates/# Jinja2 report templates
│   └── data/         # SQLite DB + generated reports
├── frontend/         # Angular 19 + Angular Material
│   └── src/app/
│       ├── pages/    # Dashboard, Targets, Scans, Vulns, Reports
│       ├── core/     # Services, models, interceptors
│       └── shared/   # Reusable components and pipes
└── docker-compose.yml
```

### Scanner Modules

| Module | Description |
|--------|-------------|
| `network_scanner` | Port scanning, service detection, banner grabbing |
| `web_vuln_scanner` | SQL injection, XSS, directory traversal, header analysis |
| `llm_security_scanner` | Prompt injection, jailbreak, data exfil, system prompt leakage |
| `api_security_scanner` | Swagger discovery, CORS, JWT attacks, rate limiting |
| `ssl_analyzer` | TLS version checks, cipher analysis, certificate validation |
| `credential_tester` | Default credentials, brute force, password policy analysis |

---

## Quick Start

### Docker (Recommended)

```bash
cp .env.example .env
docker compose up --build
```

- **Frontend:** http://localhost:4200
- **Backend API:** http://localhost:8000
- **API Docs:** http://localhost:8000/docs

### Manual Setup

**Backend:**
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend
npm install
ng serve --port 4200
```

Or use the convenience script from the project root:
```bash
python run.py
```

---

## API Overview

All endpoints under `/api/v1`:

| Resource | Endpoints |
|----------|-----------|
| **Targets** | `GET/POST /targets`, `GET/PUT/DELETE /targets/{id}` |
| **Scans** | `GET/POST /scans`, `GET /scans/{id}`, `POST /scans/{id}/stop`, `GET /scans/{id}/vulnerabilities` |
| **Vulnerabilities** | `GET /vulnerabilities`, `GET/PATCH /vulnerabilities/{id}` |
| **Reports** | `GET/POST /reports`, `GET /reports/{id}`, `GET /reports/{id}/download` |
| **Scan Configs** | `GET/POST /scan-configs`, `GET/PUT/DELETE /scan-configs/{id}` |
| **Dashboard** | `GET /dashboard/stats`, `GET /dashboard/recent-findings` |
| **WebSocket** | `ws://localhost:8000/api/v1/ws/{scan_id}` |

Full interactive docs available at `http://localhost:8000/docs` (Swagger UI).

---

## Configuration

Environment variables (see `.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite+aiosqlite:///./data/ares.db` | Database connection string |
| `MAX_CONCURRENT_SCANS` | `5` | Maximum parallel scan tasks |
| `SCAN_TIMEOUT` | `3600` | Scan timeout in seconds |

---

## License

[MIT](LICENSE)

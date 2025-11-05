# PoC: Frontend + Backend (Iceworm integration)

**Purpose:**  
This repository is a local Proof-of-Concept showing a React (Vite) frontend talking to a Go backend, and how to run and test them inside the Iceworm CEF browser for security inspection or functional testing.

**Scope:**  
This Notes covers only:
- how to run the frontend and backend locally, and
- how to integrate/run them inside Iceworm for testing.

---

## Project layout (example)
repo-root/
├─ frontend/ # Vite + React app (http://localhost:5173)
├─ backend/ # Go server (http://localhost:9000)
├─ iceworm-launcher/ (optional) # config used to launch iceworm
├─ package.json # root scripts (optional)
└─ DEV_NOTES.md

---

## Prerequisites
- Node.js (v16+ recommended)
- npm (comes with Node)
- Go (1.18+ recommended)
- Local Iceworm build (see DEVELOPER_NOTES.md)
- (Optional, for MITM inspection) Burp Suite / mitmproxy and Proxifier (Windows) — only for authorized tests

---

## Run the backend (Go)
From the project root:
```powershell
cd backend
go run main.go
Or build and run:

powershell
cd backend
go build -o bin/backend
.\bin\backend
Default: listens on http://localhost:9000 (adjust main.go if different).

cd frontend
npm install        # first time only
npm run dev
Vite default local URL: http://localhost:5173

Combined (one command)
If you have root-level scripts configured (optional), from repo root:

npm install          # installs root dev helpers (if used)
npm run dev          # runs frontend + backend in parallel (if configured)
(Alternatively run both terminals: one for backend and one for frontend.)

What this PoC is for
Validate frontend ⇄ backend communication locally.

Test how the frontend appears and behaves inside Iceworm (CEF) — useful to reproduce exam-client behaviour.

Capture and inspect HTTP(S) or WebSocket traffic originating from Iceworm (for authorized security analysis or debugging).

Integrate & run inside Iceworm (quick)
Build / have Iceworm binary ready on your machine (place it outside the repo). Example:

C:\dev\iceworm\iceworm.exe
C:\dev\iceworm\libcef.dll
C:\dev\iceworm\icudtl.dat
C:\dev\iceworm\locales...
C:\dev\iceworm\Resources...
C:\dev\iceworm\iceworm.exe

Create or edit iceworm-launcher/test_config.json (or create a minimal config) and set startUrls to your frontend and allow the backend:

Example test_config.json (minimal required parts):

json
{
  "startUrls": ["http://localhost:5173"],
  "allowedUrls": ["http://localhost:5173", "http://localhost:9000"],
  "cefArgs": {
    "remote-debugging-port": "9222"
  },
  "kioskMode": false,
  "noToolbar": false
}
Launch Iceworm pointing to the config:

powershell
& "C:\dev\iceworm\iceworm.exe" "C:\full\path\to\repo\iceworm-launcher\test_config.json"
(Optional, for debugging) Open Chrome and go to:

arduino
http://localhost:9222/
Click the target to open DevTools attached to the Iceworm CEF process.

## Quick start (Windows)
1. Install prerequisites:
   - Node.js (recommended v18+)
   - Go (1.21+ recommended)
   - Burp Suite (or mitmproxy)
   - Proxifier (or equivalent to force loopback to proxy)

2. Install dependencies:
   ```powershell
   # frontend deps
   cd frontend
   npm install

   # root dev helpers (e.g., npm-run-all)
   cd ..
   npm install
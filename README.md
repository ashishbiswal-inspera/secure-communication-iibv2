# React-Go-Iceworm Monorepo

A secure monorepo project using Turborepo to manage a React + TypeScript frontend and a Go backend, featuring AES-256-GCM encryption and proxy bypass for hardened local communication.

## Project Structure

```
.
├── frontend/          # React + Vite + TypeScript application
├── backend/           # Go API server with embedded frontend
├── Inspera Browser/   # Iceworm browser executable
├── package.json       # Root workspace configuration
├── turbo.json         # Turborepo configuration
└── SECURITY_IMPLEMENTATION.md  # Detailed security documentation
```

## Prerequisites

Before you begin, ensure you have the following installed:

- **Node.js** (v18 or higher) - [Download](https://nodejs.org/)
- **npm** (comes with Node.js)
- **Go** (v1.20 or higher) - [Download](https://golang.org/dl/)

## Getting Started

### 1. Install Dependencies

From the root directory, install all workspace dependencies:

```powershell
npm install
```

This will install:
- Turborepo and root-level dependencies
- Frontend dependencies (React, Vite, TypeScript, etc.)
- Backend package.json (minimal, just for turbo integration)

### 2. Start Development Servers

Run both frontend and backend simultaneously using Turborepo:

```powershell
npm run dev
```

This command:
1. Builds the frontend (Vite build)
2. Starts the **Go backend** with embedded frontend on a **dynamic port** (OS-assigned)
3. **Automatically launches Iceworm browser** with the application
4. Backend monitors Iceworm process and exits when browser is closed

### 3. Access the Application

- **No manual navigation needed** - Iceworm browser opens automatically
- Application runs on dynamic port (e.g., `http://localhost:50123`)
- Port is auto-assigned by the OS to avoid conflicts
- Iceworm browser configured with `--no-proxy-server` flag for security

## Available Scripts

### Root Level

- `npm run dev` - Start both frontend and backend in parallel
- `npm run dev:frontend` - Start only the frontend
- `npm run dev:backend` - Start only the backend
- `npm run install:all` - Install/update all workspace dependencies

### Frontend (`cd frontend`)

- `npm run dev` - Start Vite dev server
- `npm run build` - Build for production
- `npm run preview` - Preview production build
- `npm run lint` - Run ESLint

## API Endpoints

### Regular Endpoints (Unencrypted)

- **GET** `/api/get` - Returns a JSON response with status information
  ```json
  {
    "success": true,
    "message": "GET request successful",
    "data": { ... }
  }
  ```

- **POST** `/api/post` - Accepts JSON data and returns a response
  ```json
  // Request body
  {
    "name": "John Doe",
    "email": "john@example.com"
  }
  
  // Response
  {
    "success": true,
    "message": "Data received successfully",
    "data": { ... }
  }
  ```

## Technology Stack

### Frontend
- React 19
- TypeScript
- Vite
- Web Crypto API (for AES-256-GCM encryption)
- Embedded in Go binary using `embed` package

### Backend
- Go (with `embed` for static files)
- Standard library HTTP server
- AES-256-GCM encryption (`crypto/aes`, `crypto/cipher`)
- Dynamic port allocation
- Process lifecycle management

### Browser
- Iceworm (Chromium/CEF-based)
- Configured with `--no-proxy-server` flag
- Automatic launch and cleanup

## Security Features

🔒 **Hardened Local Communication** - Defense-in-depth against MITM attacks

1. **Proxy Bypass** - `--no-proxy-server` flag prevents Burp Suite/proxy interception
2. **Application-Layer Encryption** - AES-256-GCM encrypts all sensitive data
3. **Replay Protection** - Timestamp (5s window) + UUID nonce validation
4. **In-Memory Keys** - Encryption keys never written to disk
## Troubleshooting

### Port Already in Use

**Not an issue!** The backend uses dynamic port allocation - the OS automatically assigns a free port. If you still have port conflicts, the OS will simply assign a different port.

### Iceworm Won't Launch

Make sure the Iceworm executable exists:
```powershell
# Check if Iceworm browser exists
Test-Path ".\Inspera Browser\Iceworm.exe"
```

If missing, you need the Iceworm browser binary in the `Inspera Browser` directory.

### Backend Won't Start

Check for Go compilation errors:
```powershell
### Go Not Found

Make sure Go is installed and in your PATH:
```powershell
go version
```

### npm Install Issues

Try clearing the cache and reinstalling:
```powershell
npm cache clean --force
rm -r node_modules
npm install
```

### Encryption Errors in Browser Console

If you see encryption initialization errors:
1. Make sure backend is running (`npm run dev`)
2. Check browser console for `/api/security/key` 200 response
3. Verify encryption status shows "AES-256-GCM Ready" in UI

### Config Files Not Cleaning Up

Temporary config files (`iceworm-config-*.json`) should auto-delete. If they persist:
```powershell
# Manually clean old config files
cd backend
Remove-Item iceworm-config-*.json
```

## Quick Test

After starting the app, test the security features:

1. **Test Regular POST**: Click "POST Request" button
2. **Test Encrypted POST**: Click "Secure POST (Encrypted)" button
3. **Check Network Tab**: Open DevTools → Network
   - Regular POST shows plain JSON
   - Secure POST shows encrypted `{ciphertext, nonce}`
4. **Test Proxy Bypass**: 
   - Start Burp Suite as system proxy
   - App still works (no traffic in Burp Suite)

## License

MITSON API

### Monorepo
- Turborepo
- npm workspaces

## Development Notes

- **CORS**: The backend is configured to allow requests from `http://localhost:5173`
- **Hot Reload**: Both frontend (Vite HMR) and backend (manual restart) support development workflows
- **Ports**: 
  - Frontend: 5173
  - Backend: 9000

## Troubleshooting

### Port Already in Use

If you see an error that a port is already in use:

**Frontend (5173):**
```powershell
# Find and kill the process
netstat -ano | findstr :5173
taskkill /PID <PID> /F
```

**Backend (9000):**
```powershell
# Find and kill the process
netstat -ano | findstr :9000
taskkill /PID <PID> /F
```

### Go Not Found

Make sure Go is installed and in your PATH:
```powershell
go version
```

### npm Install Issues

Try clearing the cache and reinstalling:
```powershell
npm cache clean --force
rm -r node_modules
npm install
```

## License

MIT

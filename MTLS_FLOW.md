# mTLS Communication Flow: Ephemeral Certificates

## Overview

Complete flow from Iceworm startup to secure request/response using in-memory certificates with mTLS.

---

## ⚠️ Security Warning: Command-Line Argument Exposure

### Critical Vulnerability

**This approach (passing certs as command-line arguments) has a serious security flaw:**

#### The Problem

When you pass certificates/keys as command-line arguments, they become visible to:

1. **Process List Tools:**
   - Windows: Task Manager, PowerShell `Get-Process`
   - Linux/macOS: `ps aux`, `top`, `htop`
   - Any monitoring software

2. **Example Exposure:**

```powershell
# Windows PowerShell
PS> Get-Process iceworm | Select-Object -ExpandProperty CommandLine

# Output exposes private key:
iceworm.exe --client-key-base64 LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1JR2tBZ0VCQkRBcTNoPXM...
```

```bash
# Linux/macOS
$ ps aux | grep iceworm

# Output exposes private key:
iceworm --client-key-base64 LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1JR2tBZ0VCQkRBcTNoPXM...
```

#### Who Can See This?

| User Type | Can View Process Args? | Tools |
|-----------|----------------------|-------|
| **Regular user (same account)** | ✅ YES | Task Manager, ps, htop |
| **Other users on system** | ✅ YES (usually) | ps aux, Process Explorer |
| **Administrator** | ✅ YES | All process monitoring tools |
| **Malware/Security software** | ✅ YES | System monitoring, EDR tools |
| **Audit logs** | ✅ YES | Command history, syslog |

#### Risk Assessment

| Risk | Severity | Explanation |
|------|----------|-------------|
| **Process list exposure** | 🔴 **CRITICAL** | Private keys visible in plain text |
| **Shell history** | 🟡 MEDIUM | Commands logged in shell history files |
| **Monitoring software** | 🟡 MEDIUM | EDR/antivirus may log process launches |
| **Memory dumps** | 🟠 LOW | Args visible in crash dumps |
| **Screenshot tools** | 🟠 LOW | Task Manager screenshots expose keys |

### 🛡️ Secure Alternative: Named Pipes

**See `MTLS_NAMED_PIPE_APPROACH.md` for production-ready secure implementation.**

Key benefits:
- ✅ No command-line exposure (only pipe name visible)
- ✅ No disk storage (all in RAM)
- ✅ OS-enforced permissions
- ✅ Admin cannot recover

**Example of secure approach:**
```powershell
# What's visible in process list (SAFE):
iceworm.exe --pipe-name iceworm-a3f7d8c2-4b1e-9f0d

# No certificates or keys exposed!
```

---

---

## Phase 1: Application Startup

```
┌─────────────────────────────────────────────────────────────┐
│ Step 1: Go Server Generates Certs (In-Memory Only)         │
├─────────────────────────────────────────────────────────────┤
│ Go Server (main.go):                                        │
│   1. Generate CA cert (in RAM)                              │
│   2. Generate Server cert signed by CA (in RAM)             │
│   3. Generate Client cert signed by CA (in RAM)             │
│   4. Configure TLS server with Server cert                  │
│   5. Export Client cert + key as base64 strings             │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ Step 2: Launch Iceworm with Client Cert                    │
├─────────────────────────────────────────────────────────────┤
│ Go Server executes:                                         │
│   exec.Command("iceworm.exe",                               │
│       "--client-cert-base64", clientCertB64,                │
│       "--client-key-base64", clientKeyB64,                  │
│       "--ca-cert-base64", caCertB64,                        │
│       "--server-url", "https://127.0.0.1:9000")             │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ Step 3: Iceworm (C++) Configures CEF                       │
├─────────────────────────────────────────────────────────────┤
│ Iceworm C++ main():                                         │
│   1. Decode base64 certs from command-line args             │
│   2. Write certs to TEMP location (or keep in memory)       │
│   3. Configure CEF to use client cert for 127.0.0.1:9000    │
│   4. Load React app (https://127.0.0.1:9000)                │
└─────────────────────────────────────────────────────────────┘
```

---

## Phase 2: TLS Handshake (Automatic)

```
┌─────────────────────────────────────────────────────────────┐
│ Browser Loads: https://127.0.0.1:9000                      │
├─────────────────────────────────────────────────────────────┤
│ CEF/Chromium Network Stack (C++ Level):                    │
│                                                             │
│   1. TLS ClientHello → Server                               │
│   2. Server sends Server Certificate                        │
│   3. Server requests Client Certificate                     │
│   4. CEF sends Client Certificate (auto - configured)       │
│   5. Server verifies client cert with CA                    │
│   6. TLS handshake complete ✓                               │
│                                                             │
│   → Encrypted channel established                           │
│   → React app loads over HTTPS                              │
└─────────────────────────────────────────────────────────────┘
```

**Key Point:** React/JavaScript **NEVER sees the certificates**. TLS happens at the network layer (CEF C++ code), transparent to JavaScript.

---

## Phase 3: React API Requests

```
┌─────────────────────────────────────────────────────────────┐
│ React Frontend Makes Request                               │
├─────────────────────────────────────────────────────────────┤
│ // frontend/src/lib/secureClient.ts                        │
│                                                             │
│ export async function apiGet(endpoint: string) {           │
│   const response = await fetch(                            │
│     `https://127.0.0.1:9000${endpoint}`,                   │
│     {                                                       │
│       method: 'GET',                                        │
│       credentials: 'include', // Important for TLS client  │
│       headers: {                                            │
│         'Content-Type': 'application/json'                  │
│       }                                                     │
│     }                                                       │
│   );                                                        │
│   return response.json();                                   │
│ }                                                           │
│                                                             │
│ // Usage in component:                                     │
│ const data = await apiGet('/api/get');                     │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ CEF Network Stack (Automatic)                              │
├─────────────────────────────────────────────────────────────┤
│   1. Intercepts fetch() call                                │
│   2. Sees destination: https://127.0.0.1:9000               │
│   3. Uses existing TLS session with client cert            │
│   4. Sends encrypted request over mTLS                      │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ Go Server Receives Request                                 │
├─────────────────────────────────────────────────────────────┤
│ func handleGet(w http.ResponseWriter, r *http.Request) {   │
│   // TLS already verified client cert at this point!       │
│   // r.TLS.PeerCertificates contains client cert           │
│                                                             │
│   // Your API logic                                         │
│   data := map[string]interface{}{                          │
│     "message": "Hello from secure server",                  │
│     "timestamp": time.Now(),                                │
│   }                                                         │
│                                                             │
│   json.NewEncoder(w).Encode(data)                          │
│ }                                                           │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ Response Sent Back (Encrypted)                             │
├─────────────────────────────────────────────────────────────┤
│   1. Go encodes JSON response                               │
│   2. Sends over encrypted TLS channel                       │
│   3. CEF receives and decrypts                              │
│   4. fetch() Promise resolves with data                     │
│   5. React component receives plain JSON                    │
└─────────────────────────────────────────────────────────────┘
```

---

## Visual Flow Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                    APPLICATION START                          │
└──────────────────────────────────────────────────────────────┘
                          │
                          ▼
         ┌────────────────────────────────┐
         │   Go Server (Backend)          │
         │                                │
         │  1. Generate certs in RAM:     │
         │     - CA cert                  │
         │     - Server cert + key        │
         │     - Client cert + key        │
         │                                │
         │  2. Start HTTPS server:        │
         │     https://127.0.0.1:9000     │
         │     (with mTLS enabled)        │
         │                                │
         │  3. Launch Iceworm:            │
         │     Pass client cert via args  │
         └────────┬───────────────────────┘
                  │ spawn process
                  │ --client-cert-base64=...
                  │ --client-key-base64=...
                  ▼
         ┌────────────────────────────────┐
         │   Iceworm (C++ CEF Browser)    │
         │                                │
         │  1. Decode certs from args     │
         │  2. Configure CEF:             │
         │     - Trust CA cert            │
         │     - Use client cert for      │
         │       127.0.0.1:9000           │
         │  3. Navigate to:               │
         │     https://127.0.0.1:9000     │
         └────────┬───────────────────────┘
                  │
                  │ TLS Handshake (automatic)
                  │ ┌─────────────────────┐
                  └─┤ Client sends cert   │
                    │ Server verifies     │
                    │ Encrypted channel   │
                    └─────────┬───────────┘
                              │
                              ▼
         ┌────────────────────────────────┐
         │   React App Loaded             │
         │   (inside CEF browser)         │
         │                                │
         │   Component.tsx:               │
         │   ┌──────────────────────────┐ │
         │   │ useEffect(() => {        │ │
         │   │   fetch('/api/get')      │ │
         │   │     .then(r => r.json()) │ │
         │   │     .then(setData)       │ │
         │   │ }, [])                   │ │
         │   └──────────────────────────┘ │
         └────────┬───────────────────────┘
                  │
                  │ fetch() call
                  ▼
         ┌────────────────────────────────┐
         │   CEF Network Layer (C++)      │
         │   (Transparent to React)       │
         │                                │
         │   - Intercepts fetch()         │
         │   - Uses TLS session           │
         │   - Sends client cert auto     │
         │   - Encrypts request           │
         └────────┬───────────────────────┘
                  │
                  │ HTTPS GET /api/get
                  │ (mTLS encrypted)
                  ▼
         ┌────────────────────────────────┐
         │   Go Server Handler            │
         │                                │
         │   handleGet(w, r) {            │
         │     // Client cert already     │
         │     // verified by TLS layer   │
         │                                │
         │     json.Encode(response)      │
         │   }                            │
         └────────┬───────────────────────┘
                  │
                  │ JSON Response
                  │ (encrypted)
                  ▼
         ┌────────────────────────────────┐
         │   CEF Receives & Decrypts      │
         └────────┬───────────────────────┘
                  │
                  │ Plain JSON
                  ▼
         ┌────────────────────────────────┐
         │   React Component              │
         │   setData(jsonResponse)        │
         └────────────────────────────────┘
```

---

## Key Takeaways

### What React Sees

```javascript
// React just does normal fetch - no crypto code!
const data = await fetch('https://127.0.0.1:9000/api/get').then(r => r.json());
```

### What React DOESN'T See

- ❌ TLS handshake
- ❌ Client certificate
- ❌ Private keys
- ❌ Encryption/decryption

### Where Security Happens

1. **TLS Layer** (CEF C++ code) - Handles certificates automatically
2. **Go Server** (TLS config) - Verifies client cert before request reaches your handler

---

## Implementation Components

### 1. Go Server (Backend)

- In-memory cert generation
- mTLS configuration
- Iceworm launcher with cert args

### 2. Iceworm Integration (C++)

- Command-line arg parsing
- CEF configuration with client cert
- CA cert trust setup

### 3. React Client (Frontend)

- Simple fetch wrapper
- No changes needed from standard HTTP requests
- CEF handles everything automatically

---

## Security Benefits

| Attack Vector | Mitigation |
|--------------|------------|
| MITM on localhost | ✅ mTLS encryption |
| Rogue apps calling API | ✅ Client cert required |
| Certificate theft | ✅ Certs never touch disk |
| Memory inspection | ✅ Certs in RAM only (cleared on exit) |
| JavaScript access to keys | ✅ Keys stay in native code (C++/Go) |
| Replay attacks | ✅ TLS prevents (with timestamps in Phase 2) |

---

## Notes

- **No disk storage**: All certificates generated and used in-memory
- **Per-session security**: New certs generated on each app launch
- **Transparent to React**: Frontend code remains simple, security handled at native layer
- **Cross-platform**: Works on Windows, macOS, Linux with same approach

---

## ⚠️ Important Security Consideration

**This document describes the conceptual flow of mTLS with ephemeral certificates. However, the method shown (passing certs as command-line arguments) has critical security vulnerabilities as described in the warning section above.**

**For production use, implement the Named Pipe approach documented in `MTLS_NAMED_PIPE_APPROACH.md` instead.**

### Why Named Pipes Are Required

The command-line argument approach exposes private keys to:
- Any user running `ps aux` or Task Manager
- System monitoring tools
- Audit logs and shell history
- Security software and EDR solutions

The Named Pipe approach ensures:
- Private keys never appear in process arguments
- No disk writes (everything stays in RAM)
- OS-level access control (owner-only permissions)
- Immediate cleanup (pipe closed after <30ms)

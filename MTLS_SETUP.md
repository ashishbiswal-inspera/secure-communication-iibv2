# mTLS Security Implementation - Phase 1

## Overview

This project now implements **Mutual TLS (mTLS)** for secure communication between the Iceworm browser (frontend) and the Go backend server. All communication is encrypted with TLS 1.3 and both client and server authenticate each other using certificates.

## What Was Implemented

### 1. Certificate Management System (`backend/certs/manager.go`)

A complete certificate management package that:
- **Generates a self-signed CA** (Certificate Authority)
- **Creates server certificates** for the HTTPS server
- **Creates client certificates** for the Iceworm browser
- **Persists certificates to disk** in the `certs/` directory
- **Loads existing certificates** on subsequent runs
- Uses **ECDSA P-256** for efficient, secure cryptography

### 2. HTTPS Server with Client Certificate Verification (`backend/main.go`)

The Go server now:
- **Requires client certificates** for all connections (`RequireAndVerifyClientCert`)
- **Uses TLS 1.3** for maximum security
- **Binds to 127.0.0.1 only** (localhost-only access)
- **Validates client certificates** against the CA
- Serves on **https://127.0.0.1:9000**

### 3. Secure Frontend Client (`frontend/src/lib/secureClient.ts`)

A TypeScript API client that:
- Sends requests over HTTPS with `credentials: 'include'`
- Handles timeouts and error cases
- Provides type-safe `get()` and `post()` methods
- Ready for Phase 2 HMAC signing

### 4. Iceworm Browser Configuration (`iiw_config.json`)

Updated to:
- Use **https://127.0.0.1:9000** as start URL
- Configure client certificate paths
- Ignore self-signed certificate warnings (safe for localhost)

## Security Benefits

| Threat | Mitigation |
|--------|-----------|
| **MITM attacks on localhost** | ✅ All traffic encrypted with TLS 1.3 |
| **Rogue apps calling your API** | ✅ Client certificate required (only Iceworm has it) |
| **Network sniffing** | ✅ End-to-end encryption |
| **Certificate spoofing** | ✅ Mutual verification (both sides authenticate) |
| **Replay attacks** | ⚠️ Phase 2 will add HMAC + timestamp |

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Go Server Startup                                        │
│    - Check if certs exist in certs/ directory              │
│    - If not, generate CA + server cert + client cert       │
│    - If yes, load from disk                                 │
│    - Start HTTPS server with mTLS on 127.0.0.1:9000       │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. Iceworm Browser Launches                                 │
│    - Reads iiw_config.json                                  │
│    - Loads client-cert.pem and client-key.pem              │
│    - Navigates to https://127.0.0.1:9000                   │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. TLS Handshake (Mutual Authentication)                   │
│    Server → "Show me your certificate"                      │
│    Client → Sends client-cert.pem                          │
│    Server → Verifies signature against CA                   │
│    Client → "Show me YOUR certificate"                      │
│    Server → Sends server-cert.pem                          │
│    Client → Accepts (self-signed, but explicitly trusted)   │
│    ✓ Encrypted channel established                          │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. Frontend Loaded                                          │
│    - React app served over HTTPS                            │
│    - secureClient.ts ready for API calls                    │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 5. API Request (e.g., apiClient.get('/get'))               │
│    - Browser automatically includes client certificate      │
│    - All data encrypted in transit                          │
│    - Server verifies certificate before processing          │
└─────────────────────────────────────────────────────────────┘
```

## Certificate Details

### CA Certificate (`ca-cert.pem`)
- **Purpose**: Signs server and client certificates
- **Validity**: 10 years
- **Algorithm**: ECDSA P-256

### Server Certificate (`server-cert.pem`)
- **Purpose**: Proves server identity to clients
- **Validity**: 5 years
- **Subject**: `CN=localhost, O=Iceworm Desktop App`
- **SANs**: `127.0.0.1`, `::1`, `localhost`

### Client Certificate (`client-cert.pem`)
- **Purpose**: Proves Iceworm browser identity to server
- **Validity**: 5 years
- **Subject**: `CN=Iceworm Client, O=Iceworm Desktop App`

## File Structure

```
backend/
├── certs/
│   ├── manager.go           # Certificate management logic
│   ├── ca-cert.pem           # CA certificate (generated on first run)
│   ├── ca-key.pem            # CA private key
│   ├── server-cert.pem       # Server certificate
│   ├── server-key.pem        # Server private key
│   ├── client-cert.pem       # Client certificate (for Iceworm)
│   └── client-key.pem        # Client private key
├── main.go                   # mTLS HTTPS server

frontend/
└── src/
    └── lib/
        └── secureClient.ts   # Secure API client

iiw_config.json              # Iceworm config with cert paths
```

## First Run

When you first run the Go server, you'll see:

```
Generating new certificates...
✓ CA certificate generated
✓ Server certificate generated
✓ Client certificate generated

Certificates stored in: C:\path\to\backend\certs

🔒 Server running with mTLS on https://127.0.0.1:9000
📁 Certificates location: C:\path\to\backend\certs
⚠️  Client certificate required for all connections
```

Certificates are saved to disk, so subsequent runs will load them:

```
✓ Certificates loaded from disk
🔒 Server running with mTLS on https://127.0.0.1:9000
```

## Testing the Implementation

### 1. Build and Run the Backend

```powershell
cd backend
go run .
```

Expected output:
```
Generating new certificates...
✓ CA certificate generated
✓ Server certificate generated
✓ Client certificate generated
🔒 Server running with mTLS on https://127.0.0.1:9000
```

### 2. Test with cURL (Will Fail Without Client Cert)

```powershell
curl https://127.0.0.1:9000/api/ping -k
```

**Expected**: Connection error (client cert required)

### 3. Test with cURL (With Client Cert)

```powershell
curl https://127.0.0.1:9000/api/ping `
  --cert backend/certs/client-cert.pem `
  --key backend/certs/client-key.pem `
  --cacert backend/certs/ca-cert.pem
```

**Expected**: `{"success":true,"message":"pong pong"}`

### 4. Run Iceworm Browser

```powershell
# Build frontend first
cd frontend
npm run build

# Copy certs to iceworm directory (if needed)
# Then run iceworm with iiw_config.json
```

## Troubleshooting

### "Certificate signed by unknown authority"

**Cause**: Client doesn't trust the self-signed CA.

**Fix**: Ensure `ignore-certificate-errors` is in `iiw_config.json` or add the CA cert to Chromium's trust store.

### "No required SSL certificate was sent"

**Cause**: Client certificate not provided.

**Fix**: 
- Check `iiw_config.json` has correct cert paths
- Verify `client-cert.pem` and `client-key.pem` exist
- Ensure paths are relative to Iceworm executable

### "x509: certificate has expired"

**Cause**: Certificates expired (5-10 years by default).

**Fix**: Delete `backend/certs/` directory and restart server to regenerate.

### Regular Chromium Browser Can't Connect

**Expected behavior**. Regular browsers don't have the client certificate. Only Iceworm (configured in `iiw_config.json`) can connect.

## Certificate Renewal

Certificates are valid for:
- **CA**: 10 years
- **Server/Client**: 5 years

To regenerate certificates:

```powershell
# Stop the server
# Delete the certs directory
rm -r backend/certs

# Restart the server - new certs will be generated
cd backend
go run .
```

## Deployment Considerations

### Development Mode
- Keep `ignore-certificate-errors` in `iiw_config.json`
- Certs regenerated as needed

### Production Mode
1. Generate certs once on a secure machine
2. Package certs with the app binary
3. Set restrictive file permissions (0600 for keys)
4. Consider encrypting private keys with a passphrase
5. Remove `remote-debugging-port` from CEF args
6. Disable DevTools in Iceworm

## What's Next: Phase 2

Phase 2 will add **HMAC Request Signing** on top of mTLS:

1. ✅ Generate ephemeral secret at server startup
2. ✅ Inject secret into frontend (via closure, not window)
3. ✅ Sign each request with HMAC-SHA256(method + url + body + timestamp)
4. ✅ Server validates signature + timestamp freshness (30 seconds)
5. ✅ Prevents replay attacks even if TLS is compromised

## Security Checklist

- [x] All traffic encrypted (TLS 1.3)
- [x] Mutual authentication (client + server certs)
- [x] Localhost-only binding (127.0.0.1)
- [x] Private keys stored securely (0600 permissions)
- [x] Strong cipher suites configured
- [x] CORS restricted to same-origin
- [ ] HMAC request signing (Phase 2)
- [ ] DevTools disabled in production (Phase 3)
- [ ] Code obfuscation (Phase 3)

## References

- [RFC 8446: TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [Go crypto/tls Package](https://pkg.go.dev/crypto/tls)
- [X.509 Certificates](https://en.wikipedia.org/wiki/X.509)
- [Mutual TLS Authentication](https://www.cloudflare.com/learning/access-management/what-is-mutual-tls/)

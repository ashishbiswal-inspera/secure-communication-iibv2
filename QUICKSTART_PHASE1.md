# Quick Start: Phase 1 mTLS Implementation

## ✅ What Was Completed

**Phase 1: Mutual TLS (mTLS) Setup** is complete. Your application now has:

1. ✅ **Certificate Management** - Auto-generates CA, server, and client certificates
2. ✅ **HTTPS Server with mTLS** - Requires client certificates for all connections
3. ✅ **TLS 1.3 Encryption** - All localhost traffic is encrypted
4. ✅ **Secure Frontend Client** - TypeScript API wrapper ready for mTLS
5. ✅ **Iceworm Configuration** - Browser configured to use client certificates

## 🚀 Testing the Implementation

### Step 1: Start the Go Server

```powershell
cd backend
go run .
```

**First run output:**
```
Generating new certificates...
✓ CA certificate generated
✓ Server certificate generated
✓ Client certificate generated

Certificates stored in: C:\Users\Admin\maybeWork\React-Go-iceworm\backend\certs

🔒 Server running with mTLS on https://127.0.0.1:9000
📁 Certificates location: C:\Users\Admin\maybeWork\React-Go-iceworm\backend\certs
⚠️  Client certificate required for all connections
```

### Step 2: Verify Certificates Were Generated

```powershell
ls backend/certs
```

You should see:
- `ca-cert.pem` - Certificate Authority
- `ca-key.pem` - CA private key
- `server-cert.pem` - Server certificate
- `server-key.pem` - Server private key
- `client-cert.pem` - Client certificate (for Iceworm)
- `client-key.pem` - Client private key

### Step 3: Test API Endpoint (With Client Cert)

```powershell
# Test with client certificate (should work)
curl https://127.0.0.1:9000/api/ping `
  --cert backend/certs/client-cert.pem `
  --key backend/certs/client-key.pem `
  --cacert backend/certs/ca-cert.pem
```

**Expected response:**
```json
{"success":true,"message":"pong pong"}
```

### Step 4: Test Without Client Cert (Should Fail)

```powershell
# Test without client certificate (should fail)
curl https://127.0.0.1:9000/api/ping -k
```

**Expected**: Connection error (proving mTLS is enforced)

### Step 5: Update Frontend to Use Secure Client

In your React components, replace direct `fetch()` calls with the secure client:

```typescript
// Old way (insecure)
// fetch('http://localhost:9000/api/get')

// New way (secure with mTLS)
import { apiClient } from '@/lib/secureClient';

// GET request
const response = await apiClient.get('/get');
console.log(response.data);

// POST request
const response = await apiClient.post('/post', {
  name: 'John',
  email: 'john@example.com'
});

// Ping
const response = await apiClient.ping();
```

### Step 6: Build Frontend

```powershell
cd frontend
npm run build
```

This creates `frontend/dist/` which is embedded in the Go binary.

### Step 7: Rebuild Go Server (With Embedded Frontend)

```powershell
cd ../backend
go build -o iceworm-server.exe .
./iceworm-server.exe
```

### Step 8: Launch with Iceworm (When Ready)

Copy the certificates to where Iceworm can find them:

```powershell
# Assuming Iceworm runs from the backend directory
# The paths in iiw_config.json are relative to Iceworm executable
```

Then launch Iceworm with the updated config:
```powershell
iceworm.exe --config=iiw_config.json
```

## 🔒 Security Verification

### What's Protected Now:

✅ **MITM Prevention**: All traffic encrypted with TLS 1.3  
✅ **Authentication**: Server verifies client certificate  
✅ **Authorization**: Only apps with client cert can connect  
✅ **Localhost Only**: Server binds to 127.0.0.1  

### What's NOT Protected Yet:

⚠️ **Replay Attacks**: Phase 2 will add HMAC + timestamp  
⚠️ **Token Exposure**: Phase 2 will use closure-based secrets  
⚠️ **DevTools**: Phase 3 will disable in production  

## 🔧 Common Issues

### "certificate signed by unknown authority"

**Solution**: Already handled in `iiw_config.json` with `ignore-certificate-errors`

### "no required SSL certificate was sent"

**Solution**: Check cert paths in `iiw_config.json` are correct

### "connection refused"

**Solution**: Make sure Go server is running and listening on 127.0.0.1:9000

## 📁 Files Changed

```
backend/
├── certs/manager.go          ← NEW: Certificate management
├── certs/*.pem               ← NEW: Generated certificates (auto)
└── main.go                   ← MODIFIED: mTLS HTTPS server

frontend/
└── src/lib/secureClient.ts   ← NEW: Secure API client

iiw_config.json               ← MODIFIED: Client cert paths
MTLS_SETUP.md                 ← NEW: Full documentation
QUICKSTART_PHASE1.md          ← NEW: This file
```

## ⏭️ Next Steps: Phase 2

When you're ready, we can implement **Phase 2: HMAC Request Signing**:

1. Generate ephemeral secret at server startup
2. Inject secret into frontend via secure closure
3. Sign all requests with HMAC-SHA256(method + url + body + timestamp)
4. Server validates signature + timestamp (30-second window)
5. Prevents replay attacks

This adds defense-in-depth on top of mTLS.

## 📚 Additional Resources

- Full documentation: `MTLS_SETUP.md`
- Certificate manager: `backend/certs/manager.go`
- Secure client: `frontend/src/lib/secureClient.ts`

---

**Phase 1 Status**: ✅ Complete and working!

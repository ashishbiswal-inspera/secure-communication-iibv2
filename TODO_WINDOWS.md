# TODO: Windows Implementation - mTLS with Named Pipes

## Phase 1: Certificate Management (In-Memory Only)

### Backend (Go)

- [ ] **Update Certificate Manager for In-Memory Generation**
  - [ ] Modify `backend/certs/manager.go` to support in-memory only mode
  - [ ] Remove disk I/O operations (optional mode)
  - [ ] Add methods to export certificates as PEM byte arrays
  - [ ] Keep current AppData storage as fallback option

- [ ] **Add Named Pipe Support (Windows)**
  - [ ] Add dependency: `gopkg.in/natefinch/npipe.v2`
  - [ ] Create `backend/ipc/pipe_windows.go`
  - [ ] Implement `createNamedPipe()` function
  - [ ] Implement `generatePipeName()` with random ID
  - [ ] Add timeout handling for pipe connections (5 seconds)

- [ ] **Certificate Transfer via Pipe**
  - [ ] Create `backend/ipc/transfer.go`
  - [ ] Implement `sendCertificates()` - JSON encoding
  - [ ] Add `CertificateBundle` struct for JSON serialization
  - [ ] Implement error handling and connection cleanup

### Iceworm Integration (C++)

- [ ] **Add JSON Parsing**
  - [ ] Download `nlohmann/json.hpp` (single header)
  - [ ] Add to include path in CMake/build system
  - [ ] Create `CertificateBundle` struct in C++

- [ ] **Named Pipe Client**
  - [ ] Create `iceworm/src/ipc/pipe_client_windows.cpp`
  - [ ] Implement `connectToNamedPipe(pipeName)`
  - [ ] Implement `receiveCertificates()` - read JSON from pipe
  - [ ] Add `SecureZeroMemory()` to clear sensitive data

- [ ] **Command-Line Argument Parsing**
  - [ ] Update `main()` to accept `--pipe-name` argument
  - [ ] Validate pipe name format
  - [ ] Add error handling for connection failures

- [ ] **CEF Configuration**
  - [ ] Update CEF initialization to use received certificates
  - [ ] Configure client certificate for `127.0.0.1:9000`
  - [ ] Set CA certificate for server verification
  - [ ] Test TLS handshake with mTLS

### Frontend (React)

- [ ] **Verify No Changes Needed**
  - [ ] Confirm existing `fetch()` calls work with mTLS
  - [ ] Test with `credentials: 'include'`
  - [ ] No certificate handling in JavaScript (stays in CEF layer)

---

## Phase 2: Integration & Testing

### Backend Updates

- [ ] **Update main.go**
  - [ ] Generate certificates at startup
  - [ ] Create named pipe with random name
  - [ ] Launch Iceworm with `--pipe-name` argument
  - [ ] Wait for connection and send certificates
  - [ ] Close pipe after successful transfer
  - [ ] Start HTTPS server with mTLS

- [ ] **Logging & Debugging**
  - [ ] Add startup logs (pipe name, cert generation)
  - [ ] Log pipe connection status
  - [ ] Log certificate transfer completion
  - [ ] Add verbose mode for debugging

### Iceworm Launch

- [ ] **Process Spawning**
  - [ ] Update backend to spawn `iceworm.exe` correctly
  - [ ] Pass working directory
  - [ ] Handle Iceworm startup errors
  - [ ] Add retry logic (3 attempts with backoff)

### Testing

- [ ] **Unit Tests**
  - [ ] Test certificate generation
  - [ ] Test pipe creation and connection
  - [ ] Test JSON serialization/deserialization
  - [ ] Test timeout handling

- [ ] **Integration Tests**
  - [ ] Test full startup flow (Go → Pipe → Iceworm)
  - [ ] Test certificate transfer
  - [ ] Test TLS handshake
  - [ ] Test API requests with mTLS

- [ ] **Manual Testing**
  - [ ] Verify no certificates in process list (`Get-Process`)
  - [ ] Verify pipe closes after transfer
  - [ ] Test multiple app restarts
  - [ ] Test with Task Manager open (check for key exposure)

- [ ] **Security Verification**
  - [ ] Run `Get-Process iceworm | Select CommandLine`
  - [ ] Confirm only pipe name visible (no certs/keys)
  - [ ] Verify pipe doesn't persist after connection
  - [ ] Attempt to connect to pipe after transfer (should fail)

---

## Phase 3: Error Handling & Edge Cases

### Error Scenarios

- [ ] **Pipe Connection Failures**
  - [ ] Handle pipe creation errors
  - [ ] Handle timeout waiting for Iceworm
  - [ ] Add fallback mechanism (environment variables?)
  - [ ] Display user-friendly error messages

- [ ] **Certificate Issues**
  - [ ] Handle cert generation failures
  - [ ] Validate cert before sending
  - [ ] Handle JSON encoding errors
  - [ ] Add cert expiry warnings

- [ ] **Process Issues**
  - [ ] Handle Iceworm crash before connecting
  - [ ] Handle Go server crash during transfer
  - [ ] Clean up orphaned pipes
  - [ ] Prevent multiple instances (port conflicts)

### Cleanup

- [ ] **Resource Management**
  - [ ] Ensure pipes are closed on all code paths
  - [ ] Clear certificate data from memory
  - [ ] Handle graceful shutdown
  - [ ] Add `defer` statements for cleanup

---

## Phase 4: Production Hardening

### Security Enhancements

- [ ] **Certificate Rotation**
  - [ ] Implement per-session cert generation
  - [ ] Add cert refresh mechanism (optional)
  - [ ] Document cert lifecycle

- [ ] **Defense in Depth**
  - [ ] Consider adding encryption layer over pipe
  - [ ] Implement request signing (HMAC) as Phase 2
  - [ ] Add timestamp validation
  - [ ] Implement replay attack prevention

### Performance

- [ ] **Optimization**
  - [ ] Measure startup time (cert gen + pipe transfer)
  - [ ] Optimize pipe buffer sizes
  - [ ] Profile memory usage
  - [ ] Test with slow connections

### Documentation

- [ ] **Code Documentation**
  - [ ] Add GoDoc comments to all exported functions
  - [ ] Document C++ certificate handling
  - [ ] Add inline comments for security-critical code

- [ ] **User Documentation**
  - [ ] Create deployment guide
  - [ ] Document troubleshooting steps
  - [ ] Add FAQ for common issues
  - [ ] Create security architecture diagram

---

## Phase 5: Build & Deployment

### Build System

- [ ] **Go Backend**
  - [ ] Update `go.mod` with npipe dependency
  - [ ] Add Windows build tags if needed
  - [ ] Test `go build` on Windows
  - [ ] Create build script

- [ ] **Iceworm (CEF)**
  - [ ] Update CMakeLists.txt with JSON library
  - [ ] Add pipe client to build
  - [ ] Test compilation on Windows
  - [ ] Verify binary size (embedded resources)

### Packaging

- [ ] **Installer**
  - [ ] Test installation in `Program Files`
  - [ ] Verify no runtime file writes needed
  - [ ] Test with non-admin user
  - [ ] Create installer script (NSIS/WiX)

- [ ] **Code Signing**
  - [ ] Sign Go binary
  - [ ] Sign Iceworm executable
  - [ ] Test signature verification
  - [ ] Document signing process

### Deployment Testing

- [ ] **Clean Install**
  - [ ] Test on fresh Windows 10/11 system
  - [ ] Test with different user accounts
  - [ ] Verify no dependencies missing
  - [ ] Test first-run experience

- [ ] **Upgrade Path**
  - [ ] Test upgrade from previous version
  - [ ] Verify certificates regenerate
  - [ ] Test backward compatibility

---

## Monitoring & Maintenance

### Logging

- [ ] **Production Logging**
  - [ ] Add structured logging (JSON format)
  - [ ] Log security events
  - [ ] Add log rotation
  - [ ] Implement log levels (debug, info, warn, error)

### Monitoring

- [ ] **Health Checks**
  - [ ] Add `/health` endpoint
  - [ ] Monitor certificate status
  - [ ] Track pipe connection metrics
  - [ ] Alert on failures

### Updates

- [ ] **Version Management**
  - [ ] Add version info to binary
  - [ ] Implement update check mechanism
  - [ ] Document rollback procedure

---

## Known Limitations (Windows)

- [ ] **Document Constraints**
  - Pipe name limited to 256 characters
  - Single pipe instance per name
  - Requires Windows Vista or later
  - DACL security model only

---

## References

- Windows Named Pipes API: https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes
- npipe Go library: https://github.com/natefinch/npipe
- nlohmann JSON: https://github.com/nlohmann/json
- CEF Client Certificates: https://bitbucket.org/chromiumembedded/cef/wiki/GeneralUsage

---

## Success Criteria

✅ **Security:**
- No certificates visible in process list
- No disk writes for certificates
- mTLS connection working
- Admin cannot recover keys

✅ **Functionality:**
- App starts successfully
- Iceworm connects to Go server
- API requests work over HTTPS
- Error handling graceful

✅ **Performance:**
- Startup time < 2 seconds
- Pipe transfer < 50ms
- No memory leaks
- Stable under load

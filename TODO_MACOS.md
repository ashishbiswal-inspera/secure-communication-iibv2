# TODO: macOS Implementation - mTLS with Unix Domain Sockets

## Phase 1: Certificate Management (In-Memory Only)

### Backend (Go)

- [ ] **Update Certificate Manager for In-Memory Generation**
  - [ ] Modify `backend/certs/manager.go` to support in-memory only mode
  - [ ] Remove disk I/O operations (optional mode)
  - [ ] Add methods to export certificates as PEM byte arrays
  - [ ] Keep current AppData storage as fallback option

- [ ] **Add Unix Socket Support (macOS)**
  - [ ] Create `backend/ipc/socket_unix.go`
  - [ ] Implement `createUnixSocket()` function using `net.Listen("unix", path)`
  - [ ] Implement `generateSocketPath()` with random ID
  - [ ] Set socket permissions to 0600 (owner read/write only)
  - [ ] Add timeout handling for socket connections (5 seconds)

- [ ] **Socket Path Management**
  - [ ] Choose socket location:
    - [ ] Option 1: `/tmp/iceworm-<random>.sock`
    - [ ] Option 2: `~/Library/Application Support/Iceworm/iceworm.sock`
  - [ ] Implement socket file cleanup on startup (remove stale sockets)
  - [ ] Handle 104-character path length limit
  - [ ] Add error handling for path creation

- [ ] **Certificate Transfer via Socket**
  - [ ] Create `backend/ipc/transfer.go`
  - [ ] Implement `sendCertificates()` - JSON encoding
  - [ ] Add `CertificateBundle` struct for JSON serialization
  - [ ] Implement error handling and connection cleanup
  - [ ] Add socket file deletion after transfer

### Iceworm Integration (C++)

- [ ] **Add JSON Parsing**
  - [ ] Download `nlohmann/json.hpp` (single header)
  - [ ] Add to include path in CMakeLists.txt
  - [ ] Create `CertificateBundle` struct in C++

- [ ] **Unix Socket Client**
  - [ ] Create `iceworm/src/ipc/socket_client_unix.cpp`
  - [ ] Implement `connectToUnixSocket(socketPath)`
  - [ ] Implement `receiveCertificates()` - read JSON from socket
  - [ ] Add `explicit_bzero()` to clear sensitive data (macOS-specific)

- [ ] **Command-Line Argument Parsing**
  - [ ] Update `main()` to accept `--pipe-name` argument (same flag for cross-platform)
  - [ ] Validate socket path format
  - [ ] Add error handling for connection failures
  - [ ] Add retry logic with exponential backoff

- [ ] **CEF Configuration**
  - [ ] Update CEF initialization to use received certificates
  - [ ] Configure client certificate for `127.0.0.1:9000`
  - [ ] Set CA certificate for server verification
  - [ ] Handle macOS Keychain integration (if needed)
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
  - [ ] Add platform detection (`runtime.GOOS == "darwin"`)
  - [ ] Generate certificates at startup
  - [ ] Create Unix socket with random name
  - [ ] Launch Iceworm.app with `--pipe-name` argument
  - [ ] Wait for connection and send certificates
  - [ ] Close socket and delete file after transfer
  - [ ] Start HTTPS server with mTLS

- [ ] **macOS-Specific Considerations**
  - [ ] Handle Iceworm.app bundle structure
  - [ ] Use correct path: `./Iceworm.app/Contents/MacOS/Iceworm`
  - [ ] Set socket location in user-accessible directory
  - [ ] Handle sandboxing restrictions (if applicable)

- [ ] **Logging & Debugging**
  - [ ] Add startup logs (socket path, cert generation)
  - [ ] Log socket connection status
  - [ ] Log certificate transfer completion
  - [ ] Add verbose mode for debugging

### Iceworm Launch

- [ ] **Process Spawning**
  - [ ] Update backend to spawn Iceworm.app correctly
  - [ ] Handle macOS app bundle execution
  - [ ] Pass working directory
  - [ ] Handle Iceworm startup errors
  - [ ] Add retry logic (3 attempts with backoff)

### Testing

- [ ] **Unit Tests**
  - [ ] Test certificate generation
  - [ ] Test socket creation and connection
  - [ ] Test JSON serialization/deserialization
  - [ ] Test timeout handling
  - [ ] Test socket file cleanup

- [ ] **Integration Tests**
  - [ ] Test full startup flow (Go → Socket → Iceworm)
  - [ ] Test certificate transfer
  - [ ] Test TLS handshake
  - [ ] Test API requests with mTLS

- [ ] **Manual Testing**
  - [ ] Verify no certificates in process list (`ps aux`)
  - [ ] Verify socket file deleted after transfer
  - [ ] Test multiple app restarts
  - [ ] Check `/tmp` for orphaned socket files
  - [ ] Test with Activity Monitor open (check for key exposure)

- [ ] **Security Verification**
  - [ ] Run `ps aux | grep iceworm`
  - [ ] Confirm only socket path visible (no certs/keys)
  - [ ] Verify socket permissions: `ls -la /tmp/iceworm-*.sock`
  - [ ] Attempt to connect to socket after transfer (should fail)

---

## Phase 3: Error Handling & Edge Cases

### Error Scenarios

- [ ] **Socket Connection Failures**
  - [ ] Handle socket creation errors (permissions, path issues)
  - [ ] Handle timeout waiting for Iceworm
  - [ ] Add fallback mechanism (environment variables?)
  - [ ] Display user-friendly error messages
  - [ ] Handle "Address already in use" errors

- [ ] **Certificate Issues**
  - [ ] Handle cert generation failures
  - [ ] Validate cert before sending
  - [ ] Handle JSON encoding errors
  - [ ] Add cert expiry warnings

- [ ] **Process Issues**
  - [ ] Handle Iceworm crash before connecting
  - [ ] Handle Go server crash during transfer
  - [ ] Clean up orphaned socket files
  - [ ] Prevent multiple instances (port conflicts)

- [ ] **macOS-Specific Issues**
  - [ ] Handle Gatekeeper warnings (unsigned apps)
  - [ ] Handle sandboxing restrictions
  - [ ] Handle SIP (System Integrity Protection) constraints
  - [ ] Test on different macOS versions (11, 12, 13, 14)

### Cleanup

- [ ] **Resource Management**
  - [ ] Ensure sockets are closed on all code paths
  - [ ] Delete socket files on shutdown
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
  - [ ] Consider adding encryption layer over socket
  - [ ] Implement request signing (HMAC) as Phase 2
  - [ ] Add timestamp validation
  - [ ] Implement replay attack prevention

- [ ] **macOS Security**
  - [ ] Consider using Keychain for cert storage (optional)
  - [ ] Add entitlements for socket access
  - [ ] Test with macOS sandbox enabled
  - [ ] Document security model

### Performance

- [ ] **Optimization**
  - [ ] Measure startup time (cert gen + socket transfer)
  - [ ] Optimize socket buffer sizes
  - [ ] Profile memory usage
  - [ ] Test with slow connections

### Documentation

- [ ] **Code Documentation**
  - [ ] Add GoDoc comments to all exported functions
  - [ ] Document C++ certificate handling
  - [ ] Add inline comments for security-critical code
  - [ ] Document macOS-specific considerations

- [ ] **User Documentation**
  - [ ] Create deployment guide for macOS
  - [ ] Document troubleshooting steps
  - [ ] Add FAQ for common macOS issues
  - [ ] Create security architecture diagram

---

## Phase 5: Build & Deployment

### Build System

- [ ] **Go Backend**
  - [ ] Update `go.mod` (no external deps for Unix sockets)
  - [ ] Add macOS build tags if needed
  - [ ] Test `go build` on macOS (Intel and Apple Silicon)
  - [ ] Create universal binary (Intel + ARM64)
  - [ ] Create build script

- [ ] **Iceworm (CEF)**
  - [ ] Update CMakeLists.txt with JSON library
  - [ ] Add socket client to build
  - [ ] Test compilation on macOS (Xcode)
  - [ ] Create .app bundle structure
  - [ ] Add Info.plist configuration
  - [ ] Verify binary size (embedded resources)

### Packaging

- [ ] **macOS App Bundle**
  - [ ] Create proper .app structure
  - [ ] Add Info.plist with required keys
  - [ ] Include Go backend in bundle
  - [ ] Test bundle structure
  - [ ] Verify all resources embedded

- [ ] **Installer**
  - [ ] Create DMG installer
  - [ ] Test installation in `/Applications`
  - [ ] Verify no runtime file writes needed
  - [ ] Test with standard user account
  - [ ] Add uninstaller script

- [ ] **Code Signing & Notarization**
  - [ ] Get Apple Developer certificate
  - [ ] Sign Go binary
  - [ ] Sign Iceworm.app bundle
  - [ ] Enable Hardened Runtime
  - [ ] Notarize app with Apple
  - [ ] Staple notarization ticket
  - [ ] Test on macOS with Gatekeeper enabled
  - [ ] Document signing process

### Deployment Testing

- [ ] **Clean Install**
  - [ ] Test on fresh macOS 12+ system
  - [ ] Test on Intel and Apple Silicon Macs
  - [ ] Test with different user accounts
  - [ ] Verify no dependencies missing
  - [ ] Test first-run experience
  - [ ] Test with Gatekeeper enabled

- [ ] **Upgrade Path**
  - [ ] Test upgrade from previous version
  - [ ] Verify certificates regenerate
  - [ ] Test backward compatibility

---

## Monitoring & Maintenance

### Logging

- [ ] **Production Logging**
  - [ ] Add structured logging (JSON format)
  - [ ] Log to `~/Library/Logs/Iceworm/`
  - [ ] Add log rotation
  - [ ] Implement log levels (debug, info, warn, error)
  - [ ] Follow macOS logging guidelines

### Monitoring

- [ ] **Health Checks**
  - [ ] Add `/health` endpoint
  - [ ] Monitor certificate status
  - [ ] Track socket connection metrics
  - [ ] Alert on failures

### Updates

- [ ] **Version Management**
  - [ ] Add version info to bundle
  - [ ] Implement Sparkle update framework
  - [ ] Document rollback procedure
  - [ ] Test update process

---

## Known Limitations (macOS)

- [ ] **Document Constraints**
  - Socket path limited to 104 characters (`sizeof(sockaddr_un.sun_path)`)
  - Requires macOS 10.13 (High Sierra) or later
  - Sandboxed apps need special entitlements
  - SIP may restrict certain operations
  - Notarization required for distribution

---

## macOS-Specific Features (Optional)

- [ ] **Enhanced Security**
  - [ ] Investigate abstract namespace (Linux-only, not macOS)
  - [ ] Consider XPC for IPC (macOS native)
  - [ ] Evaluate Keychain integration
  - [ ] Add Touch ID authentication (future)

- [ ] **macOS Integration**
  - [ ] Add to Login Items (auto-start)
  - [ ] Menu bar icon
  - [ ] Native notifications
  - [ ] Dock icon customization

---

## References

- Unix Domain Sockets: https://man7.org/linux/man-pages/man7/unix.7.html
- macOS Security: https://developer.apple.com/documentation/security
- Code Signing Guide: https://developer.apple.com/documentation/xcode/code-signing
- Notarization: https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution
- CEF on macOS: https://bitbucket.org/chromiumembedded/cef/wiki/MacOS

---

## Success Criteria

✅ **Security:**
- No certificates visible in process list (`ps aux`)
- Socket file has 0600 permissions
- Socket deleted after transfer
- mTLS connection working
- Admin cannot recover keys

✅ **Functionality:**
- App starts successfully on Intel and Apple Silicon
- Iceworm connects to Go server
- API requests work over HTTPS
- Error handling graceful
- Survives macOS updates

✅ **Performance:**
- Startup time < 2 seconds
- Socket transfer < 50ms
- No memory leaks
- Stable under load

✅ **macOS Compliance:**
- Properly signed and notarized
- Passes Gatekeeper
- Works in sandboxed environment
- Follows macOS HIG (Human Interface Guidelines)

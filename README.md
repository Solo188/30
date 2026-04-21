# AdBlocker — Local VPN Ad Blocker for Android

A production-architecture Android application that blocks ads and trackers on-device using a local VPN tunnel with optional HTTPS interception (MITM).

**No traffic leaves your device.**

---

## Architecture Overview

```
Device Apps
    │
    ▼
[ TUN Interface — Android VpnService ]
    │  (all TCP traffic captured here)
    ▼
[ TunToProxyRouter ]        ← core.vpn
    │  (rewrite destination to localhost)
    ▼
[ EmbeddedProxyServer ]     ← core.proxy  (Netty)
    │
    ├─[ HTTP ]────────────────────────────────────────┐
    │                                                  │
    └─[ HTTPS CONNECT ]──[ MitmManager / BouncyCastle ]┤
                           (per-domain cert spoofing)  │
                                                       ▼
                                           [ InterceptorPipeline ]
                                                  │
                                           [ FilterEngine ]       ← filter.engine
                                                  │
                                     ┌────────────┴────────────┐
                                     │                          │
                              [ DomainTrie ]           [ SubstringRules ]
                             O(k) blocked domains      fallback scan
                                     │
                                  BLOCK / PASS
                                     │
                              ┌──────┴──────┐
                          BLOCKED        upstream OkHttp call
                         (204 reply)     (response piped back)
```

## Module Structure

```
app/src/main/java/com/adblocker/
├── AdBlockerApp.kt               — Application entry point, filter engine init
│
├── core/
│   ├── vpn/
│   │   ├── AdBlockerVpnService.kt   — Android VpnService, tun interface lifecycle
│   │   ├── TunToProxyRouter.kt      — Raw IP packet router → local proxy
│   │   └── VpnController.kt         — UI-facing start/stop/state API
│   ├── proxy/
│   │   ├── LocalProxyService.kt     — Service wrapper for the proxy server
│   │   ├── EmbeddedProxyServer.kt   — Netty ServerBootstrap (replaces LittleProxy)
│   │   ├── ProxyRequestHandler.kt   — HTTP / CONNECT handler + OkHttp upstream
│   │   └── InterceptorPipeline.kt   — Ordered request/response interception chain
│   └── mitm/
│       └── MitmManager.kt           — Root CA + per-domain leaf cert generation
│
├── filter/
│   ├── rules/
│   │   └── FilterRule.kt            — Sealed hierarchy: Network/Domain/Cosmetic/Comment
│   ├── parser/
│   │   └── EasyListParser.kt        — EasyList / uBlock Origin syntax parser
│   └── engine/
│       ├── FilterEngine.kt          — Blocking decision engine (Trie + substring)
│       └── DomainTrie.kt            — O(k) domain trie for fast lookup
│
├── ui/
│   ├── main/
│   │   ├── MainActivity.kt          — Single-screen UI
│   │   └── MainViewModel.kt         — State: VPN state, log entries, blocked count
│   └── log/
│       ├── RequestLogEntry.kt       — Immutable log snapshot
│       ├── RequestLogAdapter.kt     — RecyclerView adapter (ListAdapter + DiffUtil)
│       └── RequestLogDatabase.kt    — Room DB for persistent log storage
│
└── utils/
    ├── Logger.kt                    — Structured logging wrapper
    ├── CertificateUtils.kt          — BKS keystore persistence helpers
    └── NetworkUtils.kt              — Port discovery, host parsing helpers
```

---

## Getting Started

### Prerequisites

- Android Studio Hedgehog (2023.1.1) or later
- Android SDK 34
- JDK 17
- A physical Android device or emulator running API 26+

### 1. Clone / Download

```bash
# If downloading as a zip, extract and open in Android Studio:
# File → Open → select the android-adblocker/ directory
```

### 2. Download EasyList

The bundled `easylist.txt` is a placeholder with ~30 sample rules for testing.
Download the real EasyList (~80 000 rules) and replace the file:

```bash
# From the project root:
curl -o app/src/main/assets/filters/easylist.txt \
  https://easylist.to/easylist/easylist.txt

curl -o app/src/main/assets/filters/easyprivacy.txt \
  https://easylist.to/easylist/easyprivacy.txt
```

### 3. Build

```bash
./gradlew assembleDebug
```

Install on device:
```bash
./gradlew installDebug
```

### 4. Run Tests

```bash
./gradlew test
```

---

## First-Run Setup

1. **Grant VPN permission** — Android will show the system VPN consent dialog on first tap.
2. **Install the CA Certificate** (for HTTPS interception):
   - Tap the ⋮ overflow menu → **Export CA Certificate**
   - Android will offer to install it; tap **Install**
   - Navigate to: **Settings → Security → Encryption & Credentials → Trusted Credentials**
   - Confirm `AdBlocker Root CA` appears under User certificates

   > Without the CA cert, HTTPS traffic is not intercepted (it passes through the tunnel unmodified). HTTP and domain-level blocking still work.

---

## How HTTPS Interception Works

1. The device app opens an HTTPS connection to `ads.example.com:443`.
2. The VPN captures the TCP SYN and routes it to `localhost:8118` (the proxy).
3. The app sends `CONNECT ads.example.com:443 HTTP/1.1`.
4. `ProxyRequestHandler` responds with `200 Connection Established`.
5. `MitmManager` generates a leaf TLS certificate for `ads.example.com`, signed by our root CA.
6. A Netty `SslHandler` is injected into the pipeline using that certificate.
7. The app's TLS handshake succeeds because our root CA is trusted (step above).
8. The decrypted HTTP request flows through the `InterceptorPipeline`.
9. If blocked → 204 reply. If allowed → forwarded to the real server via OkHttp.

---

## Extending the Interceptor Pipeline

### Adding a custom request interceptor

```kotlin
// In your Application or Service setup:
pipeline.addRequestInterceptor(object : InterceptorPipeline.RequestInterceptor {
    override fun intercept(ctx: InterceptorPipeline.RequestContext): InterceptorPipeline.Decision {
        // Block anything to tracking.mycompany.com
        return if (ctx.host.contains("tracking")) {
            InterceptorPipeline.Decision.BLOCK
        } else {
            InterceptorPipeline.Decision.PASS
        }
    }
})
```

### Adding a response modifier (e.g. script injection)

```kotlin
pipeline.addResponseInterceptor(object : InterceptorPipeline.ResponseInterceptor {
    override fun intercept(
        ctx: InterceptorPipeline.ResponseContext,
        response: okhttp3.Response
    ): okhttp3.Response {
        val contentType = response.header("Content-Type") ?: ""
        if (!contentType.contains("text/html")) return response

        val body = response.body?.string() ?: return response
        val injected = body.replace("</body>", "<script>/* uBlock-style injection */</script></body>")

        return response.newBuilder()
            .body(okhttp3.ResponseBody.create(response.body?.contentType(), injected))
            .build()
    }
})
```

---

## Performance Notes

- **DomainTrie**: O(k) lookup where k = number of domain labels. 80 000 rules →  near-instant lookup.
- **Filter initialisation**: Done on `Dispatchers.IO` at app startup; UI is never blocked.
- **Netty thread pool**: 1 boss thread + 4 worker threads. Tune `WORKER_THREADS` in `EmbeddedProxyServer` for your device.
- **Leaf cert cache**: Cached in memory per domain (`ConcurrentHashMap`). Cert generation (BouncyCastle RSA 2048) is ~20–50 ms per new domain; cached hits are ~0 ms.

---

## Security Considerations

| Risk | Mitigation |
|---|---|
| Root CA key leakage | Stored in BKS keystore in app private storage (`filesDir`); not world-readable |
| Proxy accessible by other apps | Bound to `127.0.0.1` only; not reachable from other devices |
| VPN bypass by apps | Apps using certificate pinning will fail; they cannot be MITM'd |
| Malicious rule injection | Filter files are bundled assets; no remote rule update in this build |

---

## Roadmap / Future Extensions

- [ ] **Userspace TCP stack** — Replace `TunToProxyRouter` skeleton with lwIP via Android NDK for correct per-flow TCP state management
- [ ] **DNS blocking** — Intercept UDP port 53 packets in the tun router; return NXDOMAIN for blocked domains
- [ ] **Cosmetic filtering** — Inject CSS (`display:none`) for `##.element` rules via the response interceptor
- [ ] **Script injection** — uBlock-style scriptlet injection via `ResponseInterceptor`
- [ ] **Remote rule updates** — Periodic background download of EasyList with version checking
- [ ] **Per-app rules** — Use `VpnService.Builder.addAllowedApplication` / `addDisallowedApplication`
- [ ] **Statistics dashboard** — Room-backed charts of blocked requests over time

---

## Dependencies

| Library | Purpose |
|---|---|
| Netty 4.1 | Async networking engine for the embedded proxy |
| BouncyCastle 1.77 | Root CA + leaf certificate generation (MITM) |
| OkHttp 4.12 | Upstream HTTP/HTTPS request forwarding |
| Room 2.6 | Request log persistence |
| Kotlin Coroutines 1.7 | Non-blocking I/O throughout |
| Material Components 1.11 | UI components |

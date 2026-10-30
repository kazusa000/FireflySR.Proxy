# Railway local fork

Based on GesthosNetwork/FireflySR.Proxy at d41bf12591424b424b0a6f2dca38c8a9a5fd9795 (GPL-3.0).

This fork replaces the interactive standalone proxy lifecycle with a project-owned session:

- Loopback listener; exact domain boundaries; no path-only redirect; upstream TLS validation retained.
- Explicit WinINet snapshot/restore and pre-existing-proxy protection. No machine WinHTTP changes.
- Separate ordinary session/proxy watchdogs and an elevated client/certificate watchdog.
- PID plus start-time ownership, crash recovery recipes, atomic lease persistence and private runtime storage.
- Caller-selected current-user or machine root trust with exact-thumbprint cleanup and readback. Machine trust requires explicit deployment authorization.
- UTF8-encoded root Subject to match BouncyCastle leaf Issuer encoding on Windows.
- No credentials or query strings in redirect logs.
- Child-only Unity/curl proxy environment for the elevated game; no persistent environment changes.
- Disabled upstream prefetch before rewriting, so local requests do not wait on official TLS.
- Optional background desktop for the game (automated client tests): the elevated helper creates it and starts the unchanged game there.
- .NET 9 projects and NuGet lock files; build artifacts directed by the parent project's portable build wrapper.

Use the parent project's tools/dev/build-proxy.ps1 and tools/dev/Play.ps1, not upstream compile.bat. Runtime data and private keys do not belong in this repository. Original license and upstream history are retained.

# Sinks

The runner reserves `10.13.37.53` for DNS and `10.13.37.9` for HTTP and TLS on the internal Docker network. `Sandbox.start_service()` starts and removes these containers without publishing any host ports.

The production sinks are the next milestone. They will log DNS queries and data hidden in DNS labels, HTTP method, path, headers and body, and the TLS ClientHello SNI on port 443. Each hit will carry the source IP and the scan's token, and logs go to JSONL files through a dedicated bind mount. A sink counts as complete only when it has done its job, not when its container starts.

Never replace a sink container with a listener on the host. The HTTP server in the integration tests only checks connectivity.

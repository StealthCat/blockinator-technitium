# Changelog

## 1.4.0

- Fixed fail-open fallbacks bypassing Technitium's built-in blocking when `bypassBuiltInBlockingOnAllow` is enabled; only an explicit Blockinator ALLOW now bypasses it.
- Fixed a decision without a `block` field being treated as ALLOW; it now follows `failMode`.
- Fixed blocked queries resolving normally when `matched_domain` is not a valid parent domain (wildcard/regex rules); the SOA owner now falls back to the queried name.
- Fixed `timeoutMs` not bounding the response body read; one deadline now covers the whole request.
- Limited policy responses to 16 KiB.
- Stopped following HTTP redirects and ignoring ambient proxy settings so `X-Api-Key` is only sent to the configured endpoint.
- Rejected endpoint URLs containing credentials, which would otherwise be written to the log.
- Fixed string-typed numeric settings (for example `"timeoutMs": "250"`) failing initialization; they now fall back to defaults.
- Configuration reloads no longer dispose the HTTP client under in-flight lookups.
- Blocked responses now set the Recursion Available flag.
- Released decision handoff entries for allowed queries immediately and throttled the expired-entry sweep.
- Skipped policy lookups for requests without a question.
- Rate-limited policy-failure log messages and warned when `apiKey` is empty or still the example value.

## 1.3.0

- Added HTTPS policy-server endpoint support with normal operating-system certificate trust.
- Added optional custom root CA trust for private/internal PKI and ACME deployments.
- Preserved TLS hostname validation when a custom CA is configured.
- Added an explicit opt-in certificate-verification bypass for controlled troubleshooting, with a startup warning.
- Reject non-HTTP(S) policy endpoint schemes during initialization.
- Expanded startup probe diagnostics for TLS trust failures.

## 1.2.0

- Fixed Technitium app discovery packaging by building with `dotnet publish`.
- Explicitly generate and include `RemotePolicyBlockingApp.deps.json` at the install ZIP root.
- Validate the generated ZIP before reporting a successful build.
- Added startup connectivity probing against the Blockinator `/api/v1/ping` endpoint.
- Added optional per-query diagnostic logging.
- Added authenticated Blockinator policy requests using `X-Api-Key`.

## 1.1.0

- Added startup/request diagnostics for troubleshooting missing policy traffic.
- Added authenticated policy-server connectivity probe.

## 1.0.0

- Initial Technitium remote policy plugin.
- Implements request-controller and request-blocking interfaces.
- Sends complete DNS request metadata and wire payload to the remote policy service.
- Supports NXDOMAIN, REFUSED, NODATA, and zero-address blocked responses.

# Blockinator Technitium Plugin

Technitium DNS Server plugin for **Blockinator**. It forwards each DNS request to a Blockinator policy server, receives an allow/block decision, and returns the appropriate DNS response.

The repository is intentionally flat: source, project file, configuration, and build scripts all live at the repository root.

## Requirements

- Technitium DNS Server 15.x
- .NET 10 SDK for building
- A running Blockinator policy server (HTTP or HTTPS)

The project builds directly against the Technitium assemblies from the DNS Server installation so the plugin matches the version you run.

## What it does

The app implements:

- `IDnsApplication`
- `IDnsRequestController`
- `IDnsRequestBlockingHandler`
- `IDnsApplicationPreference`

For each incoming request it sends Blockinator:

- client IP and source port;
- transport protocol;
- DNS identifier, opcode, flags, RCODE, and EDNS presence;
- all questions;
- question/answer/authority/additional counts; and
- the complete DNS wire datagram as Base64.

Blockinator returns an allow/block decision plus an optional response mode. Supported blocked responses are **NXDOMAIN**, **REFUSED**, **NODATA**, and zero-address responses for A/AAAA requests.

The short-lived in-memory decision cache only passes the decision for the *same DNS request* from Technitium's request-controller stage to its blocking-handler stage. It does not cache policy decisions across separate DNS requests.

## Build

### Linux

```bash
chmod +x build-plugin.sh
./build-plugin.sh /opt/technitium/dns
```

### Windows

```powershell
.\build-plugin.ps1 -TechnitiumPath "C:\Program Files\Technitium\DNS Server"
```

The installable archive is created at:

```text
dist/RemotePolicyBlockingApp.zip
```

The build uses `dotnet publish` and validates that the ZIP contains these files at its root:

```text
RemotePolicyBlockingApp.dll
RemotePolicyBlockingApp.deps.json
dnsApp.config
README.md
```

The `.deps.json` file is required for current Technitium app discovery. Older package builds that omitted it could appear installed while never instantiating the DNS app.

## Install

1. Build `dist/RemotePolicyBlockingApp.zip`.
2. Open **Apps** in the Technitium DNS Server web console.
3. Install/upload the ZIP.
4. Edit the installed app configuration.
5. Set the Blockinator endpoint and one enabled Blockinator API key.
6. Save/restart or update the app as required by Technitium.

If Technitium and Blockinator share a Docker network, a typical endpoint is:

```json
"endpoint": "http://blockinator:8080/api/v1/decision"
```

If Blockinator is on another host, use its reachable LAN address instead. Do not use `127.0.0.1` unless Blockinator is actually reachable from the Technitium process on localhost.

## Configuration

The included `dnsApp.config` is the template:

```json
{
  "appPreference": 25,
  "endpoint": "http://127.0.0.1:8080/api/v1/decision",
  "tlsVerifyServerCertificate": true,
  "tlsCaCertificatePath": "",
  "apiKey": "change-this-long-random-api-key",
  "serverId": "technitium-1",
  "timeoutMs": 250,
  "failMode": "open",
  "blockAnswerTtl": 30,
  "bypassBuiltInBlockingOnAllow": true,
  "diagnosticLogging": false
}
```

- **appPreference** — Technitium app ordering preference.
- **endpoint** — full Blockinator `/api/v1/decision` URL. Both `http://` and `https://` are supported.
- **tlsVerifyServerCertificate** — verifies the HTTPS server certificate and hostname. Defaults to `true`. Set to `false` only for controlled testing.
- **tlsCaCertificatePath** — optional path to a PEM or DER root CA certificate trusted specifically for the Blockinator HTTPS endpoint. Useful with private/internal ACME CAs.
- **apiKey** — enabled Blockinator API key, sent as `X-Api-Key`.
- **serverId** — label stored with requests when multiple DNS servers use one Blockinator instance.
- **timeoutMs** — HTTP policy timeout. Default is 250 ms.
- **failMode** — `open` allows DNS when Blockinator is unavailable; `closed` blocks with REFUSED.
- **blockAnswerTtl** — TTL for synthetic blocked answers.
- **bypassBuiltInBlockingOnAllow** — allows a Blockinator ALLOW decision to bypass Technitium's own built-in blocking lists.
- **diagnosticLogging** — logs intercepted requests and remote decisions for troubleshooting.

## HTTPS / TLS

For a public CA such as Let's Encrypt, only change the endpoint to HTTPS:

```json
"endpoint": "https://blockinator.example.com/api/v1/decision"
```

The plugin uses the operating system trust store by default and continues to validate the certificate hostname.

For a private/internal CA, make the CA root certificate available to the Technitium process and configure it explicitly:

```json
{
  "endpoint": "https://blockinator.internal:8443/api/v1/decision",
  "tlsVerifyServerCertificate": true,
  "tlsCaCertificatePath": "/etc/technitium/blockinator-ca.pem"
}
```

The custom CA augments HTTPS validation for this policy client without requiring the CA to be installed into the host-wide trust store. Hostname validation remains required.

For temporary lab troubleshooting only, certificate validation can be disabled with `"tlsVerifyServerCertificate": false`. The plugin writes a warning to the Technitium log whenever this is active.

## Diagnostics

When `diagnosticLogging` is enabled, the app writes an interception log for each DNS request and logs the remote decision.

At startup it also probes the authenticated Blockinator ping endpoint derived from the configured decision URL.

Useful results include:

- **connectivity probe succeeded** — endpoint and API key are working.
- **HTTP 401 Unauthorized** — API key does not match an enabled Blockinator key.
- **connectivity probe FAILED** — check endpoint address, routing/firewall, container networking, and Blockinator availability.

You can test Blockinator from the Technitium host with:

```bash
curl -i -H 'X-Api-Key: YOUR_KEY' https://BLOCKINATOR:8443/api/v1/ping
```

## Version

Current plugin project version: **1.3.0**.

The plugin source was recovered from the working Blockinator v1.3 bundle. Plugin logic was unchanged in that bundle; v1.2 is the packaging/app-discovery-fixed release.

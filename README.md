# Blockinator Technitium Plugin

The **Blockinator Technitium Plugin** connects Technitium DNS Server to a Blockinator policy server.

For each DNS request, the plugin sends client and query metadata to Blockinator over an authenticated HTTP or HTTPS API. Blockinator returns an allow/block decision, and the plugin either lets Technitium continue normally or generates the requested blocked DNS response.

This repository contains the Technitium-side integration. The Blockinator policy server and web interface are maintained in the separate `blockinator-web` repository.

## Features

- Remote DNS policy decisions through Blockinator.
- Authenticated requests using a Blockinator API key.
- HTTP and HTTPS policy endpoints.
- Normal operating-system TLS trust.
- Optional custom root CA for private/internal PKI.
- TLS hostname validation with custom CA trust.
- Explicit certificate-verification bypass for controlled troubleshooting.
- Configurable fail-open or fail-closed behavior.
- Configurable policy request timeout.
- Per-DNS-server identity through `serverId`.
- Optional bypass of Technitium's built-in blocking when Blockinator explicitly allows a query.
- Synthetic blocked responses using:
  - **NXDOMAIN**
  - **REFUSED**
  - **NODATA**
  - **zero-address** A/AAAA answers
- Configurable TTL for synthetic blocked records.
- Startup connectivity/authentication probe against Blockinator.
- Optional per-query diagnostic logging.
- Full DNS request metadata and wire datagram forwarding.
- Short-lived same-request decision handoff between Technitium plugin stages.
- Linux and Windows build scripts that create and validate an installable Technitium app ZIP.

## Requirements

- **Technitium DNS Server 15.x**
- **.NET 10 SDK** to build the plugin
- A running **Blockinator** policy server
- Access to the Technitium DNS Server installation when building

The project references Technitium's own assemblies directly from the DNS Server installation so the plugin is built against the version actually installed on the system.

## How it works

The plugin implements these Technitium application interfaces:

- `IDnsApplication`
- `IDnsRequestController`
- `IDnsRequestBlockingHandler`
- `IDnsApplicationPreference`

The normal request path is:

```text
DNS client
   │
   ▼
Technitium DNS Server
   │
   ├─► Request-controller stage
   │      │
   │      └─► POST DNS metadata to Blockinator
   │                │
   │                └─► allow / block decision
   │
   ├─► Optional Technitium built-in blocking
   │
   └─► Request-blocking stage
          │
          ├─ allow ─► Technitium continues normal resolution
          │
          └─ block ─► plugin generates DNS block response
```

The request-controller stage is used to capture the Technitium transport protocol and obtain the Blockinator decision before the blocking-handler stage runs.

### What is sent to Blockinator

Each policy request can include:

- configured DNS server ID;
- DNS transport protocol;
- client IP address;
- client source port;
- DNS message identifier;
- request/response flag;
- opcode;
- authoritative-answer flag;
- truncation flag;
- recursion-desired flag;
- recursion-available flag;
- authentic-data flag;
- checking-disabled flag;
- RCODE;
- EDNS presence;
- question count;
- answer count;
- authority count;
- additional count;
- every DNS question;
- DNS question name, type, and class; and
- the complete DNS wire datagram encoded as Base64.

This gives Blockinator enough context to log the request and make policy decisions using the client, query, policy targets, and configured block lists.

## Decision handoff and caching

Technitium invokes separate request-controller and blocking-handler stages for the same DNS request.

To avoid making the same Blockinator request twice, the plugin keeps the first decision in a short-lived in-memory cache and passes it to the blocking-handler stage.

The cache key includes:

- client IP;
- client source port;
- DNS message identifier; and
- each question's name, type, and class.

Cached entries expire after approximately **5 seconds** and are consumed by the blocking-handler stage.

This is **not a DNS or policy cache**. Decisions are not reused across unrelated DNS requests.

## Installation

### 1. Build the plugin

Linux:

```bash
chmod +x build-plugin.sh
./build-plugin.sh /opt/technitium/dns
```

Windows PowerShell:

```powershell
.\build-plugin.ps1 -TechnitiumPath "C:\Program Files\Technitium\DNS Server"
```

The generated install package is:

```text
dist/RemotePolicyBlockingApp.zip
```

### 2. Install in Technitium

1. Open the Technitium DNS Server web console.
2. Go to **Apps**.
3. Install/upload `dist/RemotePolicyBlockingApp.zip`.
4. Open the installed app configuration.
5. Set the Blockinator endpoint and API key.
6. Adjust the remaining settings as needed.
7. Save/restart or update the app as required by Technitium.

## Configuration

The included `dnsApp.config` is the default configuration template:

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

### Configuration reference

| Setting | Description | Default |
| --- | --- | --- |
| `appPreference` | Technitium application ordering preference. | `25` |
| `endpoint` | Full Blockinator `/api/v1/decision` URL. Must use HTTP or HTTPS. | `http://127.0.0.1:8080/api/v1/decision` |
| `tlsVerifyServerCertificate` | Validate HTTPS certificate trust and hostname. | `true` |
| `tlsCaCertificatePath` | Optional PEM or DER root CA trusted specifically for the Blockinator endpoint. | blank |
| `apiKey` | Enabled Blockinator API key sent in the `X-Api-Key` header. | change-me value |
| `serverId` | Optional identifier recorded by Blockinator to distinguish multiple DNS servers. | `technitium-1` |
| `timeoutMs` | HTTP policy lookup timeout in milliseconds. Values are clamped to 25–10000 ms. | `250` |
| `failMode` | Behavior when Blockinator cannot return a usable decision: `open` or `closed`. | `open` |
| `blockAnswerTtl` | TTL for synthetic block answers/SOA records. Values are clamped to 0–86400 seconds. | `30` |
| `bypassBuiltInBlockingOnAllow` | Let an explicit Blockinator ALLOW bypass Technitium's built-in blocking. | `true` |
| `diagnosticLogging` | Log intercepted requests and returned decisions. | `false` |

Only `http://` and `https://` endpoint schemes are accepted.

## Endpoint examples

### Blockinator on another LAN host

```json
"endpoint": "http://192.168.1.50:8080/api/v1/decision"
```

### Blockinator over HTTPS

```json
"endpoint": "https://blockinator.example.com/api/v1/decision"
```

### Shared Docker network

If Technitium and Blockinator share a Docker network and the Blockinator application is reachable directly by its Compose service name:

```json
"endpoint": "http://blockinator:8080/api/v1/decision"
```

Do not use `127.0.0.1` unless the Blockinator service is actually reachable from the Technitium process on localhost. Inside separate containers, `127.0.0.1` refers to the Technitium container itself.

## Authentication

The plugin sends the configured API key as:

```text
X-Api-Key: <apiKey>
```

The key must correspond to an enabled API key in Blockinator.

Using a named `serverId` is strongly recommended when multiple Technitium servers send requests to the same Blockinator instance because Blockinator records the originating server in its Dashboard and Query Log.

Example:

```json
{
  "apiKey": "your-enabled-blockinator-key",
  "serverId": "dns-east-1"
}
```

## HTTPS and TLS

The plugin supports Blockinator policy servers over HTTPS without requiring a reverse proxy workaround on the Technitium side.

### Publicly trusted certificate

For certificates issued by a CA already trusted by the operating system, use an HTTPS endpoint and leave certificate verification enabled:

```json
{
  "endpoint": "https://blockinator.example.com/api/v1/decision",
  "tlsVerifyServerCertificate": true,
  "tlsCaCertificatePath": ""
}
```

The normal OS trust store is used and certificate hostname validation remains enabled.

### Private or internal CA

For an internal ACME server or private PKI, make the CA root certificate readable by the Technitium process and configure:

```json
{
  "endpoint": "https://blockinator.internal:8443/api/v1/decision",
  "tlsVerifyServerCertificate": true,
  "tlsCaCertificatePath": "/etc/technitium/blockinator-ca.pem"
}
```

The configured CA becomes a custom trust root for this Blockinator policy client.

Hostname validation is still required. A certificate trusted by the custom root is rejected if its hostname does not match the endpoint.

The custom CA file may be PEM or DER encoded.

### Disabling certificate verification

For controlled troubleshooting only:

```json
"tlsVerifyServerCertificate": false
```

This disables HTTPS server-certificate validation and should not be used as a normal production configuration.

The plugin writes a warning to the Technitium log whenever certificate verification is disabled.

## Fail-open and fail-closed behavior

Policy lookups can fail because of:

- Blockinator being unavailable;
- routing or firewall problems;
- timeout;
- invalid TLS trust;
- hostname mismatch;
- HTTP authentication failure;
- non-success HTTP response; or
- an invalid/empty decision response.

The `failMode` setting controls what happens next.

### Fail open

```json
"failMode": "open"
```

DNS is allowed to continue when the remote policy lookup fails.

The internal decision reason becomes:

```text
policy_unavailable_fail_open
```

This prioritizes DNS availability if Blockinator is offline.

### Fail closed

```json
"failMode": "closed"
```

A failed remote lookup is treated as blocked and the plugin returns **REFUSED**.

The internal decision reason becomes:

```text
policy_unavailable_fail_closed
```

This prioritizes policy enforcement over DNS availability.

## Interaction with Technitium built-in blocking

`bypassBuiltInBlockingOnAllow` controls how an explicit Blockinator ALLOW interacts with Technitium's own blocking features.

### Enabled

```json
"bypassBuiltInBlockingOnAllow": true
```

When Blockinator explicitly allows the request, the plugin reports it as allowed to Technitium's blocking framework so Technitium's built-in blocking does not override the Blockinator result.

### Disabled

```json
"bypassBuiltInBlockingOnAllow": false
```

An ALLOW from Blockinator does not bypass Technitium's built-in blocking. Technitium may still block the request according to its own lists or configuration.

This setting does not change Blockinator BLOCK decisions.

## Block response modes

Blockinator can return a `response_mode` that controls the DNS response generated by the plugin.

### NXDOMAIN

```text
response_mode: nxdomain
```

Returns:

- RCODE: **NXDOMAIN**
- an SOA authority record using `blockAnswerTtl`

This is also the fallback if Blockinator returns an unknown or missing response mode.

### REFUSED

```text
response_mode: refused
```

Returns:

- RCODE: **REFUSED**

### NODATA

```text
response_mode: nodata
```

Returns:

- RCODE: **NOERROR**
- no answer record
- an SOA authority record using `blockAnswerTtl`

### Zero address

```text
response_mode: zero
```

For an A request, the plugin returns:

```text
0.0.0.0
```

For an AAAA request, it returns:

```text
::
```

The synthetic record uses `blockAnswerTtl`.

For query types other than A or AAAA, zero mode falls back to a NODATA-style response with an SOA authority record.

## Startup connectivity probe

During initialization, the plugin derives Blockinator's authenticated ping URL from the configured decision endpoint.

For:

```text
https://blockinator.example.com/api/v1/decision
```

the probe targets:

```text
https://blockinator.example.com/api/v1/ping
```

The same configured API key and TLS settings are used.

Typical log results include:

- **connectivity probe succeeded** — Blockinator is reachable and authentication succeeded.
- **HTTP 401 Unauthorized** — the configured API key is missing, incorrect, disabled, or otherwise rejected.
- **connectivity probe FAILED** — inspect endpoint addressing, routing, firewall, TLS trust, and Blockinator availability.

A startup probe failure is diagnostic; normal per-request behavior is still governed by `failMode`.

## Diagnostic logging

Enable:

```json
"diagnosticLogging": true
```

The plugin then logs:

- each intercepted DNS request;
- client endpoint;
- transport protocol;
- question name/type; and
- Blockinator's returned block state, reason, matched policy target, and matched block list.

When diagnostic logging is disabled, the plugin still logs initialization information, errors, startup-probe results, and the first successful policy decision.

Because per-query diagnostics can be noisy on a busy resolver, enable them only while troubleshooting.

## Testing connectivity manually

From the Technitium host or container, test the Blockinator ping endpoint with the same network path and credentials used by the plugin.

HTTP example:

```bash
curl -i \
  -H 'X-Api-Key: YOUR_KEY' \
  http://BLOCKINATOR:8080/api/v1/ping
```

HTTPS example:

```bash
curl -i \
  -H 'X-Api-Key: YOUR_KEY' \
  https://BLOCKINATOR:8443/api/v1/ping
```

When using a private CA, test with the appropriate CA option for your local `curl` installation rather than disabling TLS verification.

## Building from source

The repository is intentionally flat:

```text
.
├── App.cs
├── RemotePolicyBlockingApp.csproj
├── dnsApp.config
├── build-plugin.sh
├── build-plugin.ps1
├── README.md
├── CHANGELOG.md
└── LICENSE
```

The project targets:

```text
net10.0
```

and references these assemblies from the Technitium installation:

```text
DnsServerCore.ApplicationCommon.dll
TechnitiumLibrary.Net.dll
```

### Linux

Default Technitium path:

```bash
./build-plugin.sh
```

Equivalent explicit path:

```bash
./build-plugin.sh /opt/technitium/dns
```

### Windows

Default path:

```powershell
.\build-plugin.ps1
```

Custom path:

```powershell
.\build-plugin.ps1 -TechnitiumPath "D:\Technitium\DNS Server"
```

Both build scripts use `dotnet publish`.

## Package contents

The build creates:

```text
dist/RemotePolicyBlockingApp.zip
```

The ZIP contains these files at its root:

```text
RemotePolicyBlockingApp.dll
RemotePolicyBlockingApp.deps.json
dnsApp.config
README.md
```

The build scripts validate that `RemotePolicyBlockingApp.deps.json` exists before reporting success.

That dependency file is required for current Technitium app discovery. A package that appears to install but never instantiates the app should be checked for a missing `.deps.json` file first.

## Troubleshooting

### No policy requests reach Blockinator

Check:

- the app is installed and enabled in Technitium;
- the package contains `RemotePolicyBlockingApp.deps.json`;
- `endpoint` points to a location reachable from the Technitium process/container;
- the Blockinator API key is enabled;
- routing and firewall rules allow the connection;
- HTTPS certificate validation is succeeding; and
- Technitium's logs for the startup connectivity probe.

Enable `diagnosticLogging` to confirm that the request-controller stage is intercepting queries.

### HTTP 401 from Blockinator

Verify the configured `apiKey` against **Access & Security** in Blockinator.

The plugin sends the key in `X-Api-Key`.

### HTTPS trust failure

If Blockinator uses a private CA:

1. keep `tlsVerifyServerCertificate` set to `true`;
2. provide the root CA with `tlsCaCertificatePath`; and
3. confirm the certificate hostname matches the hostname in `endpoint`.

Avoid using certificate-verification bypass except for temporary diagnosis.

### Requests time out

Confirm:

- Blockinator is reachable from Technitium;
- `timeoutMs` is appropriate for the network path;
- DNS and TLS resolution for the Blockinator hostname are working; and
- the Blockinator service is healthy.

The default timeout is **250 ms**.

### Built-in Technitium lists still block an allowed request

Set:

```json
"bypassBuiltInBlockingOnAllow": true
```

if Blockinator is intended to be authoritative for allow decisions.

## Version

Current plugin version: **1.3.0**

See [CHANGELOG.md](CHANGELOG.md) for release history.

## License

This project is licensed under the **GNU General Public License v3.0**. See [LICENSE](LICENSE) for the full license text.

# Changelog

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

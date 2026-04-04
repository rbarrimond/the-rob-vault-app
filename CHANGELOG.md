# Changelog

## 0.3.0 - 2026-04-04

### Added in 0.3.0

- Added the `utils` root module to the package metadata during the namespace reorganization.

### Changed in 0.3.0

- Reorganized the codebase into `VaultSentinelPlatform` package namespaces while retaining `function_app.py` as the Azure Functions adapter.
- Updated `static/openapi.yaml` to `info.version: 2.0.0` to reflect the accumulated breaking API-contract changes in that file's git history.

## 0.2.1 - 2026-04-03

### Added in 0.2.1

- Added the `VaultSentinelPlatform.exceptions` module for shared business and platform exception types.

### Changed in 0.2.1

- `VaultSentinelDBAgent` now raises typed platform exceptions for invalid queries and missing runtime dependencies.

## 0.2.0 - 2026-04-03

### Added in 0.2.0

- Introduced the `VaultSentinelPlatform.manifest` package for manifest lifecycle orchestration.
- Added `ManifestBlobStore` for versioned blob persistence of Bungie's native SQLite `.content` manifest.
- Added `ManifestSQLiteQueryService` for typed SQLite lookups by definition type, hash, and name.

### Changed in 0.2.0

- `manifest_cache.py` now acts as a compatibility shim over the new platform manifest module.
- Manifest persistence now stores the raw SQLite database as a versioned blob instead of treating the manifest as a JSON-first artifact.

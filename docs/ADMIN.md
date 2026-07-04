# Admin Capability

The `admin` package compiles an admin panel contract JSON into a runtime shell configuration that host applications use to render an admin UI.

## Status

**Experimental / Preview** — the admin capability is functional but the contract format and shell schema may change in future releases. Do not rely on the output shape for production integrations yet.

## What It Does

The admin package is a **stateless JSON compiler**. It:

1. Parses a host-provided contract JSON payload describing admin sections
2. Normalizes section IDs, titles, descriptions, and capability maps
3. Produces a `Shell` struct that drives the admin panel UI
4. Computes a SHA-256 hash of the contract for change detection

It has **no database dependency** and makes **no network calls**. All state lives in the contract JSON the host provides.

## Usage

### Basic compilation

```go
import "github.com/yourorg/go-platform-kit/admin"

contractJSON := []byte(`{
  "admin": {
    "schemaVersion": "v3",
    "sections": [
      {"id": "overview"},
      {"id": "notifications", "title": "User Notifications"},
      {"id": "billing", "capabilities": {"read": "billing:read", "write": "billing:write"}}
    ],
    "featureFlags": {"darkMode": true}
  }
}`)

shell, err := admin.Compile(contractJSON)
if err != nil {
    // handle invalid JSON
}

// shell.Enabled == true (has sections)
// shell.SchemaVersion == "v3"
// shell.Sections contains normalized sections
// shell.ContractHash == "sha256:..." for cache invalidation
```

### Shell output

```go
type Shell struct {
    Enabled           bool
    Sections          []Section
    AdminCapabilities []string
    AdminSections     []string
    FeatureFlags      map[string]bool
    Targeting         *Targeting
    SchemaVersion     string
    ContractHash      string
}
```

### Section format

Each section in the contract can be either a plain string (section ID) or a full object:

```json
{
  "sections": [
    "overview",
    {"id": "billing", "title": "Billing", "capabilities": {"read": "billing:read"}}
  ]
}
```

Plain strings are expanded into minimal `Section` structs with default titles.

## Schema Compiler

### `admin.Compile(contractRaw json.RawMessage) (Shell, error)`

Primary entry point. Returns an error if the input is not valid JSON.

### `admin.BuildShellFromContract(contractRaw json.RawMessage) Shell`

Legacy entry point. Silently ignores JSON syntax errors. Prefer `Compile` for new code.

### Section normalization

The compiler applies these rules:

1. **Canonical IDs** — section IDs are lowercased and trimmed; `"cron"` becomes `"cron-admin"`
2. **Default definitions** — known sections (`overview`, `notifications`, `billing`, `cron-admin`, `cron-events`) get default titles, descriptions, and capability maps
3. **Override** — contract values override defaults
4. **Deduplication** — duplicate section IDs are silently dropped

## V3 Migration

`admin.MigrateV3` rewrites legacy contract JSON from v2 format to v3:

- Converts `permissions` maps to `capabilities` notation (`admin.billing.read` → `billing:read`)
- Bumps `schemaVersion` to `"v3"`

```go
migrated, changed, err := admin.MigrateV3(oldContractJSON)
```

Returns the migrated JSON, a boolean indicating whether any changes were made, and any parse error.

## Limitations

- **No persistence** — the admin package does not store contracts or shells. Hosts must persist the contract JSON themselves.
- **No validation beyond JSON syntax** — `Compile` checks JSON validity but does not validate section structure or capability format.
- **No RBAC enforcement** — the shell describes what sections exist; authorization is the host's responsibility.
- **Preview contract format** — the contract schema may change. Pin to a specific version if using in production.
- **Built-in section set is small** — only `overview`, `notifications`, `billing`, `cron-admin`, and `cron-events` have default definitions. Custom sections get minimal defaults.

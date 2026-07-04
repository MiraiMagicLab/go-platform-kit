# Versioning

## Policy

This module follows [Semantic Versioning](https://semver.org/).

- **MAJOR**: Breaking change to public API of any top-level package
- **MINOR**: New feature or capability, backward-compatible
- **PATCH**: Bug fix, backward-compatible

## Stability tiers

| Tier | Packages | Guarantee |
|------|----------|-----------|
| Stable | `platform/config`, `platform/log`, `platform/httpx`, `platform/postgres`, `platform/redis`, `platform/health` | No breaking changes within MAJOR version |
| Stable | `platform/mail`, `platform/storage`, `platform/transaction`, `platform/clock`, `platform/id` | No breaking changes within MAJOR version |
| Stable | `auth` public API (`Open`, `Auth` methods, `Option` functions) | No breaking changes within MAJOR version |
| Evolving | `auth/internal/*` | May change in MINOR versions |
| Evolving | `admin` | May change in MINOR versions |
| Experimental | New capabilities under development | May change or be removed |

## What counts as breaking

- Removing or renaming a public function/type/method
- Changing function signature
- Changing behavior of existing API
- Removing a supported config field

## What does NOT count as breaking

- Adding new public functions/types/methods
- Adding new config fields with sensible defaults
- Fixing bugs that change incorrect behavior
- Changes to `internal/` packages

## Recommendations

- Pin to MAJOR version in go.mod: `require github.com/MiraiMagicLab/go-platform-kit v1.x.x`
- Test against MINOR upgrades before deploying
- Check CHANGELOG before upgrading

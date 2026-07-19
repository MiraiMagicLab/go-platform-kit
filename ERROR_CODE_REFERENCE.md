# Error Code Reference — go-platform-kit

> Wire codes live in `platform/errors` and match **Mirai Java `MessageCodes` (`Mxxxx`)**.
> Legacy 7-char `M00CCNNN` values are removed (clean break).
>
> Auth client buckets (Soybean-admin): `M0200` logout · `M0201` refresh · `M0202` modal logout · `M0203` credentials.

## Auth session codes (FE must handle)

| Code | Constant | HTTP | Soybean bucket |
|------|----------|------|----------------|
| `M0200` | `CodeUnauthorized` | 401 | silent logout |
| `M0201` | `CodeAuthTokenExpired` | 401 | refresh+retry (**never** from `/auth/refresh`) |
| `M0202` | Invalid / Revoked / InvalidRefresh | 401 | modal logout |
| `M0203` | `CodeAuthInvalidCredentials` | 401 | login form error |
| `M0251` | `CodeAuthAccountLocked` | 423 | toast (not logout) |
| `M0252` | Banned / email not verified | 403 | modal logout |

See control-plane `docs/AUTH_SESSION_CODES.md`.

## Common codes

| Code | Meaning |
|------|---------|
| `M0000` | Success (CP / Lingo envelope) |
| `S0000000`–`S0000004` | Kit optional success codes for httpx.Success |
| `M0100` | Bad request |
| `M0101` | Validation |
| `M0105` | Rate limited |
| `M0250` | Forbidden |
| `M0300` | Not found |
| `M0301` | Conflict |
| `M0400` | Business rule |
| `M0800` | External / bad gateway |
| `M0900` | Internal |

Kit constant names (MFA, OAuth, register, …) may share these wire codes when no dedicated MessageCode exists.

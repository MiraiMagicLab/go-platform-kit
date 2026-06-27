# Error Code Reference — go-platform-kit

> Canonical reference for the `MPPCCNNN` error code system.  
> Every backend application that imports `go-platform-kit/platform/httpx` MUST follow this specification.

---

## 1. Code Format

```
M  PP  CC  NNN
│  │   │   └─── Sequence (001–999), unique within product+category
│  │   └─────── Category (00–99), functional domain
│  └─────────── Product prefix (00–99), identifies the application
└────────────── Fixed marker ('M' for Message)
```

**Width: 7 characters.** Example: `M0001005` = Platform(00) · Auth(01) · TokenExpired(005)

---

## 2. Product Prefix Allocation

| Prefix | Product | Owner |
|--------|---------|-------|
| `00` | **Platform / Common** | go-platform-kit (shared across ALL products) |
| `01` | **TakoGo** | tako-backend |
| `02` | **AiToEarn** | aitoearn-server |
| `03`–`09` | Reserved | — |
| `10`–`99` | Reserved | Future products / microservices |

**Rule:** Each product owns exactly one prefix. Codes under prefix `00` are defined in go-platform-kit and shared by all products. Codes under any other prefix are defined by the owning product.

---

## 3. Category Allocation — Platform Common (PP = 00)

| CC | Domain | Constant Prefix | Count |
|----|--------|----------------|-------|
| `00` | System / HTTP | `Code*` (BadRequest, Unauthorized, etc.) | 8 |
| `01` | Authentication | `CodeAuth*` | 16 |
| `02` | Session | `CodeSession*` | 2 |
| `03` | RBAC | `CodeRBAC*` | 3 |
| `04` | MFA | `CodeMFA*` | 3 |
| `05` | OAuth | `CodeOAuth*` | 4 |
| `06`–`99` | Reserved | — | — |

---

## 4. Complete Code Table — Platform Common

### System (M0000xxx)

| Code | Constant | HTTP | Message |
|------|----------|------|---------|
| `M0000000` | `CodeUnknownError` | 500 | An unexpected error occurred |
| `M0000001` | `CodeBadRequest` | 400 | Invalid request |
| `M0000002` | `CodeUnauthorized` | 401 | Authentication required |
| `M0000003` | `CodeForbidden` | 403 | Access denied |
| `M0000004` | `CodeNotFound` | 404 | Resource not found |
| `M0000005` | `CodeConflict` | 409 | Resource conflict |
| `M0000006` | `CodeRateLimited` | 429 | Too many requests, please try again later |
| `M0000007` | `CodeInternal` | 500 | Internal server error |

### Auth (M0001xxx)

| Code | Constant | HTTP | Message |
|------|----------|------|---------|
| `M0001001` | `CodeAuthInvalidCredentials` | 401 | Invalid credentials |
| `M0001002` | `CodeAuthInvalidEmail` | 400 | Invalid email format |
| `M0001003` | `CodeAuthInvalidPassword` | 400 | Password must be at least 8 characters |
| `M0001004` | `CodeAuthTokenInvalid` | 401 | Invalid token |
| `M0001005` | `CodeAuthTokenExpired` | 401 | Token expired |
| `M0001006` | `CodeAuthTokenRevoked` | 401 | Token revoked |
| `M0001007` | `CodeAuthInvalidRefresh` | 401 | Invalid refresh token |
| `M0001008` | `CodeAuthEmailNotVerified` | 403 | Email address is not verified |
| `M0001009` | `CodeAuthUserBanned` | 403 | User is temporarily banned |
| `M0001010` | `CodeAuthAccountLocked` | 423 | Account is temporarily locked due to too many failed login attempts |
| `M0001011` | `CodeAuthRegisterFailed` | 500 | Could not register user |
| `M0001012` | `CodeAuthLogoutFailed` | 500 | Could not logout |
| `M0001013` | `CodeAuthPasswordResetFailed` | 500 | Could not reset password |
| `M0001014` | `CodeAuthEmailSendFailed` | 500 | Could not send email |
| `M0001015` | `CodeAuthInvalidActionToken` | 400 | Invalid or expired token |
| `M0001016` | `CodeAuthInvalidMFA` | 400 | Invalid MFA code |

### Session (M0002xxx)

| Code | Constant | HTTP | Message |
|------|----------|------|---------|
| `M0002001` | `CodeSessionNotFound` | 404 | Session not found or already revoked |
| `M0002002` | `CodeSessionNoSIDInToken` | 400 | Operation requires a session-scoped access token |

### RBAC (M0003xxx)

| Code | Constant | HTTP | Message |
|------|----------|------|---------|
| `M0003001` | `CodeRBACCreateRoleFailed` | 500 | Could not create role |
| `M0003002` | `CodeRBACCreatePermissionFailed` | 500 | Could not create permission |
| `M0003003` | `CodeRBACAssignFailed` | 500 | Could not assign |

### MFA (M0004xxx)

| Code | Constant | HTTP | Message |
|------|----------|------|---------|
| `M0004001` | `CodeMFASetupFailed` | 500 | Could not setup MFA |
| `M0004002` | `CodeMFAEnableFailed` | 500 | Could not enable MFA |
| `M0004003` | `CodeMFADisableFailed` | 500 | Could not disable MFA |

### OAuth (M0005xxx)

| Code | Constant | HTTP | Message |
|------|----------|------|---------|
| `M0005001` | `CodeOAuthStateInvalid` | 400 | Invalid OAuth state |
| `M0005002` | `CodeOAuthExchangeFail` | 502 | OAuth exchange failed |
| `M0005003` | `CodeOAuthUserFail` | 500 | OAuth user processing failed |
| `M0005004` | `CodeOAuthNotConfigured` | 501 | OAuth provider is not configured |

---

## 5. How to Use in Host Applications

### 5.1 Import the response package

```go
import "github.com/MiraiMagicLab/go-platform-kit/platform/httpx"
```

### 5.2 Return error responses

```go
// Use platform common codes directly
response.FailCode(c, http.StatusBadRequest, response.CodeBadRequest, nil)
response.FailCode(c, http.StatusUnauthorized, response.CodeUnauthorized, nil)
response.FailCode(c, http.StatusNotFound, response.CodeNotFound, nil)
```

### 5.3 Define domain-specific codes

Each host application defines its own codes under its product prefix:

```go
// internal/platform/errors/codes.go
package errors

const (
    CodeChannelAccountNotFound = "M0100001"  // PP=01 (TakoGo), CC=00 (Channel), NNN=001
    CodeChannelAccountConflict = "M0100002"
)
```

### 5.4 Register domain messages

```go
// internal/platform/errors/messages.go
package errors

import "github.com/MiraiMagicLab/go-platform-kit/platform/httpx"

func RegisterDomainMessages() {
    response.RegisterMessages(map[string]string{
        CodeChannelAccountNotFound: "Account not found",
        CodeChannelAccountConflict: "Account already exists",
    })
}
```

Call `RegisterDomainMessages()` once at startup in `main.go`:

```go
func main() {
    platErr.RegisterDomainMessages()
    // ...
}
```

### 5.5 Resolve messages at runtime

```go
msg := response.DefaultMessage("M0001005") // → "Token expired"
msg := response.DefaultMessage("M0100001") // → "Account not found" (if registered by host)
```

---

## 6. Naming Conventions

### Constant Names

| Pattern | Example | When to use |
|---------|---------|-------------|
| `Code` + Domain + Noun | `CodeAuthInvalidCredentials` | Auth-related errors |
| `Code` + Domain + Noun + Verb | `CodeRBACCreateRoleFailed` | Action failures |
| `Code` + Noun | `CodeBadRequest`, `CodeNotFound` | Generic HTTP errors |
| `Code` + Domain + Noun | `CodeSessionNotFound` | Resource not found |

### Rules

1. **Constant name** = `Code` + PascalCase description
2. **Constant value** = `M` + 2-digit product + 2-digit category + 3-digit sequence
3. **Sequence starts at 001**, increments by 1
4. **Never reuse** a sequence number within a category
5. **Never change** a code's meaning after release — deprecate and allocate a new one
6. **Message** = concise English sentence, no trailing period
7. **HTTP status** = the status code used when this error is returned via `FailCode()`

---

## 7. Adding New Codes — Checklist

When adding a new error code to go-platform-kit:

1. Add the constant to `platform/httpx/codes.go` under the correct category block
2. Add the message to `platform/httpx/messages.go` in the `commonMessages` map
3. Follow the naming convention: `Code` + Domain + Description
4. Use the next available sequence number in the category
5. Run `go build ./...` and `go test ./...`
6. Update this document

When adding a new error code to a host application:

1. Add the constant to `internal/platform/errors/codes.go` under the correct category block
2. Add the message to `internal/platform/errors/messages.go` in the `RegisterDomainMessages()` call
3. Use the product prefix assigned to your application
4. Run build + tests
5. Update the host application's `ERROR_CODE_REFERENCE.md`

---

## 8. Response Envelope

All error responses use this envelope:

```json
{
  "success": false,
  "code": "M0001005",
  "params": null
}
```

Success responses:

```json
{
  "success": true,
  "code": "success",
  "data": { ... }
}
```

The `code` field is always a string. For errors, it is always a 7-character M-code. For success, it is the literal string `"success"`.

---

## 9. Frontend Integration

### TypeScript constants

```typescript
// src/api/response.ts
export const ErrorCodes = {
  UNAUTHORIZED: 'M0000002',
  AUTH_TOKEN_EXPIRED: 'M0001005',
  // ...
} as const
```

### i18n locale files

Each locale file (`api_error.json`) maps M-code → localized message:

```json
{
  "M0000002": "Authentication required",
  "M0001005": "Login session expired"
}
```

### Error handling in API client

```typescript
const translated = directTrans('api_error', data.code)
// → looks up api_error:M0001005 → "Login session expired"
```

---

## 10. Regex Patterns

| Purpose | Pattern |
|---------|---------|
| Validate M-code | `^M\d{7}$` |
| Extract product | `^M(\d{2})\d{5}$` |
| Extract category | `^M\d{2}(\d{2})\d{3}$` |
| Extract sequence | `^M\d{4}(\d{3})$` |
| Grep all codes in codebase | `M\d{7}` |
| Grep platform codes | `M00\d{5}` |
| Grep TakoGo codes | `M01\d{5}` |
| Grep AiToEarn codes | `M02\d{5}` |

# HTTP Conventions

Standard patterns for JSON API responses in Go Platform Kit.

## ApiResponse Envelope

All API responses use a consistent JSON envelope:

```json
{
  "success": true,
  "code": "S0000000",
  "params": null,
  "data": { ... }
}
```

| Field     | Type    | Description |
|-----------|---------|-------------|
| `success` | bool    | `true` for successful operations, `false` for errors |
| `code`    | string  | Stable code for client-side i18n and error handling |
| `params`  | object  | Optional positional or named parameters for message interpolation |
| `data`    | any     | Response payload (present only on success) |

### Success responses

```go
httpx.OK(c, data)           // 200 + CodeSuccess
httpx.Created(c, data)      // 201 + CodeCreated
httpx.Success(c, 200, httpx.CodeSuccess, data, nil) // custom status/code
```

### Error responses

```go
httpx.FailCode(c, 400, httpx.CodeBadRequest, nil)
httpx.FailCodeArgs(c, 400, httpx.CodeBadRequest, "field is required")
httpx.FailNotFound(c)       // 404 + CodeNotFound
httpx.FailStatus(c, 409, params) // derives code from HTTP status
```

## Error Code Convention

Error codes follow the format `M{PP}{CC}{NNN}`:

| Segment | Meaning | Example |
|---------|---------|---------|
| `M`     | Marker prefix (error) | `M` |
| `PP`    | Product (2 digits) | `00` = platform |
| `CC`    | Category (2 digits) | `01` = auth, `02` = session |
| `NNN`   | Sequence (3 digits) | `001` |

Success codes use the `S` prefix with the same structure.

### Built-in code ranges

| Range | Category |
|-------|----------|
| `M0000xxx` | Platform common (bad request, unauthorized, forbidden, not found, conflict, rate limited, internal) |
| `M0001xxx` | Auth (invalid credentials, token errors, email verification, ban, lock, MFA) |
| `M0002xxx` | Session |
| `M0003xxx` | RBAC |
| `M0004xxx` | MFA |
| `M0005xxx` | OAuth |

### Registering custom codes

Host applications can register domain-specific codes at startup:

```go
httpx.RegisterMessages(map[string]string{
    "M0101001": "Invoice not found",
    "M0101002": "Invoice already paid",
})
```

Use `httpx.DefaultMessage(code)` to retrieve the human-readable message for a code.

## Error Mapping

`ErrorMapper` translates domain errors into stable API responses. Define mappers in your capability and chain them in handlers.

### Defining a mapper

```go
func MapInvoiceError(err error) (httpx.MappedError, bool) {
    switch {
    case errors.Is(err, domain.ErrInvoiceNotFound):
        return httpx.MappedError{Status: 404, Code: "M0101001"}, true
    case errors.Is(err, domain.ErrInvoicePaid):
        return httpx.MappedError{Status: 409, Code: "M0101002"}, true
    default:
        return httpx.MappedError{}, false
    }
}
```

### Using mappers in handlers

```go
func (h *Handler) GetInvoice(c *gin.Context) {
    inv, err := h.uc.Get(c.Request.Context(), id)
    if httpx.WriteError(c, err, httpx.CodeInternal, 500, MapInvoiceError) {
        return
    }
    httpx.OK(c, inv)
}
```

`WriteError` runs each mapper in order. The first match writes the response and returns `true`. If no mapper matches, the fallback code is used.

### Chaining multiple mappers

```go
httpx.WriteError(c, err, httpx.CodeInternal, 500,
    auth.MapError,
    MapInvoiceError,
    MapBillingError,
)
```

## Pagination

### Limit/offset

```go
limit, offset := httpx.ParseLimitOffset(c, 20, 100)
// Query: ?limit=10&offset=30

records, total := repo.List(ctx, limit, offset)
httpx.Pagination(c, 200, records, limit, offset, total)
```

Response shape:

```json
{
  "success": true,
  "code": "S0000000",
  "data": {
    "records": [...],
    "pagination": {
      "limit": 10,
      "offset": 30,
      "total": 150
    }
  }
}
```

### Page-based (current/size)

```go
current, size, limit, offset := httpx.ParsePaginationParams(c, 1, 20, 100, 20, 100)
// Query: ?current=2&size=20

records, total := repo.List(ctx, limit, offset)
httpx.PaginateQueryRecord(c, 200, records, current, size, total)
```

### Cursor-based

```go
cursor, limit := httpx.ParseCursor(c, 20, 100)
// Query: ?cursor=abc123&limit=20

records, nextCursor, hasMore := repo.ListAfter(ctx, cursor, limit)
httpx.CursorPagination(c, 200, records, nextCursor, hasMore)
```

Response shape:

```json
{
  "success": true,
  "code": "S0000000",
  "data": {
    "records": [...],
    "pagination": {
      "nextCursor": "opaque_string",
      "hasMore": true
    }
  }
}
```

## Recovery Middleware

`httpx.Recovery()` catches panics and returns a stable `M0000007` (internal error) response instead of crashing the server.

```go
r := gin.Default()
r.Use(httpx.Recovery())
```

The middleware:
1. Defers a `recover()` call for each request
2. On panic, aborts the request and writes `500 + M0000007`
3. Prevents stack traces from leaking to clients

Mount it globally before any route handlers. It works with any Gin router group.

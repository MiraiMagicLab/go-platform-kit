# Migrations

## Where migrations live

| Location | Owner | Purpose |
|----------|-------|---------|
| `migrations/0001_baseline` | go-platform-kit | Auth schema: users, roles, permissions, sessions, refresh_tokens, etc. |
| `{capability}/migrations/` | Capability (if applicable) | Capability-specific schema extensions |
| `{app}/migrations/` | Host app | App-specific tables |

## Running migrations

### Kit baseline

```bash
# Using cmd/migrate in the kit
DATABASE_URL=postgres://... go run ./cmd/migrate

# Or using golang-migrate CLI
migrate -path ./migrations -database "$DATABASE_URL" up
```

### App migrations

```bash
# In the app directory
make migrate-up
make migrate-down
make migrate-create name=create_courses
```

## Order

1. Apply kit baseline first (creates auth tables)
2. Apply app migrations after (creates app-specific tables)

## Adding new migrations to kit

1. Create `{NNNN}_{description}.up.sql` and `.down.sql` in `migrations/`
2. Update `sql/schema.sql` canonical reference
3. Test up and down
4. Document in CHANGELOG

## App migration conventions

- Use sequential numbering: `000001_`, `000002_`, etc.
- Always provide both `.up.sql` and `.down.sql`
- Use `IF NOT EXISTS` / `IF EXISTS` for idempotency
- Add indexes for foreign keys and common query patterns
- Document table purpose in SQL comments

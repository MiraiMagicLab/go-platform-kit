// Package auth provides authentication, authorization, session management,
// MFA, OAuth, and RBAC as an embeddable capability module.
//
// # Quick start
//
// Open shared infra from [platform/config], then wire auth:
//
//	infra, _ := config.Load(config.FromEnv())
//	pg, _ := postgres.Open(ctx, infra.Infra.Postgres)
//	rdb, _ := redis.Open(ctx, infra.Infra.Redis)
//
//	mod, err := auth.New(ctx,
//	    auth.WithConfig(cfg),
//	    auth.WithPostgres(pg),
//	    auth.WithRedis(rdb),
//	    auth.WithLogger(logger),
//	)
//	mod.MountAll(r.Group("/auth"))
//
// Protect host routes with mod.AuthMiddleware() and mod.RequirePermission("posts:write").
//
// # Public layout
//
//	auth/doc.go, module.go, option.go, config.go — entry point and wiring
//	auth/mount.go       — route mounting
//	auth/middleware.go  — JWT, RBAC, team-token helpers
//	auth/domain.go      — domain types and errors
//	auth/ports.go       — repository interfaces for tests and extensions
//	auth/token.go       — JWT manager re-exports
//
// # Internal layout (auth/internal)
//
//	domain/    — entities and domain errors
//	ports/     — repository and cache interfaces
//	usecase/   — one folder per use case (login, session, rbac, …)
//	http/      — Gin handlers and middleware
//	postgres/  — SQL repository implementations
//	redis/     — permission cache and token denylist
//	security/  — crypto helpers and JWT
//	validate/  — input validation and cookie helpers
//
// Email transport uses [platform/mail]; auth/usecase/email owns verify/reset flows.
//
// Package names match their directory names. Capabilities never import each other.
package auth

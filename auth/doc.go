// Package auth provides headless authentication, authorization, session management,
// MFA, OAuth, and RBAC for Go backend services.
//
// # Quick start
//
// Open shared infra, wire auth, then call use-case methods from host HTTP handlers:
//
//	a, _ := auth.Open(ctx,
//	    auth.WithConfig(cfg),
//	    auth.WithPostgres(pg),
//	    auth.WithRedis(rdb),
//	)
//
//	r.POST("/v1/sign-in", func(c *gin.Context) {
//	    res, err := a.Login(c.Request.Context(), email, password, auth.ClientMeta{IP: c.ClientIP(), UA: c.Request.UserAgent()})
//	    if auth.WriteError(c, err, httpx.CodeAuthInvalidCredentials, 401) {
//	        return
//	    }
//	    httpx.Success(c, 200, "success", res, nil)
//	})
//
//	api := r.Group("/api")
//	api.Use(a.JWTAuth())
//	api.GET("/posts", a.RequirePermission("posts:read"), listPosts)
//
// Optional reference routes: import auth/gin and call authgin.MountAll(a, r).
package auth

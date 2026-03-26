package config

import (
	"errors"
	"os"
	"time"
)

type Config struct {
	HTTPAddr            string
	DatabaseURL         string
	RedisURL            string
	JWTAccessSecret     string
	JWTRefreshSecret    string
	AccessTokenTTL      time.Duration
	RefreshTokenTTL     time.Duration
	PermissionsCacheTTL time.Duration
}

func Load() (Config, error) {
	c := Config{
		HTTPAddr:            getEnv("HTTP_ADDR", ":8080"),
		DatabaseURL:         os.Getenv("DATABASE_URL"),
		RedisURL:            os.Getenv("REDIS_URL"),
		JWTAccessSecret:     os.Getenv("JWT_ACCESS_SECRET"),
		JWTRefreshSecret:    os.Getenv("JWT_REFRESH_SECRET"),
		AccessTokenTTL:      mustParseDuration(getEnv("ACCESS_TOKEN_TTL", "15m")),
		RefreshTokenTTL:     mustParseDuration(getEnv("REFRESH_TOKEN_TTL", "720h")),
		PermissionsCacheTTL: mustParseDuration(getEnv("PERMISSIONS_CACHE_TTL", "30s")),
	}

	if c.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}
	if c.JWTAccessSecret == "" {
		return Config{}, errors.New("JWT_ACCESS_SECRET is required")
	}
	if c.JWTRefreshSecret == "" {
		return Config{}, errors.New("JWT_REFRESH_SECRET is required")
	}

	return c, nil
}

func getEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func mustParseDuration(v string) time.Duration {
	d, err := time.ParseDuration(v)
	if err != nil {
		panic(err)
	}
	return d
}

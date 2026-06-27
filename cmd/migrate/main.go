// Command migrate applies SQL migrations from the migrations/ directory.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/MiraiMagicLab/go-platform-kit/platform/config"
	"github.com/MiraiMagicLab/go-platform-kit/platform/postgres"
)

func main() {
	ctx := context.Background()
	cfg, err := config.Load(config.FromEnv())
	if err != nil {
		log.Fatal(err)
	}
	if !cfg.Infra.Postgres.IsConfigured() {
		log.Fatal("DATABASE_URL is required")
	}

	pg, err := postgres.Open(ctx, cfg.Infra.Postgres)
	if err != nil {
		log.Fatal(err)
	}
	defer pg.Close()

	table := getenv("MIGRATIONS_TABLE", "schema_migrations")
	if _, err := pg.Exec(ctx, fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			filename TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`, table)); err != nil {
		log.Fatal(err)
	}

	migDir := getenv("MIGRATIONS_DIR", "migrations")
	files, err := filepath.Glob(filepath.Join(migDir, "*.up.sql"))
	if err != nil {
		log.Fatal(err)
	}
	sort.Strings(files)

	for _, f := range files {
		var applied bool
		q := fmt.Sprintf(`SELECT EXISTS(SELECT 1 FROM %s WHERE filename = $1)`, table)
		if err := pg.QueryRow(ctx, q, filepath.Base(f)).Scan(&applied); err != nil {
			log.Fatal(err)
		}
		if applied {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("apply %s", filepath.Base(f))
		if _, err := pg.Exec(ctx, string(b)); err != nil {
			log.Fatalf("migration %s failed: %v", filepath.Base(f), err)
		}
		ins := fmt.Sprintf(`INSERT INTO %s (filename) VALUES ($1)`, table)
		if _, err := pg.Exec(ctx, ins, filepath.Base(f)); err != nil {
			log.Fatal(err)
		}
	}

	fmt.Println("migrations applied")
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	ctx := context.Background()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL is required")
	}
	pg, err := pgxpool.New(ctx, dbURL)
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

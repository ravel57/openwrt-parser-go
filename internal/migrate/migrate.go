package migrate

import (
	"database/sql"
	"embed"
	"fmt"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

func Up(sqliteDSN string) error {
	if sqliteDSN == "" {
		return fmt.Errorf("APP_SQLITE_DSN is empty")
	}
	db, err := sql.Open("sqlite", sqliteDSN)
	if err != nil {
		return err
	}
	defer db.Close()

	sqlBytes, err := migrationsFS.ReadFile("migrations/0001_init.up.sql")
	if err != nil {
		return err
	}
	if _, err := db.Exec(string(sqlBytes)); err != nil {
		return fmt.Errorf("apply SQLite migration: %w", err)
	}
	return nil
}

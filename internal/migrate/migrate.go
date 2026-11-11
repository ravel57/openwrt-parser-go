package migrate

import (
	"database/sql"
	"embed"
	"fmt"
	"sort"

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

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return err
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		sqlBytes, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		if _, err := db.Exec(string(sqlBytes)); err != nil {
			return fmt.Errorf("apply SQLite migration %s: %w", name, err)
		}
	}
	return nil
}

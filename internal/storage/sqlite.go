package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"openwrt-parser-go/internal/domain"

	_ "modernc.org/sqlite"
)

type Sqlite struct {
	db *sql.DB
}

// dsn для SQLite, примеры:
//
//	file:app.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)
//	./app.db
func New(ctx context.Context, dsn string) (*Sqlite, error) {
	if dsn == "" {
		// чтобы не ломать существующую переменную окружения, оставляем текст ошибки совместимым
		return nil, errors.New("APP_SQLITE_DSN is empty")
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}

	// базовые настройки на конкуренцию/блокировки
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	// проверка соединения
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}

	// полезные pragmas (безопасно, даже если уже выставлены в DSN)
	_, _ = db.ExecContext(ctx, `PRAGMA journal_mode=WAL;`)
	_, _ = db.ExecContext(ctx, `PRAGMA foreign_keys=ON;`)
	_, _ = db.ExecContext(ctx, `PRAGMA busy_timeout=5000;`)

	return &Sqlite{db: db}, nil
}

func (p *Sqlite) Close() { _ = p.db.Close() }

func (p *Sqlite) SaveAll(ctx context.Context, items []domain.Connection) error {
	if len(items) == 0 {
		return nil
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		insert into connections (src_ip, dst_ip, dst_dns, host_name, created_at)
		values (?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, it := range items {
		if _, err := stmt.ExecContext(ctx, it.SrcIP, it.DstIP, it.DstDNS, it.HostName, now); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (p *Sqlite) FindByDstDNSLike(ctx context.Context, q string) ([]domain.Connection, error) {
	// Sqlite DISTINCT ON (dst_ip) -> SQLite row_number() over(partition by dst_ip ...)
	rows, err := p.db.QueryContext(ctx, `
		select src_ip, dst_ip, dst_dns, host_name, created_at
		from (
			select src_ip, dst_ip, dst_dns, host_name, created_at,
				   row_number() over (partition by dst_ip order by created_at desc) as rn
			from connections
			where lower(dst_dns) like '%' || lower(?) || '%'
		)
		where rn = 1
		order by dst_ip
	`, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.Connection
	for rows.Next() {
		var c domain.Connection
		var createdAt string
		if err := rows.Scan(&c.SrcIP, &c.DstIP, &c.DstDNS, &c.HostName, &createdAt); err != nil {
			return nil, err
		}
		c.CreatedAt = createdAt
		out = append(out, c)
	}
	return out, rows.Err()
}

type DomainCount struct {
	DstDNS    string
	Count     int64
	UpdatedAt string `json:"updatedAt,omitempty"`
}

type DstCount struct {
	DstIP     string
	DstDNS    string
	Count     int64
	UpdatedAt string `json:"updatedAt,omitempty"`
}

func (p *Sqlite) UpsertDomainCounts(ctx context.Context, counts []DomainCount) error {
	if len(counts) == 0 {
		return nil
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		insert into domain_conn_counts (dst_dns, active_connections, updated_at)
		values (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
		on conflict(dst_dns) do update set
			active_connections = excluded.active_connections,
			updated_at = excluded.updated_at
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, c := range counts {
		if _, err := stmt.ExecContext(ctx, c.DstDNS, c.Count); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (p *Sqlite) FindDomainCountsLike(ctx context.Context, q string) ([]DomainCount, error) {
	rows, err := p.db.QueryContext(ctx, `
		select dst_dns, active_connections, updated_at
		  from domain_conn_counts
		 where lower(dst_dns) like '%' || lower(?) || '%'
		 order by active_connections desc
	`, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DomainCount
	for rows.Next() {
		var dc DomainCount
		if err := rows.Scan(&dc.DstDNS, &dc.Count, &dc.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, dc)
	}
	return out, rows.Err()
}

func (p *Sqlite) UpsertDstCounts(ctx context.Context, counts []DstCount) error {
	if len(counts) == 0 {
		return nil
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		insert into dst_conn_counts (dst_ip, dst_dns, active_connections, updated_at)
		values (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
		on conflict(dst_ip, dst_dns) do update set
			active_connections = excluded.active_connections,
			updated_at = excluded.updated_at
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, c := range counts {
		if _, err := stmt.ExecContext(ctx, c.DstIP, c.DstDNS, c.Count); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (p *Sqlite) FindDstCountsLike(ctx context.Context, q string) ([]DstCount, error) {
	rows, err := p.db.QueryContext(ctx, `
		select dst_ip, dst_dns, active_connections, updated_at
		  from dst_conn_counts
		 where lower(dst_dns) like '%' || lower(?) || '%'
		 order by active_connections desc
	`, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DstCount
	for rows.Next() {
		var dc DstCount
		if err := rows.Scan(&dc.DstIP, &dc.DstDNS, &dc.Count, &dc.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, dc)
	}
	return out, rows.Err()
}

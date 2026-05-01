package storage

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DBTX is the common interface satisfied by both *pgxpool.Pool and pgx.Tx,
// allowing store methods to run inside or outside a transaction.
type DBTX interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, arguments ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, arguments ...any) pgx.Row
}

// DB provides read/write connection pool splitting for production deployments
// with PostgreSQL streaming replicas. If DATABASE_READ_URL is set, read queries
// are routed to the read replica; otherwise, all queries go to the primary.
type DB struct {
	Pool     *pgxpool.Pool // Primary (read/write)
	ReadPool *pgxpool.Pool // Read replica (nil if not configured)
}

// Reader returns the read-replica pool if available, otherwise the primary.
// Use this for SELECT queries that don't need strong consistency.
func (db *DB) Reader() *pgxpool.Pool {
	if db.ReadPool != nil {
		return db.ReadPool
	}
	return db.Pool
}

func NewDB(ctx context.Context, connURL string) (*DB, error) {
	pool, err := newPool(ctx, connURL)
	if err != nil {
		return nil, fmt.Errorf("primary pool: %w", err)
	}

	db := &DB{Pool: pool}

	// If DATABASE_READ_URL is set, create a separate pool for read replicas.
	// This routes read queries to the local PostgreSQL standby (zero network latency)
	// while writes go to the primary on the DB server.
	if readURL := os.Getenv("DATABASE_READ_URL"); readURL != "" {
		readPool, err := newPool(ctx, readURL)
		if err != nil {
			pool.Close()
			return nil, fmt.Errorf("read replica pool: %w", err)
		}
		db.ReadPool = readPool
	}

	return db, nil
}

func newPool(ctx context.Context, connURL string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(connURL)
	if err != nil {
		return nil, fmt.Errorf("parse pool config: %w", err)
	}

	// Warn if TLS is not configured — production databases must use encrypted connections.
	if config.ConnConfig.TLSConfig == nil {
		slog.Warn("database connection has no TLS configured (sslmode=disable) — this is unsafe for production")
	}

	config.MaxConns = int32(envIntOr("DB_MAX_CONNS", 25))
	config.MinConns = int32(envIntOr("DB_MIN_CONNS", 5))
	config.MaxConnLifetime = 30 * time.Minute
	config.MaxConnIdleTime = 5 * time.Minute
	config.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return pool, nil
}

func (db *DB) Close() {
	db.Pool.Close()
	if db.ReadPool != nil {
		db.ReadPool.Close()
	}
}

func envIntOr(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

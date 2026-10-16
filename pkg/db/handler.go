package db

import (
	"context"
	"database/sql"
)

type ctxKey struct{}

type RollbackFunc func() error

type CommitFunc func() error

type Handler interface {
	WithAtomicTx(context.Context) (context.Context, RollbackFunc, CommitFunc, error)
}

// sql handler implementation

var sqlTxKey ctxKey

type Queryable interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type sqlDBHandler struct {
	db   *sql.DB
	tx   *sql.Tx
	opts *sql.TxOptions
}

func SqlDBHandler(db *sql.DB, opts *sql.TxOptions) Handler {
	return &sqlDBHandler{db: db, opts: opts}
}

func (sa sqlDBHandler) WithAtomicTx(ctx context.Context) (context.Context, RollbackFunc, CommitFunc, error) {
	tx, err := sa.db.BeginTx(ctx, sa.opts)
	if err != nil {
		return nil, nil, nil, nil
	}
	r := func() error { return tx.Rollback() }
	c := func() error { return tx.Commit() }
	ctx = context.WithValue(ctx, sqlTxKey, tx)
	return ctx, r, c, nil
}

func QueryableFromContext(ctx context.Context, fallback *sql.DB) Queryable {
	tx, ok := ctx.Value(sqlTxKey).(*sql.Tx)
	if !ok {
		return fallback
	}
	return tx
}

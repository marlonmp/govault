package repos

import (
	"context"
	"database/sql"
)

type ctxKey struct{}

type RollbackFunc func() error

type CommitFunc func() error

type Transactioner interface {
	WithContext(context.Context) (context.Context, RollbackFunc, CommitFunc, error)
}

// sql transactioner implementation

var sqlTxKey ctxKey

type SqlQueryAble interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type sqlTransaction struct {
	db   *sql.DB
	tx   *sql.Tx
	opts *sql.TxOptions
}

func SqlTransaction(db *sql.DB, opts *sql.TxOptions) Transactioner {
	return &sqlTransaction{db: db, opts: opts}
}

func (sa sqlTransaction) WithContext(ctx context.Context) (context.Context, RollbackFunc, CommitFunc, error) {
	tx, err := sa.db.BeginTx(ctx, sa.opts)
	if err != nil {
		return nil, nil, nil, nil
	}
	r := func() error { return tx.Rollback() }
	c := func() error { return tx.Commit() }
	ctx = context.WithValue(ctx, sqlTxKey, tx)
	return ctx, r, c, nil
}

func GetSqlQueryAbleFromContext(ctx context.Context, fallback *sql.DB) SqlQueryAble {
	tx, ok := ctx.Value(sqlTxKey).(*sql.Tx)
	if !ok {
		return fallback
	}
	return tx
}

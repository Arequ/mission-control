package store

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// ErrConflict is a unique or foreign-key violation.
var ErrConflict = errors.New("conflict")

// ErrForbidden means the caller does not own the resource.
var ErrForbidden = errors.New("forbidden")

// ErrEnrollRejected means the enroll secret did not match an enabled secret.
var ErrEnrollRejected = errors.New("enroll secret rejected")

// ErrStaleReport means a check-in is older than the stored run, outside clock skew.
var ErrStaleReport = errors.New("stale report")

// ErrIdempotencyReuse means an idempotency key was reused with a different body.
var ErrIdempotencyReuse = errors.New("idempotency key reused")

// ValidationError is a rejected request.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(msg string) error { return &ValidationError{Msg: msg} }

func mapWriteErr(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return fmt.Errorf("%w: %s", ErrConflict, pgErr.ConstraintName)
		case "23503":
			return fmt.Errorf("%w: %s", ErrConflict, pgErr.Message)
		case "23514":
			return fmt.Errorf("%w: %s", ErrConflict, pgErr.Message)
		}
	}
	return err
}

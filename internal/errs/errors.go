package errs

import (
	"github.com/google/uuid"
)

type ErrorCode string

const (
	MalformedRequestErrorCode      ErrorCode = "malformed_request"
	InvalidRequestErrorCode        ErrorCode = "invalid_request"
	InvalidAuthenticationErrorCode ErrorCode = "authentication_failed"
	NotAuthorizedErrorCode         ErrorCode = "not_authorized"
	ForbbidenErrorCode             ErrorCode = "forbbiden"
	NotFoundErrorCode              ErrorCode = "not_found"
	ConflictErrorCode              ErrorCode = "conflict"
	SourceGoneErrorCode            ErrorCode = "source_gone"
	MalformedContentErrorCode      ErrorCode = "malformed_content"
	ResourseLockedErrorCode        ErrorCode = "source_locked"
	InternalErrorCode              ErrorCode = "internal_error"
	UnknownErrorCode               ErrorCode = "unknown_error"
	NotImplementedErrorCode        ErrorCode = "not_implemented"
	ServiceUnavaliableErrorCode    ErrorCode = "service_unavailable"
	TimeoutErrorCode               ErrorCode = "timeout"
)

type AppErrorItem struct {
	Code    string
	Path    string
	Message string
}

type appError struct {
	id      uuid.UUID
	code    ErrorCode
	title   string
	message string
	errors  []AppErrorItem
	err     error
}

func (ae *appError) ID() uuid.UUID {
	return ae.id
}

func (ae *appError) Code() ErrorCode {
	return ae.code
}

func (ae *appError) Error() string {
	return ae.message
}

func (ae *appError) Unwrap() error {
	return ae.err
}

func (ae *appError) Is(target error) bool {
	t, ok := target.(*appError)
	if !ok {
		return false
	}
	if t.code != ae.code {
		return false
	}
	return true
}

func (ae *appError) As(target any) bool {
	t, ok := target.(**appError)
	if !ok {
		return false
	}
	*t = ae
	return true
}

func ValidationError(title, message string, errors ...AppErrorItem) error {
	return &appError{
		id:      uuid.New(),
		code:    InvalidRequestErrorCode,
		title:   title,
		message: message,
		errors:  errors,
		err:     nil,
	}
}

func ConflictError(message string, err error, errors ...AppErrorItem) error {
	return &appError{
		id:      uuid.New(),
		code:    ConflictErrorCode,
		title:   "there is a contflict",
		message: message,
		errors:  errors,
		err:     err,
	}
}

func NotFoundError(message string) error {
	return &appError{
		id:      uuid.New(),
		code:    NotFoundErrorCode,
		title:   "entry not found or does not exist",
		errors:  nil,
		err:     nil,
	}
}


func UnknownError(err error) error {
	return &appError{
		id:      uuid.New(),
		code:    UnknownErrorCode,
		title:   "unknown error",
		message: "there was an unknown error trying to process this operation, please try again later",
		errors:  nil,
		err:     err,
	}
}

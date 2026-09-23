package errs

import (
	"errors"

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
	NotImplementedErrorCode        ErrorCode = "not_implemented"
	ServiceUnavaliableErrorCode    ErrorCode = "service_unavailable"
	TimeoutErrorCode               ErrorCode = "timeout"
)

type ServiceErrorItem struct {
	Code    string
	Path    string
	Message string
}

type serviceError struct {
	id      uuid.UUID
	code    ErrorCode
	title   string
	message string
	errors  []ServiceErrorItem
	err error
}

func (se *serviceError) ID() uuid.UUID {
	return se.id
}

func (se *serviceError) Code() ErrorCode {
	return se.code
}

func (se *serviceError) Error() string {
	return se.message
}

func (se *serviceError) Unwrap() error {
	return se.err
}

func (se *serviceError) Is(target error) bool {
	t, ok := target.(*serviceError)
	if !ok {
		return false
	}
	if t.code != se.code {
		return false
	}
	return true
}

func (se *serviceError) As(target any) bool {
	t, ok := target.(**serviceError)
	if !ok {
		return false
	}
	*t = se
	return true
}

func IsServiceError(err error) bool {
	var se *serviceError
	return errors.Is(err, se)
}

func ValidationError(title, message string, errors []ServiceErrorItem) error {
	return &serviceError{
		id: uuid.New(),
		code: InvalidRequestErrorCode,
		title: title,
		message: message,
		errors: errors,
		err: nil,
	}
}

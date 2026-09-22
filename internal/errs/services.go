package errs

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

type ServiceError struct {
	code ErrorCode
	message string
	data map[string]any
}

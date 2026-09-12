package val

type ErrorCode string

type ErrorFormat string

const (
	TooBigCode        ErrorCode = "too_big"
	TooSmallCode      ErrorCode = "too_small"
	InvalidFormatCode ErrorCode = "invalid_format"
	InvalidTypeCode   ErrorCode = "invalid_type"

	UUIDFormat         ErrorFormat = "uuid"
	EmailFormat        ErrorFormat = "email"
	NumericFormat      ErrorFormat = "numeric"
	AlphanumericFormat ErrorFormat = "alphanumeric"
	RegexFormat        ErrorFormat = "regex"
	StartsWithFormat   ErrorFormat = "starts_with"
	EdnsWithFormat     ErrorFormat = "ends_with"
	IncludesFormat     ErrorFormat = "includes"
)

type stringError struct {
	code    ErrorCode
	path    []string
	format  ErrorFormat
	min     *int
	max     *int
	pattern string
}

func (se *stringError) Error() string {
	return string(se.code)
}

func (se *stringError) Code() ErrorCode {
	return se.code
}

func (se *stringError) Path() []string {
	path := make([]string, len(se.path))
	copy(path, se.path)
	return path
}

func (se *stringError) Format() *ErrorFormat {
	return se.format
}

func (se *stringError) Min() *int {
	return se.min
}

func (se *stringError) Max() *int {
	return se.max
}

func (se *stringError) Pattern() *string {
	return se.pattern
}

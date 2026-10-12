package vals

import (
	"github.com/marlonmp/govault/pkg/errs"
)

type ErrorContext interface {
	AddErrors(e ...errs.AppErrorItem) ErrorContext
	Extend(name string) ErrorContext
	GetError(title, message string) error
}

type errorContext struct {
	parent *errorContext
	path   string
	errors []errs.AppErrorItem
}

func (c *errorContext) addChildErrors(e ...errs.AppErrorItem) ErrorContext {
	if len(e) == 0 {
		return c
	}
	if c.errors == nil {
		c.errors = make([]errs.AppErrorItem, 0)
	}
	c.errors = append(c.errors, e...)
	return c
}

func (c *errorContext) AddErrors(e ...errs.AppErrorItem) ErrorContext {
	if len(e) == 0 {
		return c
	}
	for _, item := range e {
		item.Path = c.path + "/" + item.Path
	}
	if c.parent != nil {
		c.parent.addChildErrors(e...)
	}
	if c.errors == nil {
		c.errors = make([]errs.AppErrorItem, 0)
	}
	c.errors = append(c.errors, e...)
	return c
}

func (c *errorContext) Extend(name string) ErrorContext {
	return &errorContext{path: c.path + "/" + name}
}

func (c *errorContext) GetError(title, message string) error {
	if len(c.errors) > 0 {
		return errs.ValidationError(title, message, c.errors...)
	}
	return nil
}

func NewErrorContext(path string) ErrorContext {
	return &errorContext{path: path}
}

// validators

func ValidateNickname(value string, vctx ErrorContext) string {
	if len(value) < 3 || len(value) > 32 {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_length",
			Path:    "nickname",
			Message: "this field must have a minimum length of 3 and a maximum of 32",
		})
	}
	return value
}

func ValidateEmail(value string, vctx ErrorContext) string {
	value = NormalizeEmail(value)
	if len(value) < 6 || len(value) > 128 {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_length",
			Path:    "email",
			Message: "this field must have a minimum length of 6 and a maximum of 128",
		})
	}
	if IsValidEmail(value) {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_format",
			Path:    "email",
			Message: "this field is not a valid email",
		})
	}
	return value
}

func ValidateOTP(value string, vctx ErrorContext) string {
	if len(value) == 6 {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_length",
			Path:    "otp",
			Message: "this field must have a length of 6",
		})
	}
	return value
}

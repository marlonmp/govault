package val

import (
	"reflect"
	"regexp"
	"strings"

	"golang.org/x/text/unicode/norm"
)

type stringCheck func(val string) (string, error)

type StringFieldContext struct {
	path []string
	errors []stringError
}

func (sc *stringCheck) AddError()

type stringField struct {
	kind       reflect.Kind
	checks     []stringCheck
	allowBlank bool
}

func String() *stringField {
	return &stringField{kind: reflect.String, allowBlank: false}
}

func (spf *stringField) Kind() reflect.Kind {
	return spf.kind
}

func (spf *stringField) AddCheck(check stringCheck) *stringField {
	if spf.checks == nil {
		spf.checks = make([]stringCheck, 0)
	}
	spf.checks = append(spf.checks, check)
	return spf
}

// validators

func (spf *stringField) Min(min int) *stringField {
	return spf.AddCheck(func(val string) (string, error) {
		if len(val) < min {
			return val, &stringError{code: TooSmallCode, min: &min}
		}
		return val, nil
	})
}

func (spf *stringField) Max(max int) *stringField {
	return spf.AddCheck(func(val string) (string, error) {
		if len(val) > max {
			return val, &stringError{code: TooBigCode, max: &max}
		}
		return val, nil
	})
}

func (spf *stringField) Rage(min, max int) *stringField {
	return spf.Min(min).Max(max)
}

func (spf *stringField) Len(l int) *stringField {
	return spf.Rage(l, l)
}

func (spf *stringField) regex(exp string, base *stringError) *stringField {
	re := regexp.MustCompile(exp)
	return spf.AddCheck(func(val string) (string, error) {
		if !re.MatchString(val) {
			if base == nil {
				base = &stringError{code: InvalidFormatCode, format: RegexFormat, pattern: exp}
			}
			return val, base
		}
		return val, nil
	})
}

func (spf *stringField) Regex(exp string) *stringField {
	return spf.regex(exp, nil)
}

func (spf *stringField) Email() *stringField {
	exp := `^(?!\.)(?!.*\.\.)([a-z0-9_'+\-\.]*)[a-z0-9_+-]@([a-z0-9][a-z0-9\-]*\.)+[a-z]{2,}$`
	return spf.regex(exp, &stringError{code: InvalidFormatCode, format: EmailFormat, pattern: exp})
}

func (spf *stringField) StrictEmail() *stringField {
	return spf.
		// normalize email
		AddCheck(func(val string) (string, error) {
			val = strings.ToLower(val)
			val = norm.NFKC.String(val)
			val = strings.Map(func(r rune) rune {
				switch r {
				case '\r', '\n', '\t', '\b', '\x00':
					return -1
				}
				return r
			}, val)
			return val, nil
		}).
		// validate email
		Email()
}

func (spf *stringField) Optional() *stringField {
	spf.allowBlank = true
	return spf
}

func (spf *stringField) Required() *stringField {
	spf.allowBlank = false
	return spf
}

// transformers

func (spf *stringField) Trim() *stringField {
	return spf.AddCheck(func(val string) (string, error) {
		return strings.TrimSpace(val), nil
	})
}

func (spf *stringField) ToLower() *stringField {
	return spf.AddCheck(func(val string) (string, error) {
		return strings.ToLower(val), nil
	})
}

func (spf *stringField) ToUpper() *stringField {
	return spf.AddCheck(func(val string) (string, error) {
		return strings.ToUpper(val), nil
	})
}

// parsers

func (spf *stringField) Parse(v string) (string, error) {
	if v == "" && spf.allowBlank {
		return "", nil
	}
	var err error
	errors := make([]error, 0)
	value := v
	for i := range spf.checks {
		value, err = spf.checks[i](value)
		if err != nil {
			errors = append(errors, err)
		}
	}
	return value, errors
}

func (spf *stringField) IsValid(v string) bool {
	if v == "" && spf.allowBlank {
		return true
	}
	return spf.field.IsValid(v)
}

// string pointer

type stringPtrCheck func(val *string) (*string, error)

type stringPtrField struct {
	*stringField
	kind reflect.Kind
	checks []stringPtrCheck
	allowBlank bool
	allowNil bool
}

func StringPtr() *stringPtrField {
	return &stringPtrField{}
}

func (spf *stringPtrField) Kind() reflect.Kind {
	return spf.kind
}

func (spf *stringPtrField) ElemKind() reflect.Kind {
	return spf.stringField.Kind()
}

func (spf *stringPtrField) AddCheck(check stringPtrCheck) *stringPtrField {
	if spf.checks == nil {
		spf.checks = make([]stringPtrCheck, 0)
	}
	spf.checks = append(spf.checks, check)
	return spf
}

// parsers

func (spf *stringPtrField) Parse(v *string) (*string, error) {
	if v == nil && spf.allowNil {
		return nil, nil
	}
	var err error
	*v, err = spf.stringField.Parse(*v)
	return v, err
}

func (spf *stringPtrField) Check(v *string) error {
	if v == nil && spf.allowNil {
		return nil
	}
	return spf.stringField.Check(*v)
}

func (spf *stringPtrField) IsValid(v *string) bool {
	if v == nil && spf.allowNil {
		return true
	}
	return spf.stringField.IsValid(*v)
}

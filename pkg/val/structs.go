package val

import "reflect"

type StructCheck func(v any) (any, error)

type structField struct {
	kind reflect.Kind
	checks StructCheck
}

func Struct() *structField {
	return &structField{kind: reflect.Struct}
}

package val

import "reflect"

type CheckFn[T any] func(v T) (T, error)

type field[T any] struct {
	kind     reflect.Kind
	checks   CheckFn[T]
}

func (f *field[T]) Kind() reflect.Kind {
	return f.kind
}

func (f *field[T]) AddCheck(c CheckFn[T]) *field[T] {
	return f
}

func (f *field[T]) Parse(v T) (T, error) {
	return v, nil
}

func (f *field[T]) Check(v T) error {
	return nil
}

func (f *field[T]) IsValid(v T) bool {
	return false
}

package val

import "encoding/json"


type schemaError map[string][]string

func (se *schemaError) Error() string {
	msg, _ := json.Marshal(se)
	if len(msg) == 0 {
		return "{}"
	}
	return string(msg)
}

type schemaField struct {
	name string
	field stringField
}

type schema struct {
	fields []schemaField
}

type S map[string]stringField

func NewSchema(schema_ S) schema {
	items := make([]schemaField, 0)
	for k, v := range schema_ {
		items = append(items, schemaField{name: k, field: v})
	}
	return schema{fields: items}
}

func (mf schema) RefChekcFirst() map[string][]string {
	msgs := make(map[string][]string)
	for _, item := range mf.fields {
		msg := item.field.RefChekcFirst()
		if len(msg) > 0 {
			msgs[item.name] = []string{msg}
		}
	}
	return msgs
}

func (mf schema) RefChekcAll() map[string][]string {
	msgs := make(map[string][]string)
	for _, item := range mf.fields {
		msg := item.field.RefChekcAll()
		if len(msg) > 0 {
			msgs[item.name] = msg
		}
	}
	return msgs
}

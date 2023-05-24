package redact

import (
	"errors"
	"reflect"
)

const (
	tagName        = "redact"
	nonSecret      = "nonsecret"
	RedactStrConst = "REDACTED"
)

type redactor func(string) string

var redactors = map[string]redactor{}

// AddRedactor allows for adding custom functionality based on tag values
func AddRedactor(key string, r redactor) {
	redactors[key] = r
}

// Redact redacts all strings without the nonsecret tag
func Redact(iface interface{}) error {
	ifv := reflect.ValueOf(iface)
	if ifv.Kind() != reflect.Ptr {
		return errors.New("Not a pointer")
	}

	redact(reflect.Indirect(ifv), nonSecret)
	return nil
}

func redact(v reflect.Value, tag string) {
	switch v.Kind() {
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			redact(v.Index(i), tag)
		}

	case reflect.Interface, reflect.Pointer:
		if !v.IsNil() {
			redact(v.Elem(), tag)
		}

	case reflect.Map:
		if !v.IsNil() {
			for _, key := range v.MapKeys() {
				val := reflect.New(v.Type().Elem()).Elem()
				val.Set(v.MapIndex(key))
				redact(val, tag)
				v.SetMapIndex(key, val)
			}
		}

	case reflect.Slice:
		if !v.IsNil() {
			for i := 0; i < v.Len(); i++ {
				redact(v.Index(i), tag)
			}
		}

	case reflect.String:
		v.SetString(transformString(v.String(), tag))

	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).CanSet() {
				tag, _ := v.Type().Field(i).Tag.Lookup(tagName)
				redact(v.Field(i), tag)
			}
		}
	}
}

func transformString(input, tagVal string) string {
	switch tagVal {
	case nonSecret:
		return input
	default:
		redactor, ok := redactors[tagVal]
		if !ok {
			return RedactStrConst
		}

		return redactor(input)
	}
}

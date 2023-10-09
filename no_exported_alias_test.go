package redact

import (
	"fmt"
	"reflect"
	"strings"
)

// exportedAddresses recurses a value v, returning a map of non-nil addresses of all of the exported sub-values found and the path to those
// values.
func exportedAddresses(path string, v any) map[uintptr][]string {
	m := map[uintptr][]string{}
	recurseExportedAddresses(m, path, reflect.ValueOf(v).Elem())
	return m
}

func recurseExportedAddresses(m map[uintptr][]string, path string, v reflect.Value) {
	switch v.Kind() {
	case reflect.Array:
		if v.Len() == 0 {
			saveAddress(m, path, v)
		} else {
			for i := 0; i < v.Len(); i++ {
				recurseExportedAddresses(m, path+fmt.Sprintf("[%d]", i), v.Index(i))
			}
		}

	case reflect.Chan:
		saveAddress(m, path, v)
		savePointerAddress(m, path+"[chan]", v)

	case reflect.Interface, reflect.Pointer, reflect.UnsafePointer:
		saveAddress(m, path, v)

		if !v.IsNil() {
			recurseExportedAddresses(m, path, v.Elem())
		}

	case reflect.Map:
		saveAddress(m, path, v)
		savePointerAddress(m, path+"[map]", v)

		iter := v.MapRange()
		for iter.Next() {
			recurseExportedAddresses(m, path+fmt.Sprintf("[%v;key]", iter.Key()), iter.Key())
			recurseExportedAddresses(m, path+fmt.Sprintf("[%v]", iter.Key()), iter.Value())
		}

	case reflect.Slice:
		saveAddress(m, path, v)

		if v.Len() == 0 && v.Cap() != 0 {
			savePointerAddress(m, path+"[slice]", v)
		} else {
			for i := 0; i < v.Len(); i++ {
				recurseExportedAddresses(m, path+"[0]", v.Index(i))
			}
		}

	case reflect.Struct:
		if v.NumField() == 0 {
			saveAddress(m, path, v)
		} else {
			for i := 0; i < v.NumField(); i++ {
				if v.Type().Field(i).IsExported() {
					recurseExportedAddresses(m, path+"."+v.Type().Field(i).Name, v.Field(i))
				}
			}
		}

	default:
		saveAddress(m, path, v)
	}
}

func saveAddress(m map[uintptr][]string, path string, v reflect.Value) {
	if v.CanAddr() && !v.Addr().IsNil() {
		m[v.Addr().Pointer()] = append(m[v.Addr().Pointer()], path)
	}
}

func savePointerAddress(m map[uintptr][]string, path string, v reflect.Value) {
	if !v.IsNil() {
		m[v.Pointer()] = append(m[v.Pointer()], path)
	}
}

// ValidateNoExportedAliases validates that no exported sub-value of `a` shares the same memory address of a sub-value of `b`.  The
// intention is to guarantee that a mutation of `b` cannot inadvertently cause a mutation of `a`.
func ValidateNoExportedAliases(a, b any) (errs []error) {
	aptrs, bptrs := exportedAddresses("a", a), exportedAddresses("b", b)

	for aptr, apaths := range aptrs {
		if bpaths := bptrs[aptr]; bpaths != nil {
			errs = append(errs, fmt.Errorf("%s and %s are aliases", strings.Join(apaths, ", "), strings.Join(bpaths, ", ")))
		}
	}

	return errs
}

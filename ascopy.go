package redact

import "reflect"

// AsCopy redacts all strings without the nonsecret tag, returning a copy of the argument.  Important: the argument is not modified, but
// unexported fields are not deep copied.  There could be pointer aliasing within unexported fields.  It cannot be guaranteed that a
// subsequent mutation to the argument will not mutate the result, or vice-versa.
func AsCopy[T any](t T) T {
	return asCopy(reflect.ValueOf(t), nonSecret).Interface().(T)
}

func asCopy(in reflect.Value, tag string) reflect.Value {
	out := in

	switch in.Kind() {
	case reflect.Array:
		out = reflect.New(in.Type()).Elem()
		for i := 0; i < in.Len(); i++ {
			out.Index(i).Set(asCopy(in.Index(i), tag))
		}

	case reflect.Interface:
		if !in.IsNil() {
			out = reflect.New(in.Type()).Elem()
			out.Set(asCopy(in.Elem(), tag))
		}

	case reflect.Map:
		if !in.IsNil() {
			out = reflect.MakeMapWithSize(in.Type(), in.Len())
			iter := in.MapRange()
			for iter.Next() {
				out.SetMapIndex(iter.Key(), asCopy(iter.Value(), tag))
			}
		}

	case reflect.Pointer:
		if !in.IsNil() {
			out = asCopy(in.Elem(), tag).Addr()
		}

	case reflect.Slice:
		if !in.IsNil() {
			out = reflect.MakeSlice(in.Type(), in.Len(), in.Len())
			for i := 0; i < in.Len(); i++ {
				out.Index(i).Set(asCopy(in.Index(i), tag))
			}
		}

	case reflect.String:
		out = reflect.New(in.Type()).Elem()
		out.SetString(transformString(in.String(), tag))

	case reflect.Struct:
		out = reflect.New(in.Type()).Elem()
		out.Set(in)
		for i := 0; i < in.NumField(); i++ {
			if in.Field(i).CanSet() {
				tag, _ := in.Type().Field(i).Tag.Lookup(tagName)
				out.Field(i).Set(asCopy(in.Field(i), tag))
			}
		}
	}

	return out
}

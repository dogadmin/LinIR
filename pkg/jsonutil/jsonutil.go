package jsonutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// PrettyJSON marshals v to indented JSON bytes.
func PrettyJSON(v interface{}) ([]byte, error) {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("jsonutil: marshal: %w", err)
	}
	return buf.Bytes(), nil
}

// WriteJSON writes v as indented JSON to w.
func WriteJSON(w io.Writer, v interface{}) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// Package httpbody contains helpers for including HTTP response bodies in
// error messages without leaking credentials or flooding logs.
package httpbody

import "strings"

// maxLen is the maximum number of response bytes kept in an error message.
const maxLen = 200

// sensitiveKeys are form fields whose values must never appear in errors.
var sensitiveKeys = []string{
	"Token=",
	"Auth=",
	"Email=",
	"SID=",
	"HSID=",
	"SSID=",
	"SAPISID=",
	"oauth_token=",
	"EncryptedPasswd=",
}

// Truncate returns at most maxLen bytes of body, with an ellipsis when cut.
func Truncate(body []byte) string {
	s := string(body)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "…"
}

// fieldSeparators delimit form-encoded fields and log lines.
const fieldSeparators = "&\n\r \t"

// Redact replaces the values of well-known sensitive fields with "***".
// Fields are matched at boundaries so e.g. "SID=" does not match inside
// "SSID=".
func Redact(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for len(s) > 0 {
		var field, sep string
		if idx := strings.IndexAny(s, fieldSeparators); idx < 0 {
			field = s
			s = ""
		} else {
			field = s[:idx]
			sep = s[idx : idx+1]
			s = s[idx+1:]
		}
		for _, key := range sensitiveKeys {
			if strings.HasPrefix(field, key) {
				field = key + "***"
				break
			}
		}
		b.WriteString(field)
		b.WriteString(sep)
	}
	return b.String()
}

// Safe truncates and redacts a response body for use in an error message.
func Safe(body []byte) string {
	return Redact(Truncate(body))
}

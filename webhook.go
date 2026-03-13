// Package webhook provides HMAC-based webhook signature generation and verification.
package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrSignatureMismatch is returned when the signature does not match.
	ErrSignatureMismatch = errors.New("webhook: signature verification failed")

	// ErrMissingHeader is returned when the signature header is missing.
	ErrMissingHeader = errors.New("webhook: missing signature header")
)

// SignatureExpiredError is returned when the signature timestamp exceeds the max age.
type SignatureExpiredError struct {
	Age    time.Duration
	MaxAge time.Duration
}

func (e *SignatureExpiredError) Error() string {
	return fmt.Sprintf("webhook: signature expired: age %s exceeds max %s", e.Age, e.MaxAge)
}

// SignedPayload contains the signature result.
type SignedPayload struct {
	Signature string
	Timestamp int64
	Body      string
}

// ToHeader formats the signed payload as a header value.
func (sp *SignedPayload) ToHeader() string {
	return fmt.Sprintf("t=%d,sha256=%s", sp.Timestamp, sp.Signature)
}

// Sign generates an HMAC-SHA256 signature for the given payload.
func Sign(payload string, secret string) *SignedPayload {
	return SignAt(payload, secret, time.Now().Unix())
}

// SignAt generates an HMAC-SHA256 signature with a specific timestamp.
func SignAt(payload string, secret string, timestamp int64) *SignedPayload {
	message := fmt.Sprintf("%d.%s", timestamp, payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	sig := hex.EncodeToString(mac.Sum(nil))

	return &SignedPayload{
		Signature: sig,
		Timestamp: timestamp,
		Body:      payload,
	}
}

// Verify checks an HMAC-SHA256 signature. maxAge of 0 disables age checking.
func Verify(payload string, secret string, signature string, timestamp int64, maxAge time.Duration) error {
	if maxAge > 0 {
		age := time.Since(time.Unix(timestamp, 0))
		if age > maxAge {
			return &SignatureExpiredError{Age: age, MaxAge: maxAge}
		}
	}

	expected := SignAt(payload, secret, timestamp)
	if !hmac.Equal([]byte(signature), []byte(expected.Signature)) {
		return ErrSignatureMismatch
	}

	return nil
}

// ParseHeader parses a webhook signature header in the format "t=timestamp,sha256=signature".
func ParseHeader(header string) (signature string, timestamp int64, err error) {
	parts := make(map[string]string)
	for _, part := range strings.Split(header, ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			parts[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}

	tsStr, ok := parts["t"]
	if !ok {
		return "", 0, ErrMissingHeader
	}
	timestamp, err = strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return "", 0, fmt.Errorf("webhook: invalid timestamp: %w", err)
	}

	signature, ok = parts["sha256"]
	if !ok || signature == "" {
		return "", 0, fmt.Errorf("webhook: no sha256 signature found in header")
	}

	return signature, timestamp, nil
}

// VerifyMiddleware returns an HTTP middleware that verifies webhook signatures.
func VerifyMiddleware(secret string, headerName string, maxAge time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get(headerName)
			if header == "" {
				http.Error(w, "missing signature header", http.StatusUnauthorized)
				return
			}

			sig, ts, err := ParseHeader(header)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}

			// Restore body so downstream handlers can read it
			r.Body = io.NopCloser(bytes.NewReader(body))

			if err := Verify(string(body), secret, sig, ts, maxAge); err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

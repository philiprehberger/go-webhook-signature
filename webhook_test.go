package webhook

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testSecret = "test-secret-key"

func TestSignAndVerify(t *testing.T) {
	payload := `{"event":"order.created","id":123}`
	sp := Sign(payload, testSecret)

	if sp.Signature == "" {
		t.Fatal("expected non-empty signature")
	}
	if sp.Timestamp == 0 {
		t.Fatal("expected non-zero timestamp")
	}
	if sp.Body != payload {
		t.Fatalf("expected body %q, got %q", payload, sp.Body)
	}

	err := Verify(payload, testSecret, sp.Signature, sp.Timestamp, 0)
	if err != nil {
		t.Fatalf("expected valid signature, got: %v", err)
	}
}

func TestSignAtDeterministic(t *testing.T) {
	payload := "hello"
	ts := int64(1700000000)
	sp1 := SignAt(payload, testSecret, ts)
	sp2 := SignAt(payload, testSecret, ts)

	if sp1.Signature != sp2.Signature {
		t.Fatal("expected identical signatures for same input")
	}
}

func TestVerifyMismatch(t *testing.T) {
	payload := `{"event":"test"}`
	sp := Sign(payload, testSecret)

	err := Verify(payload, "wrong-secret", sp.Signature, sp.Timestamp, 0)
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("expected ErrSignatureMismatch, got: %v", err)
	}

	err = Verify("tampered-payload", testSecret, sp.Signature, sp.Timestamp, 0)
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("expected ErrSignatureMismatch for tampered payload, got: %v", err)
	}
}

func TestVerifyExpired(t *testing.T) {
	payload := "test"
	oldTimestamp := time.Now().Add(-2 * time.Hour).Unix()
	sp := SignAt(payload, testSecret, oldTimestamp)

	err := Verify(payload, testSecret, sp.Signature, sp.Timestamp, 1*time.Hour)
	var expiredErr *SignatureExpiredError
	if !errors.As(err, &expiredErr) {
		t.Fatalf("expected SignatureExpiredError, got: %v", err)
	}
	if expiredErr.MaxAge != 1*time.Hour {
		t.Fatalf("expected MaxAge 1h, got %v", expiredErr.MaxAge)
	}
}

func TestVerifyMaxAgeZeroDisablesCheck(t *testing.T) {
	payload := "test"
	oldTimestamp := int64(1000000000) // very old
	sp := SignAt(payload, testSecret, oldTimestamp)

	err := Verify(payload, testSecret, sp.Signature, sp.Timestamp, 0)
	if err != nil {
		t.Fatalf("expected no error with maxAge=0, got: %v", err)
	}
}

func TestToHeader(t *testing.T) {
	sp := &SignedPayload{Signature: "abc123", Timestamp: 1700000000}
	header := sp.ToHeader()
	expected := "t=1700000000,sha256=abc123"
	if header != expected {
		t.Fatalf("expected %q, got %q", expected, header)
	}
}

func TestParseHeaderValid(t *testing.T) {
	sig, ts, err := ParseHeader("t=1700000000,sha256=abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ts != 1700000000 {
		t.Fatalf("expected timestamp 1700000000, got %d", ts)
	}
	if sig != "abc123" {
		t.Fatalf("expected signature abc123, got %s", sig)
	}
}

func TestParseHeaderMissingTimestamp(t *testing.T) {
	_, _, err := ParseHeader("sha256=abc123")
	if !errors.Is(err, ErrMissingHeader) {
		t.Fatalf("expected ErrMissingHeader, got: %v", err)
	}
}

func TestParseHeaderMissingSignature(t *testing.T) {
	_, _, err := ParseHeader("t=1700000000")
	if err == nil {
		t.Fatal("expected error for missing signature")
	}
	if !strings.Contains(err.Error(), "no sha256 signature") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseHeaderInvalidTimestamp(t *testing.T) {
	_, _, err := ParseHeader("t=notanumber,sha256=abc")
	if err == nil {
		t.Fatal("expected error for invalid timestamp")
	}
	if !strings.Contains(err.Error(), "invalid timestamp") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseHeaderEmptySignature(t *testing.T) {
	_, _, err := ParseHeader("t=1700000000,sha256=")
	if err == nil {
		t.Fatal("expected error for empty sha256 value")
	}
	if !strings.Contains(err.Error(), "no sha256 signature") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseHeaderEmpty(t *testing.T) {
	_, _, err := ParseHeader("")
	if err == nil {
		t.Fatal("expected error for empty header")
	}
}

func TestParseHeaderRoundTrip(t *testing.T) {
	sp := SignAt("payload", testSecret, 1700000000)
	sig, ts, err := ParseHeader(sp.ToHeader())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sig != sp.Signature || ts != sp.Timestamp {
		t.Fatal("round-trip failed: parsed values don't match original")
	}
}

func TestSignEmptyPayload(t *testing.T) {
	sp := Sign("", testSecret)
	if sp.Signature == "" {
		t.Fatal("expected signature even for empty payload")
	}
	err := Verify("", testSecret, sp.Signature, sp.Timestamp, 0)
	if err != nil {
		t.Fatalf("expected valid verification for empty payload, got: %v", err)
	}
}

func TestSignEmptySecret(t *testing.T) {
	sp := Sign("payload", "")
	if sp.Signature == "" {
		t.Fatal("expected signature even with empty secret")
	}
	err := Verify("payload", "", sp.Signature, sp.Timestamp, 0)
	if err != nil {
		t.Fatalf("expected valid verification with empty secret, got: %v", err)
	}
}

// Middleware tests

func newSignedRequest(payload, secret, headerName string, timestamp int64) *http.Request {
	sp := SignAt(payload, secret, timestamp)
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payload))
	req.Header.Set(headerName, sp.ToHeader())
	return req
}

func TestMiddlewareSuccess(t *testing.T) {
	headerName := "X-Signature"
	handler := VerifyMiddleware(testSecret, headerName, 0)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify body is still readable
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read body in handler: %v", err)
			}
			if string(body) != "test-body" {
				t.Fatalf("expected body 'test-body', got %q", string(body))
			}
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := newSignedRequest("test-body", testSecret, headerName, time.Now().Unix())
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestMiddlewareMissingHeader(t *testing.T) {
	handler := VerifyMiddleware(testSecret, "X-Signature", 0)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not be called")
		}),
	)

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader("body"))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMiddlewareInvalidSignature(t *testing.T) {
	handler := VerifyMiddleware(testSecret, "X-Signature", 0)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not be called")
		}),
	)

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader("body"))
	req.Header.Set("X-Signature", "t=1700000000,sha256=invalidsig")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMiddlewareExpiredSignature(t *testing.T) {
	headerName := "X-Signature"
	handler := VerifyMiddleware(testSecret, headerName, 1*time.Hour)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not be called")
		}),
	)

	oldTs := time.Now().Add(-2 * time.Hour).Unix()
	req := newSignedRequest("body", testSecret, headerName, oldTs)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMiddlewareEmptyBody(t *testing.T) {
	headerName := "X-Signature"
	handler := VerifyMiddleware(testSecret, headerName, 0)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := newSignedRequest("", testSecret, headerName, time.Now().Unix())
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestMiddlewareNoContentLength(t *testing.T) {
	headerName := "X-Signature"
	payload := "test-payload"
	sp := SignAt(payload, testSecret, time.Now().Unix())

	handler := VerifyMiddleware(testSecret, headerName, 0)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	// Simulate request with unknown ContentLength (-1)
	req := httptest.NewRequest(http.MethodPost, "/webhook", io.NopCloser(bytes.NewReader([]byte(payload))))
	req.ContentLength = -1
	req.Header.Set(headerName, sp.ToHeader())

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with unknown content-length, got %d: %s", rr.Code, rr.Body.String())
	}
}

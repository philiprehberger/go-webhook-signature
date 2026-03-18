# go-webhook-signature

[![CI](https://github.com/philiprehberger/go-webhook-signature/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/go-webhook-signature/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/philiprehberger/go-webhook-signature.svg)](https://pkg.go.dev/github.com/philiprehberger/go-webhook-signature)
[![License](https://img.shields.io/github/license/philiprehberger/go-webhook-signature)](LICENSE)

HMAC-SHA256 webhook signature generation and verification with HTTP middleware for Go

## Installation

```bash
go get github.com/philiprehberger/go-webhook-signature
```

## Usage

### Sign a Payload

```go
import "github.com/philiprehberger/go-webhook-signature"

signed := webhook.Sign(`{"event":"order.created"}`, "whsec_abc123")

fmt.Println(signed.Signature) // HMAC hex digest
fmt.Println(signed.Timestamp) // Unix timestamp
fmt.Println(signed.ToHeader()) // "t=1234567890,sha256=abc..."
```

### Verify a Signature

```go
sig, ts, err := webhook.ParseHeader(r.Header.Get("X-Webhook-Signature"))
if err != nil {
    // handle error
}

err = webhook.Verify(body, "whsec_abc123", sig, ts, 5*time.Minute)
if err != nil {
    // handle error
}
```

### HTTP Middleware

```go
mux := http.NewServeMux()
mux.HandleFunc("/webhook", handleWebhook)

protected := webhook.VerifyMiddleware("whsec_abc123", "X-Webhook-Signature", 5*time.Minute)(mux)
http.ListenAndServe(":8080", protected)
```

The middleware restores the request body after reading it, so downstream handlers can still access `r.Body`.

### Error Handling

```go
err := webhook.Verify(payload, secret, sig, ts, maxAge)
if errors.Is(err, webhook.ErrSignatureMismatch) {
    // invalid signature
}

var expired *webhook.SignatureExpiredError
if errors.As(err, &expired) {
    fmt.Printf("Signature too old: %s > %s\n", expired.Age, expired.MaxAge)
}
```

### Disable Age Check

```go
webhook.Verify(payload, secret, sig, ts, 0) // no age check
```

## API

| Function / Method | Description |
|---|---|
| `Sign(payload, secret string) *SignedPayload` | Generate HMAC-SHA256 signature with current timestamp |
| `SignAt(payload, secret string, timestamp int64) *SignedPayload` | Generate HMAC-SHA256 signature with specific timestamp |
| `Verify(payload, secret, signature string, timestamp int64, maxAge time.Duration) error` | Verify an HMAC-SHA256 signature |
| `ParseHeader(header string) (signature string, timestamp int64, err error)` | Parse "t=...,sha256=..." header format |
| `VerifyMiddleware(secret, headerName string, maxAge time.Duration) func(http.Handler) http.Handler` | HTTP middleware that verifies webhook signatures |
| `SignedPayload` | Struct containing signature, timestamp, and body |
| `(*SignedPayload) ToHeader() string` | Format as "t=...,sha256=..." header value |
| `SignatureExpiredError` | Error when signature timestamp exceeds max age |
| `(*SignatureExpiredError) Error() string` | Format the expiry error message |
| `ErrSignatureMismatch` | Sentinel error for signature verification failure |
| `ErrMissingHeader` | Sentinel error for missing signature header |

## Development

```bash
go test ./...
go vet ./...
```

## License

MIT

# Basic JWKS Server

CSCE 3550 Project 1 — a small JWKS server written in Go.

## Requirements implemented

- RSA 2048-bit key generation
- Unique `kid` values and key expiry timestamps
- `GET /.well-known/jwks.json` returns only unexpired public keys
- `POST /auth` returns a signed RS256 JWT
- `POST /auth?expired` returns a JWT signed with the expired key
- JWT header contains the corresponding `kid`
- Non-supported HTTP methods return `405 Method Not Allowed`
- Automated tests using Go's standard testing and `httptest` packages

## Run

```bash
go run .
```

The server listens on `http://localhost:8080`.

## Test

```bash
go test ./...
go test -cover ./...
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

The assignment target is more than 80% test coverage. The test suite covers key generation, JWK conversion, expiry filtering, both HTTP handlers, HTTP method checks, JWT issuance, and the expired-key path.

## Manual checks

In another terminal:

```bash
curl http://localhost:8080/.well-known/jwks.json
curl -X POST http://localhost:8080/auth
curl -X POST "http://localhost:8080/auth?expired"
curl -i http://localhost:8080/auth
```

The JWKS response should contain `valid-key` but not `expired-key`. The normal JWT should have `kid=valid-key`; the expired JWT should have `kid=expired-key`.

## Linting and formatting

Format with:

```bash
gofmt -w *.go
go vet ./...
```

If `golangci-lint` is installed:

```bash
golangci-lint run
```

## Blackbox client screenshot

Run the instructor-provided test client against `localhost:8080`, then capture a screenshot that shows the successful test output and identifying information, as required by the assignment. Add that image to the repository before submitting.

## Test coverage screenshot

Run:

```bash
go test -cover ./...
```

Capture the output showing the coverage percentage and add the screenshot to the repository.

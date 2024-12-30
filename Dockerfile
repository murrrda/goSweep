# Stage 1: Build
FROM golang:1.23 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -o goSweep ./cmd/goSweep/main.go

# Stage 2: Runtime
FROM alpine:latest

# Set the working directory
WORKDIR /app

# Copy the compiled binary from the build stage
COPY --from=builder /app/goSweep /app/goSweep

# Set entrypoint
ENTRYPOINT ["/app/goSweep"]

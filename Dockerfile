FROM golang:1.23-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -trimpath -o ssh-tunnel-proxy .

FROM scratch

COPY --from=builder /build/ssh-tunnel-proxy /ssh-tunnel-proxy

ENTRYPOINT ["/ssh-tunnel-proxy"]

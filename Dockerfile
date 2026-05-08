# Сборка
FROM golang:1.25 AS builder
WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o agent ./cmd/

FROM alpine:3.23
WORKDIR /root/

COPY --from=builder /app/agent .

CMD ["./agent"]
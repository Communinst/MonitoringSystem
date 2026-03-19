# Сборка
FROM golang:1.25 AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y clang llvm libbpf-dev

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

RUN go generate ./...

RUN CGO_ENABLED=0 GOOS=linux go build -o agent ./cmd/

# Финальный образ
FROM alpine:3.23
WORKDIR /root/

# Забираем бинарник из стадии сборки
COPY --from=builder /app/agent .

CMD ["./agent"]
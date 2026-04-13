FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod ./
# Add go.sum generation explicitly by running tidy securely
# since the host mapping did not run native Go tools directly
COPY . .
RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=linux go build -o bot-binary main.go

FROM alpine:latest

WORKDIR /app
COPY --from=builder /app/bot-binary .

RUN apk add --no-cache tzdata ca-certificates su-exec

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Run natively using Alpine directly without massive OS overhead!
ENTRYPOINT ["/entrypoint.sh"]
CMD ["./bot-binary"]

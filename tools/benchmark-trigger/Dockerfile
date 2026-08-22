FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY server.go .
RUN go build -o benchmark-trigger server.go
COPY oneshot.go .
RUN go build -o tcpblaster oneshot.go

FROM alpine:3.20
COPY --from=builder /app/benchmark-trigger /usr/local/bin/benchmark-trigger
COPY --from=builder /app/tcpblaster /opt/clif/tcpblaster
EXPOSE 9515
CMD ["benchmark-trigger"]

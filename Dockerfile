FROM golang:alpine as builder

RUN apk add git

WORKDIR /app 

COPY . /app/ 

RUN go mod init github.com/mparvin/sniproxy
RUN go build -o sniproxy . 

# Run in apline
FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/sniproxy .

CMD ["/app/sniproxy"]
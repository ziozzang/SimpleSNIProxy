# Multi-stage build: tiny static binary on scratch.
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w" -o /out/sniproxy .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sniproxy /sniproxy
EXPOSE 80 443
USER nonroot:nonroot
ENTRYPOINT ["/sniproxy"]

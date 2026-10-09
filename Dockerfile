# syntax=docker/dockerfile:1.7

FROM golang:1.27.0-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/p ./cmd/p

FROM cgr.dev/chainguard/static:latest
COPY --from=build /out/p /p
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/p"]

# syntax=docker/dockerfile:1

ARG GO_VERSION=1.23
ARG NODE_VERSION=20

FROM node:${NODE_VERSION}-alpine AS frontend
WORKDIR /app
COPY web/frontend/package*.json web/frontend/
RUN cd web/frontend && npm ci
COPY web/frontend web/frontend
RUN cd web/frontend && npm run build

FROM golang:${GO_VERSION}-alpine AS backend
WORKDIR /app
RUN apk add --no-cache build-base
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /app/web/frontend/dist ./web/frontend/dist
ARG VERSION=dev
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X github.com/rochael/RocNav/internal/version.buildVersion=${VERSION}" -o /app/server ./cmd/server

FROM alpine:3.20
WORKDIR /app
RUN apk add --no-cache ca-certificates tzdata
COPY --from=backend /app/server /app/server
COPY --from=backend /app/VERSION /app/VERSION
EXPOSE 8080
ENTRYPOINT ["/app/server"]

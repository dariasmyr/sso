FROM golang:alpine AS build
RUN apk update && apk add --no-cache gcc musl-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -ldflags="-s -w" -o /app/migrator ./cmd/migrator
RUN go build -ldflags="-s -w" -o /app/sso ./cmd/sso

FROM alpine:latest
WORKDIR /app
COPY --from=build /app/sso /app/sso
COPY --from=build /app/migrator /app/migrator
CMD ["sh", "-c", "./migrator && ./sso"]



FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/gmr-vault ./cmd/api

FROM alpine:3.23
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=build /out/gmr-vault /usr/local/bin/gmr-vault

EXPOSE 8091
CMD ["gmr-vault"]

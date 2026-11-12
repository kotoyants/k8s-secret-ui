# syntax=docker/dockerfile:1

FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/secrets-ui ./cmd/secrets-ui

# CI: the binary is built outside Docker with a persistent Go build cache, then
# copied in (`--target prebuilt`, expects dist/secrets-ui). Local builds use the default target.
FROM gcr.io/distroless/static-debian12:nonroot AS prebuilt
COPY dist/secrets-ui /secrets-ui
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/secrets-ui"]

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/secrets-ui /secrets-ui
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/secrets-ui"]

# syntax=docker/dockerfile:1

FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/secret-manager ./cmd/secret-manager

# CI: the binary is built outside Docker with a persistent Go build cache, then
# copied in (`--target prebuilt`, expects dist/secret-manager). Local builds use the default target.
FROM gcr.io/distroless/static-debian12:nonroot AS prebuilt
COPY dist/secret-manager /secret-manager
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/secret-manager"]

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/secret-manager /secret-manager
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/secret-manager"]

# Multi-stage, multi-arch build. CGO disabled so the static binary runs
# on Alpine/musl in the openbao image without glibc shims.
FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" \
    -o /out/openbao-plugin-secrets-graphql \
    ./cmd/openbao-plugin-secrets-graphql

FROM openbao/openbao:latest

# OpenBao loads plugins from plugin_directory; mount or bake the binary.
COPY --from=build /out/openbao-plugin-secrets-graphql /openbao/plugins/openbao-plugin-secrets-graphql

# Register at runtime:
#   bao plugin register -sha256=$(sha256sum /openbao/plugins/openbao-plugin-secrets-graphql | cut -d' ' -f1) \
#     secret openbao-plugin-secrets-graphql
#   bao secrets enable -path=gql openbao-plugin-secrets-graphql

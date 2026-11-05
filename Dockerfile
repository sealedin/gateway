# golang:1.26.10-alpine by index digest; scripts/check-image-pins.sh rejects any tag (docs/litellm-pin.md).
FROM golang@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308 AS build
ENV GOTOOLCHAIN=local
WORKDIR /src
# Dependencies are pinned by go.sum; download them in their own cached layer.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -ldflags "-s -w -buildid=" -o /out/gateway-identity ./cmd/identity

# gcr.io/distroless/static-debian12:nonroot by index digest; see scripts/check-image-pins.sh.
FROM gcr.io/distroless/static-debian12@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/gateway-identity /gateway-identity
# Only the plaintext bootstrap; the private listener (8473) must never be published, so docker run -P cannot map it.
EXPOSE 8471
ENTRYPOINT ["/gateway-identity"]

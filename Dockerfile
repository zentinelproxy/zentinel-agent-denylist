# syntax=docker/dockerfile:1.4

# Sentinel Denylist Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY sentinel-denylist-agent /sentinel-denylist-agent

LABEL org.opencontainers.image.title="Sentinel Denylist Agent" \
      org.opencontainers.image.description="Sentinel Denylist Agent for Sentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/raskell-io/sentinel-agent-denylist"

ENV RUST_LOG=info,sentinel_denylist_agent=debug \
    SOCKET_PATH=/var/run/sentinel/denylist.sock

USER nonroot:nonroot

ENTRYPOINT ["/sentinel-denylist-agent"]

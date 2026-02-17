# syntax=docker/dockerfile:1.4

# Zentinel Denylist Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY zentinel-denylist-agent /zentinel-denylist-agent

LABEL org.opencontainers.image.title="Zentinel Denylist Agent" \
      org.opencontainers.image.description="Zentinel Denylist Agent for Zentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/zentinelproxy/zentinel-agent-denylist"

ENV RUST_LOG=info,zentinel_denylist_agent=debug \
    SOCKET_PATH=/var/run/zentinel/denylist.sock

USER nonroot:nonroot

ENTRYPOINT ["/zentinel-denylist-agent"]

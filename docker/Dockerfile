FROM sc4h/alpine-s6overlay:3.12

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

ENV \
  PATH="/app/crs:${PATH}" \
  APP_CONFIG="/config/config.yml" \
  APP_UPLOAD="/config/uploads" \
  APP_LOG="/config/activity.log" \
  APP_VERBOSITY="0"

# Binary
COPY ["dist/crs_${TARGETOS}_${TARGETARCH}${TARGETVARIANT:+_7}/crs", "/app/crs/crs"]

# Add root files
COPY ["docker/run", "/etc/services.d/crs/run"]

# Volume
VOLUME ["/config"]

# Port
EXPOSE 8684
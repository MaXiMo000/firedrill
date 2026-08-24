# firedrill drives Docker; it does not contain Postgres. The image carries the
# CLI and a docker client, and expects the host's socket to be mounted:
#
#   docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
#     -v /backups/db.dump:/backups/db.dump:ro firedrill run /backups/db.dump
#
# The containers firedrill starts are SIBLINGS, created on the host's daemon,
# so the dump must be readable at the same absolute path on the host. Mounting
# it somewhere else inside this container will start a target that cannot see
# it. This is a property of sharing the daemon, not something firedrill can fix.
FROM python:3.13-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends docker.io ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY firedrill/ ./firedrill/
RUN pip install --no-cache-dir . && pip cache purge || true

# Non-root. It needs group access to the mounted docker socket, which is the
# host's business (--group-add), not a reason to run as root here.
RUN useradd -r -u 10001 -m firedrill
USER 10001

ENTRYPOINT ["firedrill"]
CMD ["--help"]

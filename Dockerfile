FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# `ping` is what the scanner uses. It is given the NET_RAW file capability here, at build time,
# so the unprivileged user below can run it when docker-compose.yml grants NET_RAW to the
# container. (Some Debian releases ship ping without it and rely on a host sysctl instead.)
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping libcap2-bin \
    && setcap cap_net_raw+ep "$(command -v ping)" \
    && apt-get purge -y --auto-remove libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 netinv \
    && mkdir /data && chown netinv /data
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install .

USER netinv
ENV NETINV_DB=/data/netinv.db
VOLUME /data
EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8090/health')" || exit 1

CMD ["netinv", "run", "--host", "0.0.0.0", "--port", "8090"]

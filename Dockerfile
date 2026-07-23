FROM python:3.11-slim AS builder

WORKDIR /build
COPY pyproject.toml .
RUN pip install --no-cache-dir build && python -m build --wheel

FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/dist/*.whl .
RUN pip install --no-cache-dir *.whl[pdf] && rm *.whl

COPY wordlists/ wordlists/

RUN groupadd -r recon && useradd -r -g recon recon && \
    chown -R recon:recon /app/wordlists
USER recon

ENTRYPOINT ["wp-recon"]
CMD ["main", "--help"]

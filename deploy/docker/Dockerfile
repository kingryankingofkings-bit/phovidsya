# ── Stage 1: Rust build ─────────────────────────────────────────────────────
FROM rust:1.89-slim AS rust-builder

WORKDIR /build

COPY rust-toolchain.toml ./
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY kernel/ ./kernel/

# Build and test all Rust crates (no_std contracts + guardian monitor).
# No error masking: a failing contract test must fail the image build.
RUN cargo test --workspace --locked

# ── Stage 2: Python runtime ──────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="Aegis Shield"
LABEL org.opencontainers.image.description="Hardware-grade ransomware isolation — software reference deployment"
LABEL org.opencontainers.image.version="0.1.0"

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false -d /var/lib/aegis-shield aegis
RUN mkdir -p /var/lib/aegis-shield /etc/aegis-shield /run/aegis-shield \
    && chown -R aegis: /var/lib/aegis-shield /etc/aegis-shield /run/aegis-shield

WORKDIR /app

# Install Python package
COPY pyproject.toml README.md LICENSE ./
COPY aegis_shield/ ./aegis_shield/
RUN pip install --no-cache-dir .

# Web dashboard
COPY web/ ./web/

EXPOSE 8443

VOLUME ["/var/lib/aegis-shield"]

USER aegis

ENV AEGIS_NAMESPACE_DIR=/var/lib/aegis-shield/namespace
ENV AEGIS_NAMESPACE_BLOCKS=65536
ENV AEGIS_HOST=0.0.0.0
ENV AEGIS_PORT=8443

ENTRYPOINT ["aegis-shield"]
CMD ["start", "/var/lib/aegis-shield/namespace", "--host", "0.0.0.0", "--port", "8443"]

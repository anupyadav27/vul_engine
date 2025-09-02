# Simple PostgreSQL Database for Vulnerability DB
FROM postgres:15-alpine

# Set default environment variables
ENV POSTGRES_DB=vulnerability_db
ENV POSTGRES_USER=vuln_user
ENV POSTGRES_PASSWORD=vuln_secure_pass

# Install Python and required packages via apk (Alpine package manager)
RUN apk add --no-cache python3 py3-pip py3-psycopg2

# Install additional Python packages with system packages flag
RUN pip3 install --break-system-packages asyncpg

# Copy local initialization files only
COPY ./init_database.py /docker-entrypoint-initdb.d/02-init-data.py

# Create directory for config files (will be mounted as volume)
RUN mkdir -p /config

# Expose PostgreSQL port
EXPOSE 5432

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD pg_isready -U $POSTGRES_USER -d $POSTGRES_DB || exit 1
# phpscan — free external PHP vulnerability scanner.
# Passive fingerprinting plus limited, read-only path checks.
# No exploit probes, no third-party dependencies (stdlib only).
FROM python:3.12-slim

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .

# Run as an unprivileged user; the scanner only makes outbound
# HTTP requests and writes nothing.
RUN useradd --create-home --uid 10001 phpscan
USER phpscan

ENTRYPOINT ["phpscan"]

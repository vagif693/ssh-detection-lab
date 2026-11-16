FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SSHLAB_DB=/app/var/sshlab.db

WORKDIR /app

# Run as an unprivileged user, never as root.
RUN useradd --create-home --uid 10001 sshlab

COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir .

# Build a demo database from the real and sample logs.
COPY data ./data
RUN mkdir var \
    && sshlab data/OpenSSH_2k.log --db var/sshlab.db --output /tmp/report.json \
    && sshlab data/sample_attack.log --db var/sshlab.db --output /tmp/report.json \
    && chown -R sshlab:sshlab var

USER sshlab
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"

CMD ["uvicorn", "sshlab.api:app", "--host", "0.0.0.0", "--port", "8000"]

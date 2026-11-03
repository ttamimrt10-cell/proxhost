FROM python:3.11-slim

# Node.js is required for users' uploaded JavaScript files.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install the app's declared Python dependencies.
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Create a non-root runtime user and writable application directories.
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/upload_bots /app/inf /app/python-packages \
    && chown -R appuser:appuser /app

# Uploaded scripts may install their own Python packages at runtime.
ENV HOME=/home/appuser \
    PIP_TARGET=/app/python-packages \
    PYTHONPATH=/app/python-packages \
    PYTHONUNBUFFERED=1

COPY --chown=appuser:appuser app.py /app/app.py

USER appuser
EXPOSE 8080
CMD ["python", "app.py"]

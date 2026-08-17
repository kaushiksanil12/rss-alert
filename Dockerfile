FROM python:3.9-slim

# Prevent Python from writing pyc files to disk and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Create a non-root user and group with an explicit UID/GID (10000)
# This makes it easy to set host permissions for bind mounts
RUN addgroup --system --gid 10000 nonroot && adduser --system --uid 10000 --gid 10000 nonroot

WORKDIR /app

# Install dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . /app/

# Create a dedicated data directory for the SQLite database
# and ensure the non-root user owns it.
RUN mkdir /data && chown nonroot:nonroot /data

# Set environment variable to point SQLite to the new data directory
ENV DATA_DIR=/data

# Switch to the non-root user
USER nonroot

# By default, run the main script
CMD ["python", "main.py"]

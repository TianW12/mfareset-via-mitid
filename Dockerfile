FROM python:3.13-slim

# Prevent Python from buffering logs
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies (minimal)
RUN apt-get update && apt-get install -y \
    build-essential curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for caching)
COPY requirements.txt ./requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Create directory for SQLite + static
RUN mkdir -p /data /app/staticfiles

# Collect static files
RUN python manage.py collectstatic --noinput

# Run with gunicorn
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3"]
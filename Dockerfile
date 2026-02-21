# Use official Python image
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /app

# Install system dependencies required by some Python packages (OpenCV, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1-mesa-glx \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for better caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create necessary directories (they will be overridden by volumes, but ensure they exist)
RUN mkdir -p /app/instance /app/temp /app/static/qr

# Expose port 5000
EXPOSE 5000

# Run the app with gunicorn (production WSGI server)
CMD gunicorn --bind 0.0.0.0:5000 app:app
FROM python:3.10-slim

# Prevent logs from being buffered
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies (optional but recommended for many Python libs)
RUN apt-get update && apt-get install -y build-essential

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all project files
COPY . .

# Railway injects $PORT automatically
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

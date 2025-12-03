# ============================
# Base Image
# ============================
FROM python:3.10.10

# ============================
# System Dependencies
# ============================
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ============================
# Work Directory
# ============================
WORKDIR /app

# ============================
# Install Python Dependencies
# ============================
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ============================
# Copy App
# ============================
COPY . .

# ============================
# Expose Render Port
# ============================
EXPOSE 8000

# ============================
# Start FastAPI
# ============================
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port $PORT"]

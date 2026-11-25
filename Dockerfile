FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000

WORKDIR /app

# Install Python dependencies first for better Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Q-Shield source modules and web frontend
COPY benchmarks/ ./benchmarks/
COPY dashboard/ ./dashboard/
COPY frontend/ ./frontend/
COPY proxy/ ./proxy/
COPY samples/ ./samples/
COPY scanner/ ./scanner/

EXPOSE 5000

CMD ["sh", "-c", "flask --app frontend.api run --host=0.0.0.0 --port=${PORT}"]
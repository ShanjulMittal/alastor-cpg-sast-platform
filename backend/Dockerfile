FROM python:3.12-slim

WORKDIR /app

# Install system dependencies if required for C/C++ compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create non-root execution user to remediate CWE-250 (IAC-2-CONTAINER-ROOT)
RUN groupadd -r app && useradd -r -g app appuser && chown -R appuser:app /app

USER appuser

EXPOSE 8000

ENV PYTHONUNBUFFERED=1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

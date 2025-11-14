FROM python:3.11-slim

# Prevent .pyc files and force unbuffered logs
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Cloud Run will inject $PORT; default to 8080 for local debugging
ENV PORT=8080

# Ensure output directory exists (just in case)
RUN mkdir -p out/outputs

# Start Waitress serving the Flask app
# web_app:app => "app" object inside web_app.py
CMD ["sh", "-c", "waitress-serve --listen=0.0.0.0:${PORT} web_app:app"]
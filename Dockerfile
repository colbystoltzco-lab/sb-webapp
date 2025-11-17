# Dockerfile at repo root

FROM python:3.11-slim

# Create and switch to app directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the code
COPY . .

# Cloud Run will inject PORT, but waitress needs to listen on it
ENV PYTHONUNBUFFERED=1

# Start the app with waitress, binding to 0.0.0.0:$PORT as Cloud Run requires
# "web_app:app" = module "web_app", object "app"
CMD ["sh", "-c", "waitress-serve --listen=0.0.0.0:${PORT} web_app:app"]
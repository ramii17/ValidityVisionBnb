# Use a Python base image
FROM python:3.10-slim

# Set the working directory
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Cloud Run expects the application to listen on the PORT environment variable
ENV PORT 8080

# Run the application using Gunicorn (production WSGI server)
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 app:app
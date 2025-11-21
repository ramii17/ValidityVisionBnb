# Use a slim Python base image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Cloud Run sets the PORT environment variable. Flask uses 8080 by default.
# The container must listen on the port defined by the PORT environment variable.
ENV PORT 8080

# Run the application using the gunicorn WSGI server for production, 
# or use the built-in Flask server for simplicity in this case.
# Using a production server like Gunicorn or Waitress is highly recommended 
# for stability in Cloud Run.

# Use Gunicorn as the production web server:
# Make sure to install gunicorn in your requirements.txt
# CMD exec gunicorn --bind :$PORT --workers 2 --threads 4 --timeout 0 app:app

# For now, let's stick to the Flask development server for simplicity,
# but note that this is NOT recommended for production:
CMD ["python", "app.py"]
# Use the official Python base image
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1  
# Ensure that Python output is not buffered (helpful for logging)

# Set the working directory in the container
WORKDIR /app

# Copy requirements.txt into the container
COPY requirements.txt /app/

# Install any dependencies specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY . /app

# Expose a port (change if necessary, depending on your application)
EXPOSE 8000

# Run the application
CMD ["python", "Vulnerability_Agent.py"] 
 # Runs the main file

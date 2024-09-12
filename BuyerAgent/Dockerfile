# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install the Python dependencies
RUN pip install -r requirements.txt

# Copy the BuyerAgent.py file into the container
COPY BuyerAgent.py /app/

# Expose port 8081 on which FastAPI will run
EXPOSE 8081

# Run Uvicorn server on port 8081
CMD ["uvicorn", "BuyerAgent:app", "--host", "0.0.0.0", "--port", "8081"]

# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install the Python dependencies
RUN pip install -r requirements.txt

# Copy the BuyerAgent.py file into the container
COPY BuyerAgentApp.py /app/

# Expose port 8081 on which FastAPI will run
EXPOSE 8081

# Run Uvicorn server on port 8081
CMD ["streamlit","run", "BuyerAgentApp.py",  "--server.port", "8081"]

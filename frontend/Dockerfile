FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app/ ./app/
EXPOSE 8000

# Start Uvicorn as the container's main process.
ENTRYPOINT ["uvicorn"]

# FastAPI application and its default network settings.
CMD ["app.main:app", "--host", "0.0.0.0", "--port", "8000"]
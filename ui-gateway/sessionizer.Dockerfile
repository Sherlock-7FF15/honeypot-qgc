FROM python:3.11-slim
WORKDIR /app
COPY sessionizer.py /app/sessionizer.py
ENV PYTHONUNBUFFERED=1
CMD ["python", "/app/sessionizer.py"]

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY sessionizer.py /app/sessionizer.py
CMD ["python", "/app/sessionizer.py"]

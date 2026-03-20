FROM python:3.11-slim
WORKDIR /app
COPY web_sessionizer.py /app/web_sessionizer.py
COPY rtsp_sessionizer.py /app/rtsp_sessionizer.py
ENV PYTHONUNBUFFERED=1

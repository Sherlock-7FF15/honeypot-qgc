FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

RUN pip install MAVProxy==1.8.74 pymavlink future

WORKDIR /app
COPY entrypoint.sh /app/entrypoint.sh
COPY run_logged.py /app/run_logged.py
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]

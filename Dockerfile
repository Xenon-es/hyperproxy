# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY proxy.py /app/proxy.py

RUN useradd --create-home --uid 10001 proxy
USER proxy

EXPOSE 8080 9090

ENTRYPOINT ["python", "-u", "/app/proxy.py"]
CMD ["--host", "0.0.0.0", "--port", "8080", "--admin-port", "9090"]
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY email_otp_service.py email_otp_webui.py config.example.json ./
COPY docker-entrypoint.sh /app/docker-entrypoint.sh

RUN chmod +x /app/docker-entrypoint.sh \
    && mkdir -p /app/config /app/data

ENV EMAIL_OTP_CONFIG=/app/config/config.json \
    EMAIL_OTP_DB=/app/data/email_otp_service.sqlite3 \
    EMAIL_OTP_WEBUI_SECRET=/app/config/webui.secret \
    EMAIL_OTP_REFRESH_URL=http://127.0.0.1:8088/refresh

EXPOSE 8090

ENTRYPOINT ["/app/docker-entrypoint.sh"]

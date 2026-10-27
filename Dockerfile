FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 APP_ENV=production
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Run as an unprivileged user (least privilege)
RUN useradd -r -u 10001 bank && chown -R bank /app
USER bank
EXPOSE 8000
CMD ["sh", "-c", "gunicorn app:app --workers 1 --threads 4 --bind 0.0.0.0:${PORT:-8000} --access-logfile -"]

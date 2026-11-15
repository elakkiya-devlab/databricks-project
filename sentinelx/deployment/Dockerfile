FROM python:3.11-slim
WORKDIR /app
COPY requirements.lock.txt .
RUN pip install --no-cache-dir -r requirements.lock.txt \
    && groupadd --gid 10001 sentinelx \
    && useradd --uid 10001 --gid sentinelx --create-home sentinelx
COPY --chown=10001:10001 . .
RUN mkdir -p /app/.local && chown -R 10001:10001 /app/.local
USER 10001:10001
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
EXPOSE 8000 8501
CMD ["python", "-m", "uvicorn", "backend.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
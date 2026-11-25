FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PORT=8080
WORKDIR /service
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --uid 10001 --no-create-home scanner
COPY app ./app
COPY static ./static
COPY data ./data
RUN chmod -R a=rX app static && chown -R 10001:10001 data
USER 10001
EXPOSE 8080
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port \"$PORT\" --workers 1 --limit-concurrency 16 --timeout-keep-alive 5"]

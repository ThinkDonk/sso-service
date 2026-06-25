FROM python:3.12-slim

WORKDIR /app

COPY . .

RUN pip install -e .

RUN useradd --create-home --shell /bin/bash app \
    && mkdir -p /app/data \
    && chown -R app:app /app/data

USER app

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]

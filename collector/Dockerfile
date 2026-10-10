FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN groupadd -r -g 10002 collector && useradd -r -u 10002 -g collector collector
WORKDIR /app
COPY requirements.txt requirements-dev.txt ./
RUN pip install -r requirements-dev.txt
COPY hlpa_collector ./hlpa_collector
COPY rules ./rules
COPY tests ./tests
USER 10002:10002
CMD ["python", "-m", "hlpa_collector.main"]

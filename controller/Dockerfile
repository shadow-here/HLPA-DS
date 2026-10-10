# HLPA-DS decoy controller - the only service with Docker socket access.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY controller.py .
EXPOSE 9000
CMD ["python", "controller.py"]

# HLPA-DS HTTP / banner decoy (stdlib only, no third-party packages).
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd -r -g 10001 decoy && useradd -r -u 10001 -g decoy decoy \
 && mkdir -p /var/log/hlpa && chown decoy:decoy /var/log/hlpa
WORKDIR /app
COPY decoy.py /app/decoy.py
USER 10001:10001
EXPOSE 80 25 53 110 135 139 143 445 3389 5432 5900 8080 8443 9200 11211
CMD ["python", "/app/decoy.py"]

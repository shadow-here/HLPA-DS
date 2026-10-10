# HLPA-DS OpenCanary decoy - pinned OpenCanary version from PyPI.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends gcc libffi-dev libssl-dev libpcap-dev \
 && pip install opencanary==0.9.10 \
 && apt-get purge -y gcc && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /etc/opencanaryd /var/log/opencanary

COPY opencanary.conf /etc/opencanaryd/opencanary.conf
EXPOSE 21 1433 3306 5000 6379 9418
RUN chown -R nobody:nogroup /var/log/opencanary
# Run unprivileged from the start (all capabilities are dropped, so no setuid step).
USER nobody
CMD ["twistd", "-noy", "/usr/local/bin/opencanary.tac", "--pidfile="]

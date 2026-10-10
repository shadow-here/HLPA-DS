# HLPA-DS Cowrie decoy - pinned Cowrie version installed from PyPI.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 COWRIE_STDOUT=yes
RUN apt-get update && apt-get install -y --no-install-recommends gcc libffi-dev libssl-dev \
 && pip install cowrie==3.1.1 \
 && apt-get purge -y gcc && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* \
 && groupadd -r -g 999 cowrie && useradd -r -u 999 -g cowrie -d /cowrie cowrie \
 && mkdir -p /cowrie/etc /cowrie/var/log/cowrie /cowrie/var/lib/cowrie /cowrie/var/run \
 && chown -R cowrie:cowrie /cowrie

WORKDIR /cowrie
COPY --chown=cowrie:cowrie cowrie.cfg /cowrie/etc/cowrie.cfg
COPY --chown=cowrie:cowrie userdb.txt /cowrie/etc/userdb.txt

USER 999:999
EXPOSE 22 23
CMD ["cowrie", "start"]

FROM alpine:latest

ENV TZ=Europe/Rome

RUN set -ex && \
    apk --no-cache --timeout 1 add netcat-openbsd openssh-client \
      python3 py3-bcrypt py3-cachetools py3-requests py3-twisted sshpass

COPY ./contrib/docker/fix-twisted-protocols-policies.diff /tmp/
COPY . /tmp/haas-proxy/
RUN set -ex && \
    apk --no-cache --timeout 1 add patch py3-pip && \
    patch --directory /usr/lib/python3.12/site-packages \
      --input=/tmp/fix-twisted-protocols-policies.diff --strip=2 --silent -V none && \
    rm /tmp/fix-twisted-protocols-policies.diff && \
    pip install --isolated --quiet --no-input --no-cache-dir \
      --disable-pip-version-check --no-deps --no-build-isolation \
      --break-system-packages --compile --root-user-action=ignore /tmp/haas-proxy && \
    rm -r /tmp/haas-proxy/ && \
    apk del patch py3-pip

RUN set -ex && \
    adduser -S haas-proxy

ENV PYTHONWARNINGS="ignore::UserWarning:twisted.conch.ssh.transport:97,\
ignore::UserWarning:twisted.conch.ssh.transport:101,\
ignore::UserWarning:twisted.conch.ssh.transport:106,\
ignore::UserWarning:twisted.conch.ssh.transport:107"

ENV DEVICE_TOKEN="" ARGS=""

USER haas-proxy
SHELL ["/bin/sh", "-c"]
CMD exec python3 -m haas_proxy --nodaemon --pidfile= haas_proxy --device-token ${DEVICE_TOKEN} ${ARGS}

EXPOSE 2222/tcp

HEALTHCHECK --interval=5s --timeout=1s --start-interval=2s CMD nc -z -w 1 -n 127.0.0.1 2222

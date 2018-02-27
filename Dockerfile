FROM alpine:3.5

ADD . /proxy

RUN apk add --no-cache \
	gcc \
	musl-dev \
	python3-dev \
	py3-pip \
	py3-cffi \
	py3-cryptography \
	ca-certificates \
	sshpass \
	openssh
RUN pip3 install --upgrade pip

RUN python3 -m pip install /proxy
RUN rm -rf /proxy

EXPOSE 2222

CMD python3 -m haas_proxy --nodaemon haas_proxy --device-token ${DEVICE_TOKEN}

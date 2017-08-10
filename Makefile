
.PHONY: all prepare-dev test lint run-py2 run-py3 build clean

FPM_CMD=fpm -f -d sshpass -m 'haas@nic.cz' -s python
FPM_CMD_PY2=${FPM_CMD} --python-bin /usr/bin/python2 --python-package-name-prefix python
FPM_CMD_PY3=${FPM_CMD} --python-bin /usr/bin/python3 --python-package-name-prefix python3

all:
	@echo "make prepare-dev"
	@echo "make test"
	@echo "make lint"
	@echo "make run"
	@echo "make build"
	@echo "make clean"


prepare-dev:
	@# lib*-dev and cffi for building cryptography, dependency of twisted.
	apt-get install -y python python-dev python-pip python3 python3-dev python3-pip sshpass libffi-dev libssl-dev libxml2-dev libxslt1-dev libjpeg8-dev zlib1g-dev
	python2 -m pip install -U cffi
	python3 -m pip install -U cffi
	python2 -m pip install -e .[test]
	python3 -m pip install -e .[test]

    # Build dependencies
	apt-get install -y ruby ruby-dev rubygems build-essential rpm
	gem install --no-ri --no-rdoc fpm

test:
	if [ `which python2` ]; then python2 -m pytest test_honeypot_proxy.py; fi
	if [ `which python3` ]; then python3 -m pytest test_honeypot_proxy.py; fi

lint:
	python3 -m pylint --rcfile=pylintrc honeypot_proxy.py

run-py2:
	sudo python2 honeypot_proxy.py --device-token 42
run-py3:
	sudo python3 honeypot_proxy.py --device-token 42

build:
	# Debian packages
	${FPM_CMD_PY2} -t deb setup.py
	${FPM_CMD_PY3} -t deb setup.py

	# Red Hat packages
	${FPM_CMD_PY2} -t rpm setup.py
	${FPM_CMD_PY3} -t rpm setup.py

    # Just archive, no deps
	${FPM_CMD} -t tar setup.py

clean:
	python setup.py clean
	rm -rf *.deb *.rpm *.tar

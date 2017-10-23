
.PHONY: all prepare-dev test lint run-py2 run-py3 release build clean
SHELL=/bin/bash

# Normally it would be just twistd but it runs always with Python 2 in this moment.
TWISTD_CMD=-m haas_proxy
TWISTD_RUN_ARGS=-l haas.log -n haas_proxy -d ${DEVICE_TOKEN}

FPM_CMD=fpm -f -d sshpass -m 'haas@nic.cz' -s python
FPM_CMD_PY2=${FPM_CMD} --python-bin /usr/bin/python2 --python-package-name-prefix python
FPM_CMD_PY3=${FPM_CMD} --python-bin /usr/bin/python3 --python-package-name-prefix python3 --python-install-lib /usr/lib/python3/dist-packages

all:
	@echo "make prepare-dev"
	@echo "make test"
	@echo "make lint"
	@echo "make run"
	@echo "make build"
	@echo "make clean"


prepare-dev:
	@# lib*-dev and cffi for building cryptography, dependency of twisted.
	apt-get install -y python python-dev python-pip python3 python3-dev python3-pip sshpass libffi-dev libssl-dev
	python2 -m pip install -U cffi
	python3 -m pip install -U cffi
	python2 -m pip install -e .[test]
	python3 -m pip install -e .[test]

    # Build dependencies
	apt-get install -y ruby ruby-dev rubygems build-essential rpm
	gem install --no-ri --no-rdoc fpm

test:
	if [ `which python2` ]; then python2 -m pytest test_haas_proxy.py; fi
	if [ `which python3` ]; then python3 -m pytest test_haas_proxy.py; fi

lint:
	python3 -m pylint --rcfile=pylintrc haas_proxy haas_proxy/twisted/plugins/haas_proxy_plugin.py

run-py2:
	python2 ${TWISTD_CMD} ${TWISTD_RUN_ARGS}
run-py3:
	python3 ${TWISTD_CMD} ${TWISTD_RUN_ARGS}

release: build
	rm -rf release
	mkdir release
	mv *deb *rpm *tar.gz release
	cd release; for f in `ls`; do md5sum "$${f}" > "$${f}.checksum"; done

upload:
	python3 setup.py register sdist upload

build:
	# Debian packages
	${FPM_CMD_PY2} -t deb setup.py
	${FPM_CMD_PY3} -t deb setup.py

	# Red Hat packages
	${FPM_CMD_PY2} -t rpm setup.py
	${FPM_CMD_PY3} -t rpm setup.py

    # Just archive, no deps
	python setup.py sdist --formats=gztar --dist-dir .

clean:
	python setup.py clean
	rm -rf *.deb *.rpm *.tar

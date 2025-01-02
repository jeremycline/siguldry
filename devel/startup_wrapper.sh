#!/bin/bash

set -eu

# Gross hack to inject the correct config when running in CI
if [ -v CI ]; then
	cp /etc/sigul-pesign-bridge-ci/* /etc/sigul/
fi

if [ -v RUN_SIGUL_SERVER ]; then
	sigul_server -v -v
elif [ -v RUN_SIGUL_BRIDGE ]; then
	sigul_bridge -v -v
else
	exec /bin/bash
fi


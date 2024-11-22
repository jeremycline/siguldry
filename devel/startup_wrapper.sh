#!/bin/bash

set -eu

if [ -v RUN_SIGUL_SERVER ]; then
	sigul_server -v -v
elif [ -v RUN_SIGUL_BRIDGE ]; then
	sigul_bridge -v -v
else
	exec /bin/bash
fi


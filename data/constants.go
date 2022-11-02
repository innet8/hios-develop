package data

const ExecContent = string(`#!/bin/bash
echo "---------- cmd start ----------"

{{.CMD}}

CMD_RUN_RESULT=$?

echo "---------- cmd end ----------"

if [[ 0 -eq $CMD_RUN_RESULT ]]; then
	exit 1
fi

if [ -n "{{.END_PATH}}" ]; then
	echo "{{.END_TAG}}" > {{.END_PATH}}
fi
`)

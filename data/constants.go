package data

const ExecContent = string(`#!/bin/bash
echo "---------- cmd start ----------"

{{.CMD}}

echo "---------- cmd end ----------"

if [ -n "{{.END_PATH}}" ]; then
	echo "{{.END_TAG}}" > {{.END_PATH}}
fi
`)

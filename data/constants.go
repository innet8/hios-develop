package data

const ExecContent = string(`#!/bin/bash
{{.CMD}}

if [ -n "{{.END_PATH}}" ]; then
	echo "{{.END_TAG}}" > {{.END_PATH}}
fi
`)

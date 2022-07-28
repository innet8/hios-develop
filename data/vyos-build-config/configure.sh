#!/bin/bash

file=$1
if [ -f "${file}" ]; then
    expect <<-EOF
set timeout 30
spawn su vyos
expect "$" { send "configure\n" }
expect "#" { send "load ${file}\n" }
expect "#" { send "commit\n" }
expect "#" { send "exit\n" } expect eof
interact
EOF
fi

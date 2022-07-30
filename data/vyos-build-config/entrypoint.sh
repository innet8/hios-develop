#!/bin/bash

binDir="/usr/lib/hicloud/bin"

load_init() {
    if [ -f ${binDir}/hios ]; then
        chmod +x ${binDir}/hios
    fi

    if [ -f ${binDir}/xray ]; then
        chmod +x ${binDir}/xray
    fi

    expect <<EOF
set timeout 30
spawn su vyos
expect "$" { send "configure\n" }
expect "#" { send "set interfaces ethernet eth0 ipv6 address no-default-link-local\n" }
expect "#" { send "set system name-server 8.8.8.8\n" }
expect "#" { send "commit\n" }
expect "#" { send "exit\n" } expect eof
interact
EOF
    echo "nameserver 127.0.0.11" > /etc/resolv.dnsmasq.conf

    exist=`ps -ef | grep "${binDir}/hios work" | grep -v "grep"`
    if [ -z "$exist" ]; then
        nohup ${binDir}/hios work > /dev/null 2>&1 &
    fi
}

load_boot() {
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
}

########################################################################
########################################################################
########################################################################

if [ "$1" = "load" ]; then
    # 加载配置文件：文件路径
    load_boot $2
else
    # 初始化并启动hios
    load_init
fi
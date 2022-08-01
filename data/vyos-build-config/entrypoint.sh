#!/bin/bash

binDir="/usr/lib/hicloud/bin"
logDir="/usr/lib/hicloud/log"

check_user() {
    n=1
    while true; do
        if id -u vyos >/dev/null 2>&1 ; then
            if [ "$n" -gt 1 ]; then
                sleep 3
            fi
            break
        else
            if [ "$n" -gt 10 ]; then
                echo "user vyos does not exist, failed exit"
                exit 2
            else
                echo "user vyos does not exist, try again later ${n}"
                sleep 5
            fi
        fi
        n=$(($n+1))
    done
}

load_init() {
    echo "----init start: $(date "+%Y-%m-%d %H:%M:%S")----"

    if [ -f ${binDir}/hios ]; then
        chmod +x ${binDir}/hios
    fi

    if [ -f ${binDir}/xray ]; then
        chmod +x ${binDir}/xray
    fi

    if [ -n "${HI_NETIP}" ] && [ -n "${HI_NETGW}" ]; then
        check_user
        expect <<EOF
set timeout 300
spawn su vyos
expect -ex "$" { send "configure\n" }
expect -ex "#" { send "export TERM=xterm\n" }
expect -ex "#" { send "set system name-server 8.8.8.8\n" }
expect -ex "#" { send "set protocols static route 0.0.0.0/0 next-hop ${HI_NETGW}\n" }
expect -ex "#" { send "set interfaces ethernet eth0 address ${HI_NETIP}/24\n" }
expect -ex "#" { send "set interfaces ethernet eth0 ipv6 address no-default-link-local\n" }
expect -ex "#" { send "commit\n" }
expect -ex "#" { send "exit\n" }
expect -ex "$" { send "exit\n" }
expect eof
EOF
    fi

    cat > /etc/dnsmasq.conf <<EOF
user=dnsmasq
all-servers
cache-size=150
clear-on-reload
resolv-file=/etc/resolv.dnsmasq.conf
conf-dir=/etc/dnsmasq.d
EOF
    echo "nameserver 127.0.0.11" > /etc/resolv.dnsmasq.conf

    exist=`ps -ef | grep "${binDir}/hios work" | grep -v "grep"`
    if [ -z "$exist" ]; then
        nohup ${binDir}/hios work > /dev/null 2>&1 &
    fi

    echo "----init end: $(date "+%Y-%m-%d %H:%M:%S")----"
}

load_config() {
    loadFile=$1
    echo "----config start: $(date "+%Y-%m-%d %H:%M:%S")----"
    if [ -f "${loadFile}" ]; then
        check_user
        expect <<EOF
set timeout 300
spawn su vyos
expect -ex "$" { send "configure\n" }
expect -ex "#" { send "export TERM=xterm\n" }
expect -ex "#" { send "load ${loadFile}\n" }
expect -ex "#" { send "commit\n" }
expect -ex "#" { send "exit\n" }
expect -ex "$" { send "exit\n" }
expect eof
EOF
    fi
    echo "----config end: $(date "+%Y-%m-%d %H:%M:%S")----"
}

########################################################################
########################################################################
########################################################################

if [ "$1" = "config" ]; then
    # 加载配置文件 {文件路径}
    load_config $2 >> ${logDir}/config.log
else
    # 初始化日志
    mkdir -p ${logDir}
    rm -f ${logDir}/init.log
    rm -f ${logDir}/config.log
    # 初始化并启动hios
    sleep 10
    load_init >> ${logDir}/init.log
fi
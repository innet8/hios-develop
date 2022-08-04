#!/bin/bash

binDir="/usr/lib/hicloud/bin"
logDir="/usr/lib/hicloud/log"

check_user() {
    local n=1
    while true; do
        if id -u vyos >/dev/null 2>&1 ; then
            if [ "$n" -gt 1 ]; then
                sleep 1
            fi
            break
        else
            echo "User vyos not exist, retry ${n}th in 5s"
            sleep 5
        fi
        n=$(($n+1))
    done
}

check_loader() {
    local exist
    local n=1
    while true; do
        exist=`ps -ef | grep "vyos-boot-config-loader.py" | grep -v "grep"`
        if [ -z "$exist" ]; then
            if [ "$n" -gt 1 ]; then
                sleep 1
            fi
            break
        else
            echo "Config loading, retry ${n}th in 5s"
            sleep 5
        fi
        n=$(($n+1))
    done
    chown -R root:vyattacfg /opt/vyatta/config/active/ &> /dev/null
}

check_network() {
    local ret_code=`curl -I -s --connect-timeout 1 -m 5 ${HI_URL} -w %{http_code} | tail -n1`
    if [ "x$ret_code" = "x200" ] || [ "x$ret_code" = "x301" ] || [ "x$ret_code" = "x302" ]; then
        return 1
    else
        return 0
    fi
    return 0
}

check_configure() {
    local n=1
    while true; do
        expect <<EOF
set timeout 300
spawn su vyos
expect -ex "$" { send "configure\n" }
expect -ex "#" { send "export TERM=xterm\n" }
expect -ex "#" { send "set system name-server 127.0.0.1\n" }
expect -ex "#" { send "set protocols static route 0.0.0.0/0 next-hop ${HI_NETGW}\n" }
expect -ex "#" { send "set interfaces ethernet eth0 address ${HI_NETIP}/24\n" }
expect -ex "#" { send "set interfaces ethernet eth0 ipv6 address no-default-link-local\n" }
expect -ex "#" { send "commit\n" }
expect {
    -ex "exit discard" { send "sleep 3 && commit\n"; exp_continue }
    -ex "#" { send "exit\n"; exp_continue }
    -ex "$" { send "exit\n" }
}
expect eof
EOF
        check_network
        if [ $? -eq 0 ]; then
            echo "Network unreachable, retry ${n}th in 5s"
            sleep 5
        else
            break
        fi
        n=$(($n+1))
    done
}

check_iptables() {
    [ -z "`iptables-legacy -L POSTROUTING -nvt nat | grep " eth0 "`" ] && {
        iptables-legacy -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    }
}

check_dnsmasq() {
    cat > /etc/dnsmasq.conf <<EOF
user=dnsmasq
all-servers
except-interface=eth0
cache-size=1000
clear-on-reload
resolv-file=/etc/resolv.dnsmasq.conf
conf-dir=/etc/dnsmasq.d
EOF
    cat > /etc/resolv.dnsmasq.conf <<EOF
nameserver 127.0.0.11
nameserver 8.8.8.8
EOF
    cat > /etc/resolv.conf <<EOF
nameserver 127.0.0.1
EOF
    systemctl restart dnsmasq
}

load_init() {
    echo "----start: $(date "+%Y-%m-%d %H:%M:%S")----"

    if [ -f ${binDir}/hios ]; then
        chmod +x ${binDir}/hios
    fi

    if [ -f ${binDir}/xray ]; then
        chmod +x ${binDir}/xray
    fi

    if [ -n "${HI_URL}" ] && [ -n "${HI_NETIP}" ] && [ -n "${HI_NETGW}" ]; then
        check_user
        check_loader
        check_configure
        check_iptables
        check_dnsmasq

        local exist=`ps -ef | grep "${binDir}/hios work" | grep -v "grep"`
        if [ -z "$exist" ]; then
            echo "Start hios work"
            nohup ${binDir}/hios work > /dev/null 2>&1 &
        else
            echo "Hios not exist"
        fi
    else
        echo "Environment variable error"
    fi

    echo "----end: $(date "+%Y-%m-%d %H:%M:%S")----"
}

load_config() {
    loadFile=$1
    echo "----start: $(date "+%Y-%m-%d %H:%M:%S")----"
    if [ -f "${loadFile}" ]; then
        check_user
        check_loader
        expect <<EOF
set timeout 300
spawn su vyos
expect -ex "$" { send "configure\n" }
expect -ex "#" { send "export TERM=xterm\n" }
expect -ex "#" { send "load ${loadFile}\n" }
expect -ex "#" { send "commit\n" }
expect {
    -ex "exit discard" { send "sleep 3 && commit\n"; exp_continue }
    -ex "#" { send "exit\n"; exp_continue }
    -ex "$" { send "exit\n" }
}
expect eof
EOF
    fi
    echo "----end: $(date "+%Y-%m-%d %H:%M:%S")----"
}

########################################################################
########################################################################
########################################################################

if [ "$1" = "config" ]; then
    # 加载配置文件 {文件路径}
    load_config $2 >> ${logDir}/config.log
else
    # 初始化并启动hios
    load_init >> ${logDir}/init.log
fi
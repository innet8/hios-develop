#!/bin/bash

binDir="/usr/lib/hicloud/bin"
logDir="/usr/lib/hicloud/log"
defaultConfigFile="/usr/lib/hicloud/share/default.config.boot"

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
    save_default_config_file
    local n=1
    while true; do
        expect <<EOF
set timeout 300
spawn su vyos
expect -ex "$" { send "configure\n" }
expect -ex "#" { send "export TERM=xterm\n" }
expect -ex "#" { send "load ${defaultConfigFile}\n" }
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
    if [ -z "`iptables-legacy -L POSTROUTING -nvt nat | grep " eth0 "`" ]; then
        iptables-legacy -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    fi
    if [ -z "`iptables-legacy -L -nvt mangle | grep "shunt-100"`" ]; then
        for ((i=1;i<=100;i++)); do
            iptables-legacy -t mangle -N shunt-${i}
            iptables-legacy -t mangle -A PREROUTING -j shunt-${i}
        done
    fi
    if [ -z "`iptables-legacy -L -nvt nat | grep "shunt-100"`" ]; then
        for ((i=1;i<=100;i++)); do
            iptables-legacy -t nat -N shunt-${i}
            iptables-legacy -t nat -A PREROUTING -j shunt-${i}
        done
    fi
}

save_default_config_file() {
  mkdir -p $(dirname ${defaultConfigFile})
  if [ -f "${defaultConfigFile}" ]; then
    return
  fi
  cat > ${defaultConfigFile} <<EOF
interfaces {
  ethernet eth0 {
    address 10.8.8.210/24
    ipv6 {
      address {
        no-default-link-local
      }
    }
  }
}
protocols {
  static {
    route 0.0.0.0/0 {
      next-hop 10.8.8.1 {
      }
    }
  }
}
nat {
  source {
    rule 100 {
      outbound-interface eth0
      translation {
        address masquerade
      }
    }
  }
}
system {
  config-management {
    commit-revisions 100
  }
  conntrack {
    modules {
      ftp
      h323
      nfs
      pptp
      sip
      sqlnet
      tftp
    }
  }
  console {
    device ttyS0 {
      speed 115200
    }
  }
  host-name vyos
  login {
    user vyos {
      authentication {
        encrypted-password $6$QxPS.uk6mfo$9QBSo8u1FkH16gMyAVhus6fU3LOzvLR9Z9.82m3tiHFAxTtIkhaZSWssSgzt4v4dGAL8rhVQxTg0oAG9/q11h/
        plaintext-password ""
      }
    }
  }
  name-server 127.0.0.1
  syslog {
    global {
      facility all {
        level info
      }
      facility protocols {
        level debug
      }
    }
  }
}
// vyos-config-version: "bgp@2:broadcast-relay@1:cluster@1:config-management@1:conntrack@3:conntrack-sync@2:dhcp-relay@2:dhcp-server@6:dhcpv6-server@1:dns-forwarding@3:firewall@7:flow-accounting@1:https@3:interfaces@26:ipoe-server@1:ipsec@9:isis@1:l2tp@4:lldp@1:mdns@1:monitoring@1:nat@5:nat66@1:ntp@1:openconnect@2:ospf@1:policy@3:pppoe-server@5:pptp@2:qos@1:quagga@10:rpki@1:salt@1:snmp@2:ssh@2:sstp@4:system@25:vrf@3:vrrp@3:vyos-accel-ppp@2:wanloadbalance@3:webproxy@2"
EOF
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

check_sysctl() {
    if [ -z "$(cat /etc/sysctl.conf | grep 'net.ipv6.conf.all.disable_ipv6')" ]; then
        echo "net.ipv6.conf.all.disable_ipv6 = 0" >> /etc/sysctl.conf
    else
        sed -i "/net.ipv6.conf.all.disable_ipv6/c net.ipv6.conf.all.disable_ipv6 = 0" /etc/sysctl.conf
    fi
    if [ -z "$(cat /etc/sysctl.conf | grep 'net.ipv6.conf.default.disable_ipv6')" ]; then
        echo "net.ipv6.conf.default.disable_ipv6 = 0" >> /etc/sysctl.conf
    else
        sed -i "/net.ipv6.conf.default.disable_ipv6/c net.ipv6.conf.default.disable_ipv6 = 0" /etc/sysctl.conf
    fi
    if [ -z "$(cat /etc/sysctl.conf | grep 'net.ipv6.conf.lo.disable_ipv6')" ]; then
        echo "net.ipv6.conf.lo.disable_ipv6 = 0" >> /etc/sysctl.conf
    else
        sed -i "/net.ipv6.conf.lo.disable_ipv6/c net.ipv6.conf.lo.disable_ipv6 = 0" /etc/sysctl.conf
    fi
    sysctl -p
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
        check_sysctl

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
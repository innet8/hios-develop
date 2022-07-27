#!/bin/bash

binDir="/usr/lib/hicloud/bin"

get_wsurl() {
    local host=$(echo "$SERVER_URL" | awk -F "/" '{print $3}')
    local exi=$(echo "$SERVER_URL" | grep 'https://')
    if [ -n "$exi" ]; then
        echo "wss://${host}/ws"
    else
        echo "ws://${host}/ws"
    fi
}

check_network() {
    local target=$SERVER_URL
    local ret_code=`curl -I -s --connect-timeout 1 -m 5 ${target} -w %{http_code} | tail -n1`
    if [ "x$ret_code" = "x200" ] || [ "x$ret_code" = "x301" ] || [ "x$ret_code" = "x302" ]; then
        return 1
    else
        return 0
    fi
    return 0
}

check_work() {
    local url=`get_wsurl`
    local exist=`ps -ef | grep "${binDir}/hios work" | grep -v "grep"`
    [ -n "$url" ] && [ -z "$exist" ] && {
        check_network
        if [ $? -eq 0 ]; then
            echo "network is blocked, try again 10 seconds"
        else
            echo "${url}?action=nodework&nodemode=${NODE_MODE}&nodename=${NODE_NAME}&nodetoken=${NODE_TOKEN}&hostname=${HOSTNAME}" > ${binDir}/.hios-work-server
            nohup ${binDir}/hios work > /dev/null 2>&1 &
        fi
    }
}

init_network() {
    expect <<EOF
set timeout 30
spawn su vyos
expect "$" { send "configure\n" }
expect "#" { send "set interfaces ethernet eth0 ipv6 address no-default-link-local\n" }
expect "#" { send "set system name-server 8.8.8.8\n" }
expect "#" { send "commit\n" }
expect "#" { send "exit\n" } expect eof
EOF
}

init_work() {
    if [ -f ${binDir}/hios ]; then
        chmod +x ${binDir}/hios
    fi

    if [ -f ${binDir}/xray ]; then
        chmod +x ${binDir}/xray
    fi

    while true; do
        sleep 10
        check_work > /dev/null 2>&1 &
    done
}


RUNDIR=$(cd `dirname $0`; pwd)
PIDFILE="${RUNDIR}/.entrypoint.pid"

if [ -s ${PIDFILE} ]; then
   SPID=`cat ${PIDFILE}`
   if [ -e /proc/${SPID}/status ]; then
      echo "The script is already running."
      exit 1
  fi
  cat /dev/null > ${PIDFILE}
fi
echo $$ > ${PIDFILE}

init_network
init_work

cat /dev/null > ${PIDFILE}
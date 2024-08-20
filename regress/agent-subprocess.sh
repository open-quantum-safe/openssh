#	$OpenBSD: agent-subprocess.sh,v 1.1 2020/06/19 05:07:09 dtucker Exp $
#	Placed in the Public Domain.

tid="agent subprocess"

is_alive() {
	kill -0 ${1} >/dev/null 2>&1 && [ `ps -p ${1} -o state=` != "Z" ]
}

trace "ensure agent exits when run as subprocess"
${SSHAGENT} sh -c "echo \$SSH_AGENT_PID >$OBJ/pidfile; sleep 1"

pid=`cat $OBJ/pidfile`

# Currently ssh-agent polls every 10s so we need to wait at least that long.
n=12
while is_alive ${pid} && test "$n" -gt "0"; do
	n=$(($n - 1))
	sleep 1
done

if test "$n" -eq "0"; then
	fail "agent still running"
fi

rm -f $OBJ/pidfile

#!/opt/vyatta/bin/cliexec
GID=$(getent group  | grep '^$VAR(@):' | cut -d: -f3)
GID_MIN=$(awk '/^GID_MIN/{ print $2 }' </etc/login.defs)
if [[ $GID -gt $GID_MIN || $GID -eq $GID_MIN ]]; then
    groupdel $VAR(@) 2>/dev/null || builtin exit 0
fi

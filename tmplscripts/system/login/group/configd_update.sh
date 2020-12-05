#!/opt/vyatta/bin/cliexec
GID_MIN=$(awk '/^GID_MIN/{ print $2 }' </etc/login.defs)
groupadd -f -g $GID_MIN $VAR(@)

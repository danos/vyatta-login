#!/opt/vyatta/bin/cliexec
sed -i -e '/* - maxsyslogins/d' /etc/security/limits.conf

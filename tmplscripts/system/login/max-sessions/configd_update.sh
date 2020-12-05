#!/opt/vyatta/bin/cliexec
sed -i -e '/* - maxsyslogins/d' /etc/security/limits.conf
echo '* - maxsyslogins $VAR(@)' >> /etc/security/limits.conf

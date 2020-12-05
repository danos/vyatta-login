#!/opt/vyatta/bin/cliexec
sh -c "cat <<EOF >|/etc/profile.d/autologout.sh
TMOUT=$VAR(@)
readonly TMOUT
export TMOUT
EOF"

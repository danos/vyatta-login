#!/opt/vyatta/bin/cliexec
awk -F: '
$1 == "routeadm" || $1 == "vyattacfg" || $1 == "vyattaop" || \
    $1 == "vyattaadm" || $1 == "vyattasu" || \
    $1 == "sudo" || $1 == "adm" || $1 == "operator" { next; }
{printf "%s ", $1}' <<<"$VAR(/system/login/group/@@)"

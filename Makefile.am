SUBDIRS = . src

share_perl5dir = $(datarootdir)/perl5/Vyatta
share_perl5_logindir = $(datarootdir)/perl5/Vyatta/Login
etcdir = /etc
initddir = /etc/init.d
vpamcfgdir = /opt/vyatta/etc/pam-configs
pamconfigdir = /usr/share/pam-configs
templatedir = $(datadir)/vyatta-op/templates
tmplscriptdir = $(datadir)/tmplscripts
yangdir = /usr/share/configd/yang
vyatta_securitydir = /opt/vyatta/etc/security/

bin_PROGRAMS =
bin_SCRIPTS =
sbin_SCRIPTS =
sysconf_DATA =
initd_SCRIPTS =

pamconfig_DATA = usr/share/pam-configs/umask

bin_SCRIPTS  += scripts/check_old_passwords
bin_SCRIPTS  += scripts/encrypt_shadow_passwd
bin_SCRIPTS  += scripts/show-users-op
bin_SCRIPTS  += scripts/system/vyatta_tally_op
bin_SCRIPTS  += scripts/vyatta-login-history
bin_SCRIPTS  += scripts/vyatta-show-current-user
bin_SCRIPTS  += scripts/vyatta-show-login-history
sbin_SCRIPTS += scripts/standalone_root_pw_reset
sbin_SCRIPTS += scripts/vyatta-passwd-sync
sbin_SCRIPTS += scripts/system-login-information
sbin_SCRIPTS += scripts/system/vyatta_check_username.pl
sbin_SCRIPTS += scripts/system/vyatta_create_account
sbin_SCRIPTS += scripts/system/vyatta_tally_rpc
sbin_SCRIPTS += scripts/system/vyatta_update_login.pl
sbin_SCRIPTS += scripts/system/update_password_quality.pl
sbin_SCRIPTS += scripts/vyatta-banner.pl
sbin_SCRIPTS += scripts/vyatta-change-password

share_perl5_login_DATA = lib/Vyatta/Login/User.pm
share_perl5_login_DATA += lib/Vyatta/Login/Password.pm

vyatta_security_DATA = etc/security/pwquality.config.template

vyatta_preconfigddir = /opt/vyatta/preconfig.d
vyatta_preconfigd_SCRIPTS = preconfig.d/5000-banner

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(vpamcfgdir)
	mkdir -p $(DESTDIR)$(templatedir)
	cd templates && $(cpiop) $(DESTDIR)$(templatedir)
	mkdir -p $(DESTDIR)$(tmplscritdir)
	cd tmplscripts && $(cpiop) $(DESTDIR)$(tmplscriptdir)
	mkdir -p $(DESTDIR)$(yangdir)
	cd yang && $(cpiop) $(DESTDIR)$(yangdir)

#!/bin/bash
PATH=/www/server/panel/pyenv/bin:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

pluginPath=/www/server/panel/plugin/wafpro
enginePath=/www/server/wafpro
vhostPath=/www/server/panel/vhost/nginx
logPath=/www/wwwlogs/wafpro
geoDb=/www/server/panel/data/firewall/GeoLite2-Country.json
engineFiles="wafpro.lua detect.lua init.lua worker.lua waf.lua header.lua body.lua"

# Re-render every engine file from the panel's settings. Needed on update:
# a new engine may read a new rule format (2.1 switched sites.txt to named
# fields), and the old files would leave every site unprotected until the
# next settings save.
Compile_rules()
{
	cd /www/server/panel && python3 -c "
import sys
sys.path.insert(0, 'class'); sys.path.insert(0, '$pluginPath')
import wafpro_main
wafpro_main.wafpro_main()._compile()
" 2>&1 | tail -3
}

# libinjection (engine/libinjection, BSD-3) decides SQLi/XSS for the engine
# through LuaJIT's FFI. Without a compiler the engine falls back to its own
# Lua analysers, so a failed build is a warning, not an error.
Build_libinjection()
{
	src=$pluginPath/engine/libinjection
	[ -d $src ] || return
	if ! command -v gcc >/dev/null 2>&1; then
		echo "NOTE: gcc not found — SQLi/XSS semantic analysis uses the built-in Lua analysers."
		return
	fi
	if gcc -O2 -fPIC -shared -o $enginePath/libinjection.so.new $src/*.c 2>/tmp/wafpro_libinjection.log; then
		mv -f $enginePath/libinjection.so.new $enginePath/libinjection.so
		chmod 644 $enginePath/libinjection.so
		echo "libinjection built"
	else
		rm -f $enginePath/libinjection.so.new
		echo "WARNING: libinjection build failed (see /tmp/wafpro_libinjection.log); using the built-in analysers."
	fi
}

Install_wafpro()
{
	mkdir -p $pluginPath/cache $pluginPath/export $pluginPath/rules $pluginPath/webshell
	mkdir -p $enginePath/rule $logPath
	chmod 700 $pluginPath/cache $pluginPath/export $pluginPath/webshell
	# nginx workers run as www: they read the engine + rules and write the
	# block log, so those must be reachable for www or the engine silently
	# runs without rules / without logging.
	chmod 755 $enginePath $enginePath/rule
	chown -R www:www $logPath 2>/dev/null

	if [ -f $pluginPath/icon.png ]; then
		\cp -a -r $pluginPath/icon.png /www/server/panel/BTPanel/static/img/soft_ico/ico-wafpro.png 2>/dev/null
	fi

	# The engine ships with this module — no other WAF plugin is required.
	for f in $engineFiles; do
		\cp -f $pluginPath/engine/$f $enginePath/$f 2>/dev/null
		chmod 644 $enginePath/$f 2>/dev/null
	done
	# Drop the old per-request loader from pre-2.0 layouts (engine is cached now)
	rm -f $enginePath/loader.lua
	Build_libinjection

	# The panel ships the country DB but no longer refreshes it (task.py's
	# flush_geoip is commented out), so fetch it ourselves when missing.
	if [ ! -s $geoDb ]; then
		echo "Country database missing — downloading..."
		mkdir -p /www/server/panel/data/firewall
		wget -q -O $geoDb "http://download.bt.cn/install/lib/GeoLite2-Country.json" -T 30
		if [ ! -s $geoDb ]; then
			echo "WARNING: could not fetch GeoLite2-Country.json; the Region tab will be empty."
		fi
	fi

	Compile_rules

	# Already wired (an update): the engine is cached at nginx start, so the
	# new lua only runs after a reload — and only reload on a passing test.
	if [ -f $vhostPath/wafpro.conf ]; then
		cp -f $vhostPath/wafpro.conf /tmp/wafpro.conf.bak
		\cp -f $pluginPath/engine/wafpro.conf $vhostPath/wafpro.conf
		if /www/server/nginx/sbin/nginx -t >/dev/null 2>&1; then
			/etc/init.d/nginx reload >/dev/null 2>&1
			echo "Engine updated and nginx reloaded"
		else
			cp -f /tmp/wafpro.conf.bak $vhostPath/wafpro.conf
			echo "WARNING: nginx -t failed with the new engine conf; kept the old one"
		fi
	fi

	echo 'Successify'
}

# Wiring nginx is deliberately NOT done on a fresh install: only one lua WAF
# can own the access phase, and a bad config stops nginx for every site on the
# box. The panel does it behind a guarded button (writes conf -> nginx -t ->
# rollback on failure -> reload only on success).
Uninstall_wafpro()
{
	# origin-response tracking: point the sites back at the default log
	# format before dropping ours (a format still in use cannot go)
	if [ -f $vhostPath/0.wafpro_log_format.conf ]; then
		sed -i -E 's#(access_log[[:space:]]+/[^[:space:]]+\.log)[[:space:]]+wafpro[[:space:]]*;#\1;#' $vhostPath/*.conf
		rm -f $vhostPath/0.wafpro_log_format.conf
	fi
	rm -f $vhostPath/wafpro.conf
	if /www/server/nginx/sbin/nginx -t 2>/dev/null; then
		/etc/init.d/nginx reload 2>/dev/null
	fi
	rm -f /www/server/panel/BTPanel/static/img/soft_ico/ico-wafpro.png
	rm -rf $enginePath
	rm -rf $pluginPath
	echo 'Successify'
}

case "$1" in
	install) Install_wafpro ;;
	update)  Install_wafpro ;;
	uninstall) Uninstall_wafpro ;;
	*) Install_wafpro ;;
esac

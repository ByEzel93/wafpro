#!/bin/bash
PATH=/www/server/panel/pyenv/bin:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

pluginPath=/www/server/panel/plugin/wafpro
enginePath=/www/server/wafpro
vhostPath=/www/server/panel/vhost/nginx
logPath=/www/wwwlogs/wafpro
geoDb=/www/server/panel/data/firewall/GeoLite2-Country.json

Install_wafpro()
{
	mkdir -p $pluginPath/cache $pluginPath/export $pluginPath/rules
	mkdir -p $enginePath/rule $logPath
	chmod 700 $pluginPath/cache $pluginPath/export
	# nginx workers run as www and must be able to write the block log; the dir
	# is created by root, so hand it to www or logging silently fails.
	chown -R www:www $logPath 2>/dev/null

	if [ -f $pluginPath/icon.png ]; then
		\cp -a -r $pluginPath/icon.png /www/server/panel/BTPanel/static/img/soft_ico/ico-wafpro.png
	fi

	# The engine ships with this module — no other WAF plugin is required.
	\cp -a -f $pluginPath/engine/wafpro.lua \
	          $pluginPath/engine/init.lua $pluginPath/engine/worker.lua \
	          $pluginPath/engine/waf.lua $enginePath/ 2>/dev/null
	# Drop the old per-request loader from pre-2.0 layouts (engine is cached now)
	rm -f $enginePath/loader.lua

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

	echo 'Successify'
}

# Wiring nginx is deliberately NOT done here: only one lua WAF can own the
# access phase, and a bad config stops nginx for every site on the box. The
# panel does it behind a guarded button (writes conf -> nginx -t -> rollback
# on failure -> reload only on success).
Uninstall_wafpro()
{
	if [ -f $vhostPath/wafpro.conf ]; then
		rm -f $vhostPath/wafpro.conf
		if /www/server/nginx/sbin/nginx -t 2>/dev/null; then
			/etc/init.d/nginx reload 2>/dev/null
		fi
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

#!/usr/bin/python
# coding: utf-8
# +-------------------------------------------------------------------
# | WAF Pro — standalone Nginx WAF for aaPanel
# +-------------------------------------------------------------------
# | Self-contained: ships its own lua engine (/www/server/wafpro) and its
# | own config, rules and logs. It does not read, write or require the
# | "Nginx free firewall" plugin — installing this module is enough.
# |
# | The panel side is the source of truth (config.json / site.json here in
# | the plugin dir) and compiles that down into the plain-text + packed
# | binary files the lua reads, then bumps rule/version. Workers poll the
# | version, so saving a setting never needs an nginx reload.
# +-------------------------------------------------------------------
import os
import re
import sys
import json
import time
import struct

os.chdir('/www/server/panel')
if 'class/' not in sys.path:
    sys.path.insert(0, 'class/')

import public

PLUGIN_PATH = '/www/server/panel/plugin/wafpro/'
ENGINE_PATH = '/www/server/wafpro/'
RULE_DIR = ENGINE_PATH + 'rule/'
WAF_LOG_DIR = '/www/wwwlogs/wafpro/'
NGINX_CONF_D = '/www/server/panel/vhost/nginx/'

if PLUGIN_PATH not in sys.path:
    sys.path.insert(0, PLUGIN_PATH)


class wafpro_main:

    # ----------------------------------------------------------------
    # helpers
    # ----------------------------------------------------------------
    def _dash(self):
        import importlib
        import wafpro_dash
        importlib.reload(wafpro_dash)
        return wafpro_dash

    def _read_json(self, filename, default=None):
        '''public.readFile() returns False for a missing file, which would
        blow up json.loads — always go through this.'''
        try:
            body = public.readFile(filename)
        except Exception:
            body = None
        if not body or not isinstance(body, (str, bytes, bytearray)):
            return default
        try:
            return json.loads(body)
        except Exception:
            return default

    def _write_json(self, filename, data):
        return public.writeFile(filename, json.dumps(data, indent=2))

    # The panel's router reads `action`, `name` and `s` from the merged
    # GET+POST arguments (BTPanel get_input: form fields override the query
    # string). A form that posts a field called `action` or `name` therefore
    # hijacks the route itself and the panel answers "Specific parameters are
    # invalid!" before this plugin ever runs (issue #1). The UI posts those
    # values under other keys; this reads them back.
    RESERVED_ARGS = {'name': 'rname', 'action': 'act'}

    def _arg(self, get, key, default=''):
        alias = self.RESERVED_ARGS.get(key)
        if alias:
            v = getattr(get, alias, None)
            return default if v is None else v
        v = getattr(get, key, None)
        return default if v is None else v

    # ----------------------------------------------------------------
    # default rule sets (PCRE, matched case-insensitively by ngx.re.find)
    #
    # These run on live traffic, so they are deliberately conservative: each
    # one targets syntax that has no business in normal input, rather than
    # single keywords like "select" or "union" that appear in ordinary text
    # and would block real visitors. Users can add their own per set.
    # ----------------------------------------------------------------
    DEFAULT_RULES = {
        'get': [
            {'rule': r'\bunion\b[\s/*]+\bselect\b', 'ps': 'SQL injection — union select', 'open': True},
            {'rule': r'\bselect\b.{1,60}?\bfrom\b.{1,60}?\binformation_schema\b', 'ps': 'SQL injection — information_schema', 'open': True},
            {'rule': r'\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(', 'ps': 'SQL injection — time based', 'open': True},
            {'rule': r'\b(load_file|into\s+(out|dump)file)\b', 'ps': 'SQL injection — file access', 'open': True},
            {'rule': r"['\"\)]\s*(or|and)\s+['\"\d].{0,12}?=", 'ps': 'SQL injection — boolean', 'open': True},
            {'rule': r'<\s*script[\s>]', 'ps': 'XSS — script tag', 'open': True},
            {'rule': r'\bon(error|load|mouseover|focus|click)\s*=', 'ps': 'XSS — event handler', 'open': True},
            {'rule': r'javascript\s*:', 'ps': 'XSS — javascript uri', 'open': True},
            {'rule': r'(\.\./|\.\.%2f){2,}', 'ps': 'Path traversal', 'open': True},
            {'rule': r'\b(etc/passwd|proc/self/environ)\b', 'ps': 'Local file inclusion', 'open': True},
            {'rule': r'\$\{jndi:', 'ps': 'Log4Shell', 'open': True},
            {'rule': r'\b(system|exec|shell_exec|passthru|popen)\s*\(', 'ps': 'Command execution', 'open': True},
        ],
        'post': [
            {'rule': r'\bunion\b[\s/*]+\bselect\b', 'ps': 'SQL injection — union select', 'open': True},
            {'rule': r'\b(sleep|benchmark|pg_sleep)\s*\(', 'ps': 'SQL injection — time based', 'open': True},
            {'rule': r'\b(load_file|into\s+(out|dump)file)\b', 'ps': 'SQL injection — file access', 'open': True},
            {'rule': r'<\s*script[\s>]', 'ps': 'XSS — script tag', 'open': True},
            {'rule': r'\$\{jndi:', 'ps': 'Log4Shell', 'open': True},
            {'rule': r'\b(eval|assert|base64_decode)\s*\(\s*\$_(post|get|request)', 'ps': 'PHP webshell', 'open': True},
            {'rule': r'@eval\s*\(', 'ps': 'PHP webshell — eval', 'open': True},
        ],
        'cookie': [
            {'rule': r'\bunion\b[\s/*]+\bselect\b', 'ps': 'SQL injection via cookie', 'open': True},
            {'rule': r'<\s*script[\s>]', 'ps': 'XSS via cookie', 'open': True},
            {'rule': r'\$\{jndi:', 'ps': 'Log4Shell via cookie', 'open': True},
        ],
        'ua': [
            {'rule': r'\b(sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|wpscan)\b', 'ps': 'Scanner', 'open': True},
            {'rule': r'\b(acunetix|netsparker|havij|arachni|nessus|openvas|w3af)\b', 'ps': 'Vulnerability scanner', 'open': True},
            {'rule': r'^\s*$', 'ps': 'Empty user-agent', 'open': False},
        ],
        'scan': [
            {'rule': r'/\.(env|git|svn|hg)(/|$)', 'ps': 'Exposed VCS/env file', 'open': True},
            {'rule': r'/(wp-config|configuration)\.php[.~]', 'ps': 'Config file probe', 'open': True},
            {'rule': r'/\.(bash_history|ssh/|aws/)', 'ps': 'Sensitive dotfile', 'open': True},
            {'rule': r'\.(sql|bak|old|swp|zip|tar\.gz)$', 'ps': 'Backup/dump probe', 'open': False},
            {'rule': r'/(phpmyadmin|pma|adminer)\b', 'ps': 'Admin tool probe', 'open': False},
        ],
        # Virtual patches for widely exploited, public CVEs. Matched against
        # the decoded request line and urlencoded body, on sites with the
        # N-day switch on. Each pattern is the exploit's own fingerprint, not
        # a generic keyword, so it stays quiet on normal traffic.
        'nday': [
            {'rule': r'[?&](?:-|%ad|\xad)d[+\s]*(?:allow_url_include|auto_prepend_file)', 'ps': 'PHP-CGI argument injection (CVE-2024-4577 / CVE-2012-1823)', 'open': True},
            {'rule': r'\\think\\(?:app|container|request|template\\driver)', 'ps': 'ThinkPHP 5.x RCE (invokefunction)', 'open': True},
            {'rule': r'_method=__construct', 'ps': 'ThinkPHP 5.0.x RCE (_method=__construct)', 'open': True},
            {'rule': r'^/(?:application|runtime)/.+\.(?:log|php)$', 'ps': 'ThinkPHP 3.x log / cache disclosure', 'open': True},
            {'rule': r'/vendor/phpunit/phpunit/src/util/php/eval-stdin\.php', 'ps': 'PHPUnit eval-stdin RCE (CVE-2017-9841)', 'open': True},
            {'rule': r'/_ignition/execute-solution', 'ps': 'Laravel Ignition RCE (CVE-2021-3129)', 'open': True},
            {'rule': r'class\.module\.classloader', 'ps': 'Spring4Shell (CVE-2022-22965)', 'open': True},
            {'rule': r'/actuator/gateway/routes', 'ps': 'Spring Cloud Gateway RCE (CVE-2022-22947)', 'open': True},
            {'rule': r'/mgmt/tm/util/bash', 'ps': 'F5 BIG-IP iControl RCE (CVE-2021-22986)', 'open': True},
            {'rule': r'[%$]\{[^}]{0,200}(?:#_memberaccess|@java\.lang\.runtime|processbuilder|getruntime\(\))', 'ps': 'OGNL/EL injection (Struts2, Confluence CVE-2022-26134)', 'open': True},
            {'rule': r'/\.(?:%2e|\.)/(?:\.(?:%2e|\.)/|%2e%2e/)', 'ps': 'Apache path traversal (CVE-2021-41773/42013)', 'open': True},
            {'rule': r'/wp-content/plugins/wp-file-manager/lib/php/connector\.minimal\.php', 'ps': 'WP File Manager upload RCE (CVE-2020-25213)', 'open': True},
            {'rule': r'/wp-admin/admin-ajax\.php\?action=(?:revslider_show_image|duplicator_download)&', 'ps': 'WordPress plugin file read (RevSlider / Duplicator)', 'open': True},
            {'rule': r'/index\.php\?s=/?index/\\?think', 'ps': 'ThinkPHP route RCE probe', 'open': True},
            {'rule': r'/(?:solr/[^/]+/(?:dataimport|config)|druid/indexer/v1/sampler)', 'ps': 'Solr / Druid RCE probe', 'open': True},
            {'rule': r'/cgi-bin/(?:\.(?:%2e|\.)/|%2e%2e/)+', 'ps': 'cgi-bin traversal to shell', 'open': True},
        ],
    }

    # ----------------------------------------------------------------
    # our config model
    #
    # Panel side owns config.json / site.json in the plugin dir; _compile()
    # renders them into what the lua reads and bumps rule/version. The engine
    # never parses JSON — see the note at the top of wafpro.lua.
    # ----------------------------------------------------------------
    CONFIG = PLUGIN_PATH + 'config.json'
    SITES = PLUGIN_PATH + 'site.json'
    # Distinct name on purpose: the rt-tracking section below also defines a
    # NGINX_CONF (the main nginx.conf). Two class attributes with one name means
    # the later wins — which once pointed our "write the WAF conf" path straight
    # at nginx.conf and truncated it.
    WAFPRO_CONF = NGINX_CONF_D + 'wafpro.conf'

    DEFAULT_CONFIG = {
        'open': True,
        'log': True,
        'log_save': 30,
        'cdn': False,
        'get_status': 403,
        'post_status': 403,
        'cookie_status': 403,
        'ua_status': 403,
        'scan_status': 444,
        'cc_status': 444,
        'black_status': 444,
        'method_status': 405,
        'header_status': 403,
        'crawl_status': 429,
        # site req/s above which Smart CC starts tightening
        'smart_at': 50,
        # block IPs from the public abuse feed
        'mal_open': False,
        # auto-ban: retry blocks within retry_cycle s -> banned for retry_time s.
        # retry=0 turns it off.
        'retry': 6,
        'retry_cycle': 60,
        'retry_time': 600,
        # CC counts static assets too when True; default False = skip them
        'static_protect': False,
        'start_time': 0,
        'custom_status': 403,
        # 4xx blocks show the block page (444 always just closes)
        'block_page': True,
        # PHP2Shell / multipart limits (PHP advisory GHSA-w8hw-w9fx-j79w)
        'php2shell_status': 403,
        'mp_max_parts': 500,
        'mp_max_headers': 16,
        'mp_max_depth': 10,
        'mp_max_empty': 50,
        'mp_scan_mb': 64,
        # request shape limits
        'max_params': 8000,
        # how much of a body nginx spilled to disk is still inspected
        'body_scan_kb': 1024,
        'max_headers': 800,
        # repeat offenders get longer bans (x times banned today, max a day)
        'ban_escalate': True,
        # fetch/XHR calls get this many times the per-site CC budget
        'cc_api_mult': 5,
        # Global module switches. A protection runs only when it is on here
        # AND on the site (WebSite tab) — the stock WAF's model.
        'm_cc': True, 'm_get': True, 'm_post': True, 'm_cookie': True, 'm_ua': True,
        'm_scan': True, 'm_nday': True, 'm_php2shell': True, 'm_spider': True,
        # ...and these switch a protection on for every site at once
        'browser_all': False, 'form_all': False, 'http_all': False, 'body_max_all': 2048,
        # CC "initial rule": what a newly added site starts with
        'cc_def_limit': 120, 'cc_def_cycle': 60, 'cc_def_block': 600,
        'cc_def_mode': 'block', 'cc_def_key': 'ip',
        # CC automatic mode: past cc_auto_limit requests in cc_auto_cycle s a
        # site switches to browser verification for cc_auto_hold s
        'cc_auto': False, 'cc_auto_limit': 3000, 'cc_auto_cycle': 60, 'cc_auto_hold': 600,
        # malicious upload / download defense (per-site upload_ext / deny_ext)
        'm_upload': True, 'm_download': True,
        # semantic analysis per parameter (engine/detect.lua). SQLi/XSS go to
        # libinjection: on its own corpora it catches ~100% and on this
        # project's real traffic (42k distinct parameter values) it flagged
        # only scanner probes. Command/file detection is our own heuristic
        # and stays opt-in.
        'm_sqli': True, 'm_xss': True, 'm_rce': False,
        'sqli_status': 403, 'xss_status': 403, 'rce_status': 403,
        # weak password defense / error-message leak masking
        'weak_pass': False, 'info_leak': False,
        # directory scan defense: more than dirscan_count 404s in dirscan_time s
        'dirscan': False, 'dirscan_time': 60, 'dirscan_count': 120,
        # Blockade > Rule hit record: which custom-rule matches are written
        'rulehit_type': 'all',
    }
    # text settings and the values they may take
    CONFIG_CHOICES = {'cc_def_mode': ('block', 'challenge'), 'cc_def_key': ('ip', 'url', 'path', 'ipua'),
                      'rulehit_type': ('all', 'intercept', 'release', 'none')}
    # Empty = allow every method. Anything here is an allow-list.
    DEFAULT_METHODS = ['GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE', 'PATCH']
    # header|max bytes — oversized headers are probes, not real traffic
    DEFAULT_HDR_LIMITS = [
        {'h': 'user-agent', 'max': 1024},
        {'h': 'referer', 'max': 2048},
        {'h': 'cookie', 'max': 8192},
        {'h': 'x-forwarded-for', 'max': 512},
    ]
    DEFAULT_SITE = {
        'open': True, 'get': True, 'post': True, 'cookie': True,
        'ua': True, 'scan': True,
        # read the visitor IP from X-Forwarded-For for this site
        'cdn': False,
        # block anything calling itself Googlebot/Bingbot from an IP the
        # crawler's owner does not publish
        'fake_spider': True,
        # tighten the per-IP CC allowance automatically while the whole site
        # is under load, instead of relying on one fixed limit
        'smart_cc': False,
        # unverified bots get their own, much tighter budget
        'crawl': False, 'crawl_limit': 30,
        # past this many req/s the overflow gets a retry page, not a timeout
        'wait': False, 'wait_limit': 200,
        'cc_open': True, 'cc_limit': 120, 'cc_cycle': 60, 'cc_block': 600,
        # comma-separated, no dots: extensions the site must never serve
        'deny_ext': 'sql,bak,swp,ini,log,sh,py',
        # extensions refused in multipart uploads (webshell vectors)
        'upload_ext': 'php,php3,php4,php5,phtml,jsp,asp,aspx,exe,sh',
        # paths under which .php must never execute (upload dirs)
        'php_path': '',
        # PHP2Shell (CVE-2026-109618/109619) multipart guard. Seeded on for
        # PHP sites only — see _site_defaults.
        'php_guard': True,
        # reject malformed multipart/form-data bodies
        'form_strict': False,
        # page loads must run JavaScript once (non-browser clients blocked)
        'browser': False,
        # what happens past the CC limit: 'block' bans, 'challenge' asks the
        # visitor to verify it is a browser first
        'cc_mode': 'block',
        # what CC counts per: ip, url (IP + full URL), path (IP + URL without
        # query), ipua (IP + user-agent)
        'cc_key': 'ip',
        # largest non-upload request body in KB; 0 = no limit
        'body_max': 0,
        # virtual patches for known CVEs (the 'nday' rule set)
        'nday': True,
        # refuse visitors from cloud/datacenter address space
        'idc': False,
    }
    SITE_BOOL_FIELDS = ('open', 'get', 'post', 'cookie', 'ua', 'scan', 'cc_open',
                        'cdn', 'fake_spider', 'smart_cc', 'crawl', 'wait',
                        'php_guard', 'form_strict', 'browser', 'nday', 'idc')
    SITE_INT_FIELDS = ('cc_limit', 'cc_cycle', 'cc_block', 'crawl_limit', 'wait_limit',
                       'body_max')
    SITE_TEXT_FIELDS = ('deny_ext', 'upload_ext', 'php_path')
    SITE_CHOICE_FIELDS = {'cc_mode': ('block', 'challenge'), 'cc_key': ('ip', 'url', 'path', 'ipua')}
    # panel project types whose requests reach PHP
    PHP_PROJECT_TYPES = ('PHP', 'WP', 'WP2', '')

    def _config(self):
        cfg = self._read_json(self.CONFIG, None)
        if not isinstance(cfg, dict):
            cfg = dict(self.DEFAULT_CONFIG)
            cfg['start_time'] = int(time.time())
            self._write_json(self.CONFIG, cfg)
        else:
            changed = False
            for k, v in self.DEFAULT_CONFIG.items():
                if k not in cfg:
                    cfg[k] = v
                    changed = True
            if changed:
                self._write_json(self.CONFIG, cfg)
        return cfg

    def _sites(self):
        '''Per-site switches, seeded from the panel's site list.

        The panel database is the authority on which sites exist — we do not
        depend on any WAF plugin's site.json.
        '''
        data = self._read_json(self.SITES, None)
        if not isinstance(data, dict):
            data = {}
        changed = False
        types = self._panel_site_types()
        for name in types:
            if name not in data:
                data[name] = self._site_defaults(types.get(name))
                changed = True
        # Backfill keys added by a later version, or sites saved before that
        # version keep compiling with the field empty (silently unprotected).
        for name, conf in data.items():
            if not isinstance(conf, dict):
                continue
            defaults = self._site_defaults(types.get(name))
            for k, v in defaults.items():
                if k not in conf:
                    conf[k] = v
                    changed = True
        if changed:
            self._write_json(self.SITES, data)
        return data

    def _site_defaults(self, project_type):
        d = dict(self.DEFAULT_SITE)
        # the Global CC "initial rule" is what a new site starts with
        cfg = self._read_json(self.CONFIG, {}) or {}
        for src, dst in (('cc_def_limit', 'cc_limit'), ('cc_def_cycle', 'cc_cycle'), ('cc_def_block', 'cc_block'),
                         ('cc_def_mode', 'cc_mode'), ('cc_def_key', 'cc_key')):
            if src in cfg:
                d[dst] = cfg[src]
        # The multipart guard reads the whole upload before passing it on;
        # that is the right trade for PHP (the parser it protects), pointless
        # for a Node/Python/Go app.
        d['php_guard'] = (project_type or '') in self.PHP_PROJECT_TYPES
        return d

    def _panel_site_types(self):
        '''site name -> panel project_type (PHP, WP2, Node, ...).'''
        try:
            rows = public.M('sites').field('name,project_type').order('name asc').select()
            if isinstance(rows, list):
                return {r['name']: (r.get('project_type') or '') for r in rows if r.get('name')}
        except Exception:
            pass
        return {}

    def _panel_sites(self):
        return sorted(self._panel_site_types().keys())

    # vhost file prefixes aaPanel uses per project type: node_market.conf is
    # the site "market"
    VHOST_PREFIXES = ('node_', 'java_', 'go_', 'python_', 'other_', 'net_', 'html_',
                      'proxy_', 'nodejs_', 'php_')

    def _site_domains(self):
        '''host -> site name, for the engine's domains.txt.

        Two sources, because neither is complete on its own: the panel's
        domain table (every domain bound in the UI, incl. Node projects whose
        site name is not a host at all) and the server_name lines of each
        site's own vhost (wildcards like *.example.com that people add by
        hand never reach the table).
        '''
        out = {}
        try:
            ids = {r['id']: r['name'] for r in public.M('sites').field('id,name').select()}
            for r in public.M('domain').field('pid,name').select():
                site = ids.get(r.get('pid'))
                if site and r.get('name'):
                    out[str(r['name']).lower().strip()] = site
        except Exception:
            pass
        sites = set(self._panel_sites())
        for s in sites:
            out.setdefault(s.lower(), s)
        try:
            for fn in os.listdir(NGINX_CONF_D):
                if not fn.endswith('.conf'):
                    continue
                base = fn[:-5]
                site = base if base in sites else None
                if not site:
                    for p in self.VHOST_PREFIXES:
                        if base.startswith(p) and base[len(p):] in sites:
                            site = base[len(p):]
                            break
                if not site:
                    continue
                body = public.readFile(NGINX_CONF_D + fn) or ''
                for m in re.finditer(r'^\s*server_name\s+([^;]+);', body, re.M):
                    for h in m.group(1).split():
                        h = h.lower().strip()
                        if h and h != '_' and not h.startswith('~') and h not in out:
                            out[h] = site
        except Exception:
            pass
        return out

    METHODS_FILE = PLUGIN_PATH + 'methods.json'
    HDR_FILE = PLUGIN_PATH + 'hdr_limits.json'
    DROP_LOG = WAF_LOG_DIR + 'drop_ip.log'
    # panel-side source; _compile() copies it to rule/unban.txt for the engine
    UNBAN_FILE = PLUGIN_PATH + 'unban.txt'

    def _methods(self):
        m = self._read_json(self.METHODS_FILE, None)
        if not isinstance(m, list):
            m = list(self.DEFAULT_METHODS)
            self._write_json(self.METHODS_FILE, m)
        return [x.upper() for x in m if isinstance(x, str)]

    def _hdr_limits(self):
        h = self._read_json(self.HDR_FILE, None)
        if not isinstance(h, list):
            h = [dict(x) for x in self.DEFAULT_HDR_LIMITS]
            self._write_json(self.HDR_FILE, h)
        return [x for x in h if isinstance(x, dict) and x.get('h')]

    # ---------- auto-ban (Blockade > IP blocking record) ----------

    # an unban entry only needs to outlive the longest ban it could lift
    UNBAN_KEEP = 7 * 86400

    def _unban_entries(self):
        '''unban.txt -> {ip: unix time of the unban}. Pre-2.1 files held bare
        IPs with no time; those are dropped (they were the bug: kept forever,
        they re-lifted every later ban of the same address).'''
        out = {}
        for line in (public.readFile(self.UNBAN_FILE) or '').split('\n'):
            f = line.strip().split('|')
            if len(f) == 2 and f[1].isdigit():
                out[f[0]] = int(f[1])
        return out

    def _unban_write(self, entries):
        now = int(time.time())
        keep = {ip: ts for ip, ts in entries.items() if now - ts < self.UNBAN_KEEP}
        public.writeFile(self.UNBAN_FILE, '\n'.join('{}|{}'.format(ip, ts) for ip, ts in keep.items()))

    def bans(self, get):
        '''Currently banned IPs (auto-ban, CC, traffic block).

        The ban itself lives in the engine's shared dict, which we cannot read
        from here, so the engine mirrors every ban into drop_ip.log
        (ip|until|hits|site|rule|start) and we report the live entries.
        '''
        now = int(time.time())
        rows = {}
        try:
            body = public.readFile(self.DROP_LOG) or ''
        except Exception:
            body = ''
        unbanned = self._unban_entries()
        for line in body.split('\n'):
            f = line.split('|')
            if len(f) < 3:
                continue
            try:
                until = int(f[1])
            except Exception:
                continue
            start = int(f[5]) if len(f) > 5 and f[5].isdigit() else until
            # a ban that started before its unban is gone; a later one is not
            if until <= now or (f[0] in unbanned and start <= unbanned[f[0]]):
                continue
            # later lines win: an IP can be re-banned
            rows[f[0]] = {'ip': f[0], 'until': until, 'left': until - now, 'start': start,
                          'hits': int(f[2]) if f[2].isdigit() else 0,
                          'site': f[3] if len(f) > 3 else '',
                          'rule': f[4] if len(f) > 4 else ''}
        # The engine only ever appends here; the IP blocking record shows the
        # newest BAN_KEEP_ROWS, so trim to those once the file gets big.
        self._trim_tail(self.DROP_LOG, body, self.BAN_KEEP_ROWS)
        out = sorted(rows.values(), key=lambda x: x['until'], reverse=True)
        cfg = self._config()
        return {'status': True, 'data': out,
                'retry': cfg.get('retry', 0), 'retry_cycle': cfg.get('retry_cycle', 60),
                'retry_time': cfg.get('retry_time', 600)}

    def unban(self, get):
        '''Lift a ban. The engine drops the key on its next resync (~2s),
        so the version bump is what actually applies this.'''
        import ipaddress
        ip = (getattr(get, 'ip', '') or '').strip()
        try:
            ip = str(ipaddress.ip_address(ip))   # canonical, as the engine keys it
        except ValueError:
            return public.returnMsg(False, 'Invalid IP')
        entries = self._unban_entries()
        entries[ip] = int(time.time())
        self._unban_write(entries)
        self._compile()
        public.WriteLog('WAF Pro', 'unbanned {}'.format(ip))
        return public.returnMsg(True, 'Unbanned {} — takes effect within a few seconds'.format(ip))

    def unban_all(self, get):
        rows = self.bans(get)['data']
        if not rows:
            return public.returnMsg(True, 'Nothing to unban')
        entries = self._unban_entries()
        now = int(time.time())
        for r in rows:
            entries[r['ip']] = now
        self._unban_write(entries)
        self._compile()
        return public.returnMsg(True, 'Cleared {} ban(s)'.format(len(rows)))

    # ---------- Blockade > IP blocking record (history) ----------

    BAN_KEEP_ROWS = 2000
    RULEHIT_LOG = WAF_LOG_DIR + 'rulehit.log'

    def _trim_tail(self, path, body, keep):
        '''Cut an append-only log down to its newest keep lines once it has
        grown well past them (the engine keeps appending to the same inode).'''
        try:
            lines = [x for x in body.split('\n') if x.strip()]
            if len(lines) > keep * 1.25:
                public.writeFile(path, '\n'.join(lines[-keep:]) + '\n')
                os.system('chown www:www {} 2>/dev/null'.format(path))
        except Exception:
            pass

    def _ban_rows(self):
        '''Every row of drop_ip.log, newest first, with its live state.'''
        now = int(time.time())
        unbanned = self._unban_entries()
        out = []
        for line in (public.readFile(self.DROP_LOG) or '').split('\n'):
            f = line.split('|')
            if len(f) < 3 or not f[1].isdigit():
                continue
            until = int(f[1])
            start = int(f[5]) if len(f) > 5 and f[5].isdigit() else until
            lifted = f[0] in unbanned and start <= unbanned[f[0]]
            rule = f[4] if len(f) > 4 else ''
            out.append({'ip': f[0], 'start': start, 'until': until,
                        'secs': max(until - start, 0),
                        'hits': int(f[2]) if f[2].isdigit() else 0,
                        'site': f[3] if len(f) > 3 else '', 'rule': rule,
                        'reason': self.FILTER_NAMES.get(rule.split(':')[0], rule),
                        'uri': (f[6] if len(f) > 6 else '').replace('%7C', '|'),
                        'blocking': until > now and not lifted,
                        'left': max(until - now, 0) if until > now and not lifted else 0})
        out.sort(key=lambda x: x['start'], reverse=True)
        return out

    def _with_geo(self, rows, key='ip'):
        try:
            geo = self._dash()
        except Exception:
            geo = None
        for r in rows:
            g = geo.geo_lookup(r[key]) if geo else {}
            loc = g.get('country', '') or ''
            if g.get('city'):
                loc += ' / ' + g['city']
            r['location'] = loc or 'Unknown'
        return rows

    def _paged(self, get, rows, q_keys):
        '''Free-text search over q_keys, then one page of the result.'''
        q = (getattr(get, 'q', '') or '').strip().lower()
        if q:
            rows = [r for r in rows if q in ' '.join(str(r.get(k, '')) for k in q_keys).lower()]
        try:
            p = max(int(getattr(get, 'p', 1)), 1)
        except Exception:
            p = 1
        try:
            size = min(max(int(getattr(get, 'size', 10)), 5), 100000)
        except Exception:
            size = 10
        total = len(rows)
        return {'status': True, 'total': total, 'p': p, 'size': size,
                'pages': max((total + size - 1) // size, 1),
                'data': rows[(p - 1) * size: p * size]}

    def ban_records(self, get):
        '''Every ban the engine applied (newest first), live or expired.'''
        rows = self._with_geo(self._ban_rows())
        res = self._paged(get, rows, ('ip', 'site', 'uri', 'reason', 'location'))
        res['live'] = sum(1 for r in rows if r['blocking'])
        return res

    def ban_clear(self, get):
        '''Drop the ban history. Live bans stay — in the engine and in the
        file, which is how this tab can still show and lift them.'''
        live = [r for r in self._ban_rows() if r['blocking']]
        public.writeFile(self.DROP_LOG, ''.join(
            '{}|{}|{}|{}|{}|{}|{}\n'.format(r['ip'], r['until'], r['hits'], r['site'], r['rule'],
                                           r['start'], r['uri'].replace('|', '%7C'))
            for r in reversed(live)))
        os.system('chown www:www {} 2>/dev/null'.format(self.DROP_LOG))
        return public.returnMsg(True, 'Ban history cleared ({} active ban(s) kept)'.format(len(live)))

    def ban_export(self, get):
        get.size = 100000
        get.p = 1
        rows = self.ban_records(get)['data']
        out = ['Start time,User IP,Site,URL address,Reason for blocking,Time (s),Status,IP location']
        for r in rows:
            out.append(','.join(self._csv(v) for v in (
                time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r['start'])), r['ip'], r['site'],
                r['uri'], r['reason'], r['secs'], 'Blocking' if r['blocking'] else 'Expired',
                r['location'])))
        return self._export_csv('wafpro_bans', out)

    def _csv(self, v):
        return '"{}"'.format(str(v).replace('"', '""'))

    def _export_csv(self, prefix, lines):
        if not os.path.exists(PLUGIN_PATH + 'export'):
            os.makedirs(PLUGIN_PATH + 'export', 0o700)
        fname = '{}_{}.csv'.format(prefix, time.strftime('%Y%m%d_%H%M%S'))
        public.writeFile(PLUGIN_PATH + 'export/' + fname, '\n'.join(lines))
        return {'status': True, 'rows': len(lines) - 1, 'filename': fname}

    # ---------- Blockade > Rule hit record ----------

    def rulehit_logs(self, get):
        '''Custom-rule matches the engine recorded (intercepted and released).'''
        body = public.readFile(self.RULEHIT_LOG) or ''
        self._trim_tail(self.RULEHIT_LOG, body, self.BAN_KEEP_ROWS)
        names = {r.get('id'): r.get('name') or r.get('id') for r in self._custom()}
        act = (getattr(get, 'act', '') or '').strip()
        rows = []
        for line in body.split('\n'):
            try:
                d = json.loads(line)
            except Exception:
                continue
            if not isinstance(d, dict) or (act and d.get('act') != act):
                continue
            d['name'] = names.get(d.get('id'), d.get('id', '') + ' (deleted)')
            d['time_s'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(d.get('time', 0)))
            rows.append(d)
        rows.reverse()
        rows = self._with_geo(rows)
        res = self._paged(get, rows, ('ip', 'site', 'uri', 'name', 'ua', 'location'))
        res['record_type'] = self._config().get('rulehit_type', 'all')
        return res

    def rulehit_clear(self, get):
        public.writeFile(self.RULEHIT_LOG, '')
        os.system('chown www:www {} 2>/dev/null'.format(self.RULEHIT_LOG))
        return public.returnMsg(True, 'Rule hit records cleared')

    def get_methods(self, get):
        return {'status': True, 'data': self._methods(), 'all': self.DEFAULT_METHODS}

    def save_methods(self, get):
        try:
            m = json.loads(getattr(get, 'methods', '[]'))
        except Exception:
            return public.returnMsg(False, 'Invalid payload')
        if not isinstance(m, list) or not m:
            return public.returnMsg(False, 'Allow at least one method')
        if 'GET' not in [str(x).upper() for x in m]:
            return public.returnMsg(False, 'GET cannot be blocked — the sites would stop working')
        self._write_json(self.METHODS_FILE, [str(x).upper() for x in m])
        self._compile()
        return public.returnMsg(True, 'Methods saved')

    def get_hdr_limits(self, get):
        return {'status': True, 'data': self._hdr_limits()}

    def save_hdr_limits(self, get):
        try:
            h = json.loads(getattr(get, 'limits', '[]'))
        except Exception:
            return public.returnMsg(False, 'Invalid payload')
        out = []
        for x in h if isinstance(h, list) else []:
            try:
                if x.get('h') and int(x['max']) > 0:
                    out.append({'h': str(x['h']).lower(), 'max': int(x['max'])})
            except Exception:
                continue
        self._write_json(self.HDR_FILE, out)
        self._compile()
        return public.returnMsg(True, 'Header limits saved')

    SPIDER_FILE = PLUGIN_PATH + 'spiders.json'
    # Where each crawler's owner publishes the IPs it actually crawls from.
    # A UA saying "Googlebot" from anywhere else is someone else wearing the hat.
    SPIDER_SOURCES = [
        # 'common-crawlers' is where Google moved googlebot.json; the old
        # googlebot.json path under /crawling/ is a 404.
        ('googlebot', 'https://developers.google.com/static/crawling/ipranges/common-crawlers.json'),
        ('google-special', 'https://developers.google.com/static/crawling/ipranges/special-crawlers.json'),
        ('bingbot', 'https://www.bing.com/toolbox/bingbot.json'),
        ('applebot', 'https://search.developer.apple.com/applebot.json'),
    ]
    # UA fragments that claim to be one of the crawlers above
    SPIDER_UA = r'(googlebot|adsbot-google|mediapartners-google|storebot-google|' \
                r'google-inspectiontool|bingbot|adidxbot|bingpreview|msnbot|applebot)'

    def _spiders(self):
        return self._read_json(self.SPIDER_FILE, None)

    def spider_status(self, get):
        d = self._spiders()
        return {'status': True,
                'have': isinstance(d, dict) and bool(d.get('ranges')),
                'count': (len(d.get('ranges', [])) + len(d.get('ranges6', []))) if isinstance(d, dict) else 0,
                'updated': (d or {}).get('updated', ''),
                'sources': [n for n, _ in self.SPIDER_SOURCES]}

    def spider_update(self, get):
        '''Refresh the verified-crawler IP list from the official sources.'''
        import urllib.request
        got, got6, failed = [], [], []
        for name, url in self.SPIDER_SOURCES:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'wafpro'})
                body = urllib.request.urlopen(req, timeout=20).read()
                data = json.loads(body)
                n = 0
                for pfx in data.get('prefixes', []):
                    cidr = pfx.get('ipv4Prefix') or pfx.get('ipv6Prefix')
                    if not cidr:
                        continue
                    try:
                        fam, a, b = self._any_range(cidr)
                    except Exception:
                        continue
                    (got if fam == 4 else got6).append([a, b])
                    n += 1
                if not n:
                    failed.append(name)
            except Exception:
                failed.append(name)
        if not got and not got6:
            return public.returnMsg(False, 'Could not fetch any crawler list ({}). '
                                           'Check the server\'s outbound access.'.format(
                                               ', '.join(failed)))
        merged, merged6 = self._merge(got), self._merge(got6)
        self._write_json(self.SPIDER_FILE, {
            'ranges': merged, 'ranges6': merged6,
            'updated': time.strftime('%Y-%m-%d %H:%M:%S'), 'failed': failed})
        self._compile()
        msg = 'Verified crawler IPs updated: {} IPv4 + {} IPv6 ranges'.format(len(merged), len(merged6))
        if failed:
            msg += ' ({} unreachable, kept the rest)'.format(', '.join(failed))
        public.WriteLog('WAF Pro', msg)
        return public.returnMsg(True, msg)

    # Datacenter address space, from the lists the providers publish
    # themselves. Not every host is covered (several publish nothing), so this
    # is "known cloud", not "every server on the internet".
    IDC_FILE = PLUGIN_PATH + 'idc.json'
    IDC_SOURCES = [
        ('aws', 'https://ip-ranges.amazonaws.com/ip-ranges.json'),
        ('google-cloud', 'https://www.gstatic.com/ipranges/cloud.json'),
        ('oracle', 'https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json'),
        ('digitalocean', 'https://digitalocean.com/geo/google.csv'),
        ('linode', 'https://geoip.linode.com/'),
    ]
    CIDR_RE = re.compile(r'(?<![\w:.])((?:\d{1,3}\.){3}\d{1,3}/\d{1,2}|[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}/\d{1,3})')

    def idc_status(self, get):
        d = self._read_json(self.IDC_FILE, None)
        return {'status': True, 'have': isinstance(d, dict) and bool(d.get('ranges')),
                'count': (len(d.get('ranges', [])) + len(d.get('ranges6', []))) if isinstance(d, dict) else 0,
                'updated': (d or {}).get('updated', ''), 'failed': (d or {}).get('failed', []),
                'sources': [n for n, _ in self.IDC_SOURCES]}

    def idc_update(self, get):
        '''Refresh the datacenter IP list. Every source is just scanned for
        CIDRs — the formats differ (JSON, CSV) but all list prefixes.'''
        import urllib.request
        got, got6, failed = [], [], []
        for name, url in self.IDC_SOURCES:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'wafpro'})
                body = urllib.request.urlopen(req, timeout=30).read().decode('utf-8', 'replace')
                n = 0
                for m in self.CIDR_RE.finditer(body):
                    try:
                        fam, a, b = self._any_range(m.group(1))
                    except Exception:
                        continue
                    (got if fam == 4 else got6).append([a, b])
                    n += 1
                if not n:
                    failed.append(name)
            except Exception:
                failed.append(name)
        if not got and not got6:
            return public.returnMsg(False, 'Could not fetch any provider list ({}).'.format(', '.join(failed)))
        merged, merged6 = self._merge(got), self._merge(got6)
        self._write_json(self.IDC_FILE, {'ranges': merged, 'ranges6': merged6, 'failed': failed,
                                         'updated': time.strftime('%Y-%m-%d %H:%M:%S')})
        self._compile()
        msg = 'Datacenter IPs updated: {} IPv4 + {} IPv6 ranges'.format(len(merged), len(merged6))
        if failed:
            msg += ' ({} unreachable)'.format(', '.join(failed))
        public.WriteLog('WAF Pro', msg)
        return public.returnMsg(True, msg)

    MAL_FILE = PLUGIN_PATH + 'malicious.json'
    WAIT_FILE = PLUGIN_PATH + 'waiting.html'
    # Public abuse feeds. aaPanel ships its own list; this is the open
    # equivalent. Only high-confidence sources: a false positive here blocks a
    # real visitor outright, so no "seen once" lists.
    MAL_SOURCES = [
        # appeared on 5+ independent blacklists
        ('ipsum', 'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt'),
        # repeat attackers seen by blocklist.de sensors
        ('blocklist.de', 'https://lists.blocklist.de/lists/strongips.txt'),
        # netblocks that should never appear as a source (hijacked/leased to spammers)
        ('spamhaus-drop', 'https://www.spamhaus.org/drop/drop.txt'),
        ('spamhaus-drop-v6', 'https://www.spamhaus.org/drop/dropv6.txt'),
        # active botnet C2
        ('feodo', 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt'),
    ]
    # UA fragments of bots that are not verified search crawlers. Not blocked —
    # rate-limited, since most are harmless and some are useful.
    CRAWL_UA = r'(bot|crawler|spider|scrape|curl|wget|python-requests|httpclient|' \
               r'java/|go-http|okhttp|libwww|scrapy|headlesschrome|phantomjs)'

    def _malicious(self):
        return self._read_json(self.MAL_FILE, None)

    def malicious_status(self, get):
        d = self._malicious()
        return {'status': True,
                'have': isinstance(d, dict) and bool(d.get('ranges')),
                'count': (len(d.get('ranges', [])) + len(d.get('ranges6', []))) if isinstance(d, dict) else 0,
                'updated': (d or {}).get('updated', ''),
                'open': bool(self._config().get('mal_open')),
                'sources': [n for n, _ in self.MAL_SOURCES]}

    def malicious_update(self, get):
        '''Refresh the known-malicious IP list from the public feeds.'''
        import urllib.request
        got, got6, failed, seen = [], [], [], 0
        for name, url in self.MAL_SOURCES:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'wafpro'})
                body = urllib.request.urlopen(req, timeout=25).read().decode('utf-8', 'replace')
                n = 0
                for line in body.split('\n'):
                    # every feed uses ';' or '#' for comments, in either column
                    line = line.split(';')[0].split('#')[0].strip()
                    if not line:
                        continue
                    try:
                        fam, a, b = self._any_range(line.split()[0])
                    except Exception:
                        continue
                    (got if fam == 4 else got6).append([a, b])
                    n += 1
                seen += n
                if not n:
                    failed.append(name)
            except Exception:
                failed.append(name)
        if not got and not got6:
            return public.returnMsg(False, 'Could not fetch any feed ({}). '
                                           'Check outbound access.'.format(', '.join(failed)))
        merged = self._merge(got)
        # Our own IPs never get blocked by it: the engine checks the self/LAN
        # sets before the feed.
        self._write_json(self.MAL_FILE, {
            'ranges': merged, 'ranges6': self._merge(got6),
            'updated': time.strftime('%Y-%m-%d %H:%M:%S'),
            'raw': seen, 'failed': failed})
        self._compile()
        msg = 'Malicious IP list updated: {} ranges from {} entries'.format(len(merged), seen)
        if failed:
            msg += ' ({} unreachable)'.format(', '.join(failed))
        public.WriteLog('WAF Pro', msg)
        return public.returnMsg(True, msg)

    def malicious_toggle(self, get):
        cfg = self._config()
        if str(getattr(get, 'open', '0')) in ('1', 'true', 'True'):
            if not (self._malicious() or {}).get('ranges'):
                return public.returnMsg(False, 'Download the list first')
            cfg['mal_open'] = True
        else:
            cfg['mal_open'] = False
        self._write_json(self.CONFIG, cfg)
        self._compile()
        return public.returnMsg(True, 'Malicious IP blocking {}'.format(
            'enabled' if cfg['mal_open'] else 'disabled'))

    DEFAULT_WAIT_HTML = """<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Just a moment</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
  font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;
  background:#f5f6f8;color:#1f2329}
.b{max-width:420px;padding:36px 30px;background:#fff;border:1px solid #ebedf0;
  border-radius:12px;text-align:center}
h1{margin:0 0 8px;font-size:19px}
p{margin:0;color:#5c6470}
.s{margin:0 auto 18px;width:30px;height:30px;border:3px solid #ebedf0;
  border-top-color:#20a53a;border-radius:50%;animation:r .8s linear infinite}
@keyframes r{to{transform:rotate(360deg)}}
</style>
<div class="b"><div class="s"></div>
<h1>Just a moment</h1>
<p>The site is busier than usual. This page refreshes by itself &mdash; no need to do anything.</p></div>
<script>setTimeout(function(){location.reload()},5000)</script>
"""

    def _waiting_html(self):
        h = public.readFile(self.WAIT_FILE)
        if not h:
            public.writeFile(self.WAIT_FILE, self.DEFAULT_WAIT_HTML)
            return self.DEFAULT_WAIT_HTML
        return h

    # Pages the engine serves itself. {placeholders} are filled per request;
    # the challenge page must keep {script}.
    DEFAULT_PAGES = {
        'block': """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Request blocked</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
  font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;
  background:#f5f6f8;color:#1f2329}
.b{width:min(460px,calc(100% - 32px));padding:34px 30px;background:#fff;
  border:1px solid #ebedf0;border-radius:12px;box-sizing:border-box}
.i{width:46px;height:46px;border-radius:50%;background:#fdecec;color:#ef4d4d;display:flex;
  align-items:center;justify-content:center;font-size:24px;font-weight:700;margin-bottom:16px}
h1{margin:0 0 6px;font-size:19px}
p{margin:0 0 18px;color:#5c6470}
dl{margin:0;display:grid;grid-template-columns:auto 1fr;gap:6px 14px;font-size:13px;
  border-top:1px solid #ebedf0;padding-top:14px}
dt{color:#9aa1ab}dd{margin:0;word-break:break-all}
</style></head><body><div class="b">
<div class="i">!</div>
<h1>Your request was blocked</h1>
<p>This website is protected by a web application firewall. If you think this is a
mistake, contact the site owner and quote the details below.</p>
<dl><dt>Reason</dt><dd>{rule}</dd><dt>Your IP</dt><dd>{ip}</dd>
<dt>Time</dt><dd>{time}</dd><dt>Status</dt><dd>{status}</dd><dt>Request ID</dt><dd>{id}</dd></dl>
</div></body></html>
""",
        'challenge': """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>Checking your browser</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
  font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;
  background:#f5f6f8;color:#1f2329}
.b{width:min(420px,calc(100% - 32px));padding:36px 30px;background:#fff;
  border:1px solid #ebedf0;border-radius:12px;text-align:center;box-sizing:border-box}
h1{margin:0 0 8px;font-size:19px}p{margin:0;color:#5c6470}
.s{margin:0 auto 18px;width:30px;height:30px;border:3px solid #ebedf0;
  border-top-color:#20a53a;border-radius:50%;animation:r .8s linear infinite}
@keyframes r{to{transform:rotate(360deg)}}
</style></head><body><div class="b"><div class="s"></div>
<h1>Checking your browser</h1>
<p>This only takes a moment. Please enable JavaScript and cookies if this page does not continue.</p>
</div><script>{script}</script></body></html>
""",
        # Traffic Limit "Return Web Content" (sent with 429)
        'limit': """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Too many requests</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
  background:#f5f7fa;font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:#303133}
.b{background:#fff;border-radius:8px;padding:40px 48px;box-shadow:0 2px 12px rgba(0,0,0,.06);text-align:center;max-width:460px}
h1{font-size:22px;margin:0 0 10px;color:#e6a23c}
p{margin:0;color:#606266}
</style></head><body><div class="b"><h1>Too many requests</h1>
<p>The website is receiving more traffic than it can serve right now. Please try again in a moment.</p>
</div></body></html>""",
        'limitjson': '{"code": 429, "msg": "Too many requests, please try again later"}',
    }

    def _page(self, kind):
        h = public.readFile(PLUGIN_PATH + 'page_' + kind + '.html')
        return h or self.DEFAULT_PAGES[kind]

    def get_page(self, get):
        kind = getattr(get, 'kind', '')
        if kind not in self.DEFAULT_PAGES:
            return public.returnMsg(False, 'Unknown page')
        return {'status': True, 'html': self._page(kind), 'default': self.DEFAULT_PAGES[kind]}

    def save_page(self, get):
        kind = getattr(get, 'kind', '')
        if kind not in self.DEFAULT_PAGES:
            return public.returnMsg(False, 'Unknown page')
        h = getattr(get, 'html', '') or ''
        if len(h) > 200000:
            return public.returnMsg(False, 'Page is too large')
        if kind == 'challenge' and h and '{script}' not in h:
            return public.returnMsg(False, 'The challenge page must contain {script}')
        path = PLUGIN_PATH + 'page_' + kind + '.html'
        if h.strip():
            public.writeFile(path, h)
        elif os.path.exists(path):
            os.remove(path)
        self._compile()
        return public.returnMsg(True, 'Page saved')

    def get_waiting_html(self, get):
        return {'status': True, 'html': self._waiting_html()}

    def save_waiting_html(self, get):
        h = getattr(get, 'html', '') or ''
        if len(h) > 200000:
            return public.returnMsg(False, 'Page is too large')
        public.writeFile(self.WAIT_FILE, h or self.DEFAULT_WAIT_HTML)
        self._compile()
        return public.returnMsg(True, 'Waiting page saved')

    # .bin/.bin6 sets _compile() writes itself; any other packed file is a
    # stale region/custom rule and gets cleaned up.
    FIXED_SETS = ('lan', 'self', 'ip_white', 'ip_black', 'spider', 'malicious', 'idc', 'cloudflare')

    # Cloudflare's edge (cloudflare.com/ips-v4, /ips-v6). The engine trusts
    # CF-Connecting-IP on connections from these, whatever the CDN switch
    # says: nobody else can connect from Cloudflare's addresses.
    CLOUDFLARE_V4 = ('173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
                     '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
                     '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
                     '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22')
    CLOUDFLARE_V6 = ('2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
                     '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32')

    def _w(self, name, body):
        '''Write one engine file, readable by the nginx workers (www).'''
        path = RULE_DIR + name
        public.writeFile(path, body)
        try:
            os.chmod(path, 0o644)
        except Exception:
            pass

    def _secret(self, name, length=32):
        '''A random value generated once and kept (HMAC key, test token).'''
        path = PLUGIN_PATH + name
        v = (public.readFile(path) or '').strip()
        if len(v) < 16:
            import secrets
            v = secrets.token_hex(length // 2)
            public.writeFile(path, v)
            os.chmod(path, 0o600)
        return v

    # ---------- compile: panel json -> engine files ----------

    def _compile(self):
        '''Render config/sites/rules into the engine's formats and bump the
        version. Workers pick it up within ~2s; no nginx reload involved.'''
        import ipaddress
        # 755, not 700: the workers (www) read everything in here
        if not os.path.exists(RULE_DIR):
            os.makedirs(RULE_DIR)
        os.chmod(ENGINE_PATH, 0o755)
        os.chmod(RULE_DIR, 0o755)
        if not os.path.exists(WAF_LOG_DIR):
            os.makedirs(WAF_LOG_DIR, 0o755)
        os.system('chown www:www {} 2>/dev/null'.format(WAF_LOG_DIR))

        cfg = self._config()
        kv = []
        for k, v in sorted(cfg.items()):
            if isinstance(v, bool):
                v = 'true' if v else 'false'
            kv.append('{}={}'.format(k, v))
        kv.append('methods={}'.format(','.join(self._methods())))
        self._w('config.txt', '\n'.join(kv))

        # name<TAB>key=value... — see parse_sites in wafpro.lua
        lines = []
        for name, s in sorted(self._sites().items()):
            if not isinstance(s, dict):
                continue
            f = [name]
            for k in self.SITE_BOOL_FIELDS:
                f.append('{}={}'.format(k, '1' if s.get(k) else '0'))
            for k in self.SITE_INT_FIELDS:
                try:
                    f.append('{}={}'.format(k, int(s.get(k, self.DEFAULT_SITE[k]))))
                except Exception:
                    f.append('{}={}'.format(k, self.DEFAULT_SITE[k]))
            for k in self.SITE_TEXT_FIELDS:
                f.append('{}={}'.format(k, re.sub(r'[\t\r\n]', '', str(s.get(k, '')))))
            for k, choices in self.SITE_CHOICE_FIELDS.items():
                v = s.get(k, self.DEFAULT_SITE[k])
                f.append('{}={}'.format(k, v if v in choices else self.DEFAULT_SITE[k]))
            lines.append('\t'.join(f))
        self._w('sites.txt', '\n'.join(lines))

        self._w('domains.txt', '\n'.join(
            '{}|{}'.format(h, site) for h, site in sorted(self._site_domains().items())
            if '|' not in h and '\n' not in h))

        lan6 = []
        for n in self.PRIVATE_V6:
            net = ipaddress.ip_network(n)
            lan6.append([int(net.network_address), int(net.broadcast_address)])
        self._pack_set('lan', self._merge([[self._ip2int(a), self._ip2int(b)]
                                           for a, b in self.PRIVATE_RANGES]), self._merge(lan6))
        self._pack_set('self', *self._self_ips())
        cf4, cf6 = [], []
        for c in self.CLOUDFLARE_V4 + self.CLOUDFLARE_V6:
            fam, a, b = self._any_range(c)
            (cf4 if fam == 4 else cf6).append([a, b])
        self._pack_set('cloudflare', self._merge(cf4), self._merge(cf6))
        for name in ('ip_white', 'ip_black'):
            self._pack_set(name, *self._ip_ranges(name))
        for name in self.RULE_NAMES:
            rules = [r['rule'] for r in self._rule_set(name) if r.get('open')]
            self._w('r_' + name + '.txt', '\n'.join(rules))
        for name in self.URL_LISTS:
            self._w(name + '.txt', '\n'.join((x.get('ip') or x.get('rule') or '')
                                             if isinstance(x, dict) else str(x)
                                             for x in self._list_load(name)))
        self._w('hdr_limits.txt', '\n'.join(
            '{}|{}'.format(x['h'], int(x['max'])) for x in self._hdr_limits()))
        sp = self._spiders() or {}
        self._pack_set('spider', sp.get('ranges', []), sp.get('ranges6', []))
        self._w('spider_ua.txt', self.SPIDER_UA)
        self._w('crawl_ua.txt', self.CRAWL_UA)
        ml = self._malicious() or {}
        self._pack_set('malicious', ml.get('ranges', []), ml.get('ranges6', []))
        idc = self._read_json(self.IDC_FILE, None) or {}
        self._pack_set('idc', idc.get('ranges', []), idc.get('ranges6', []))
        self._w('waiting.html', self._waiting_html())
        self._w('block.html', self._page('block'))
        self._w('challenge.html', self._page('challenge'))
        self._w('limit.html', self._page('limit'))
        self._w('limit.json', self._page('limitjson'))
        self._w('secret.txt', self._secret('secret.key'))
        self._w('test_token.txt', self._secret('test.key'))
        self._w('unban.txt', (public.readFile(self.UNBAN_FILE) or '')
                if os.path.exists(self.UNBAN_FILE) else '')

        region = self._rules()
        rl = []
        keep = set()
        for r in region:
            keep.add(r['id'] + '.bin')
            # packed ranges are (re)built here when missing: geo_update
            # deletes them so rules pick up new country data, and rules made
            # before there was IPv6 data get their .bin6 once it arrives
            b4 = RULE_DIR + r['id'] + '.bin'
            if not os.path.exists(b4):
                v4 = self._ranges_for(r.get('areas') or [])
                if v4:
                    r['ranges'] = self._pack(v4, b4)
            b6 = RULE_DIR + r['id'] + '.bin6'
            if not os.path.exists(b6):
                v6 = self._ranges6_for(r.get('areas') or [])
                if v6 is not None:
                    self._pack6(v6, b6)
            if os.path.exists(b6):
                keep.add(r['id'] + '.bin6')
            # a rule may cover several sites (or '*' = all): one line each,
            # all pointing at the same packed ranges
            for site in self._region_sites(r):
                rl.append('|'.join([r['id'], site, r['type'], str(r['status']),
                                    '1' if r.get('open') else '0']))
            page = public.readFile(self.REGION_PAGES + r['id'] + '.html') or ''
            if page.strip():
                keep.add(r['id'] + '.html')
                self._w(r['id'] + '.html', page)
        self._w('region.txt', '\n'.join(rl))

        # traffic limit: id|site|url|dim|rate|action|status|open|win|winmax|ret
        # (one line per site the rule covers)
        tl = []
        for t in self._traffic():
            c = self._traffic_compiled(t)
            for site in c['sites']:
                tl.append('|'.join([t['id'], site, c['url'].replace('|', ''), c['dim'],
                                    str(c['rate']), c['action'], str(c['status']),
                                    '1' if t.get('open') else '0', str(c['win']),
                                    str(c['winmax']), c['ret']]))
        self._w('traffic.txt', '\n'.join(tl))

        # custom rules -> multi-line format the engine reads:
        #   R|id|site|action|status|open
        #   C|field|op|extra|value|group  (extra = param/header name or bin file;
        #                                  same group = AND, groups are ORed)
        # ip/country conditions compile their ranges to a .bin (+ .bin6 for ip)
        # kept alongside the region bins (added to `keep` so the cleanup below
        # spares them).
        cl = []
        for r in self._custom():
            # one R block per site the rule covers
            conds_lines = []
            for ci, c in enumerate(r.get('conds', [])):
                field, op = c.get('field', ''), c.get('op', '')
                extra, value = c.get('extra', ''), c.get('value', '')
                if field in ('ip', 'country'):
                    if field == 'country':
                        codes = self._split_csv(value)
                        v4, v6 = self._ranges_for(codes) or [], self._ranges6_for(codes) or []
                    else:
                        v4, v6 = self._ip_value_ranges(value)
                    binname = '{}_{}.bin'.format(r['id'], ci)
                    self._pack(v4, RULE_DIR + binname)
                    self._pack6(v6, RULE_DIR + binname + '6')
                    keep.add(binname)
                    keep.add(binname + '6')
                    extra, value = binname, ''
                conds_lines.append('|'.join(['C', field, op, self._enc_pipe(extra),
                                             self._enc_pipe(value), str(int(c.get('g', 0)))]))
            for site in (r.get('sites') or [r.get('site', '')]):
                cl.append('|'.join(['R', r['id'], site, r['action'],
                                   str(int(r.get('status', 403))),
                                   '1' if r.get('open') else '0']))
                cl.extend(conds_lines)
        self._w('custom.txt', '\n'.join(cl))

        # per-site lists (forbidden URL, anti-leech, protected URL, API, replace)
        self._w('site_rules.txt', self._site_rules_compiled())

        # Drop packed files of rules that no longer exist. Only region/custom
        # rules have generated names — every fixed set must be in FIXED_SETS
        # or it gets deleted the moment it is created.
        fixed = set(n + '.bin' for n in self.FIXED_SETS) | set(n + '.bin6' for n in self.FIXED_SETS)
        for fn in os.listdir(RULE_DIR):
            if (fn.endswith('.bin') or fn.endswith('.bin6') or (fn.startswith('r') and fn.endswith('.html'))) \
                    and fn not in keep and fn not in fixed:
                try:
                    os.remove(RULE_DIR + fn)
                except Exception:
                    pass

        self._purge_old_logs(cfg)
        try:
            ver = int(public.readFile(RULE_DIR + 'version') or 0)
        except Exception:
            ver = 0
        self._w('version', str(ver + 1))
        return True

    def _purge_old_logs(self, cfg):
        '''Keep log_save days of block logs.'''
        try:
            days = int(cfg.get('log_save', 30))
        except Exception:
            days = 30
        if days <= 0 or not os.path.isdir(WAF_LOG_DIR):
            return
        cutoff = time.strftime('%Y-%m-%d', time.localtime(time.time() - days * 86400))
        for f in os.listdir(WAF_LOG_DIR):
            d = f[:-4]
            if f.endswith('.log') and re.match(r'^\d{4}-\d{2}-\d{2}$', d) and d < cutoff:
                try:
                    os.remove(WAF_LOG_DIR + f)
                except Exception:
                    pass

    def _rule_set(self, name):
        data = self._read_json(PLUGIN_PATH + 'rules/' + name + '.json', None)
        if not isinstance(data, list):
            data = self.DEFAULT_RULES.get(name, [])
            self._save_rule_set(name, data)
        return data

    def _save_rule_set(self, name, data):
        d = PLUGIN_PATH + 'rules/'
        if not os.path.exists(d):
            os.makedirs(d, 0o700)
        self._write_json(d + name + '.json', data)

    def _ip_ranges(self, name):
        '''A stored IP list -> (v4 ranges, v6 ranges), each merged.'''
        v4, v6 = [], []
        for x in self._read_json(PLUGIN_PATH + name + '.json', []) or []:
            ip = x['ip'] if isinstance(x, dict) else x
            try:
                fam, s, e = self._any_range(ip)
            except Exception:
                continue
            (v4 if fam == 4 else v6).append([s, e])
        return self._merge(v4), self._merge(v6)

    @staticmethod
    def _any_range(text):
        '''Single address, CIDR, or "a-b" range, IPv4 or IPv6 ->
        (family, start int, end int).'''
        import ipaddress
        text = str(text).strip()
        if '/' in text:
            net = ipaddress.ip_network(text, strict=False)
            return net.version, int(net.network_address), int(net.broadcast_address)
        if text.count('-') == 1:          # IPv6 text never contains '-'
            a, b = [p.strip() for p in text.split('-', 1)]
            ia = ipaddress.ip_address(a)
            if ia.version == 4 and '.' not in b:      # short form 1.2.3.4-100
                b = a.rsplit('.', 1)[0] + '.' + b
            ib = ipaddress.ip_address(b)
            if ia.version != ib.version:
                raise ValueError('Range mixes IPv4 and IPv6')
            if int(ia) > int(ib):
                raise ValueError('The starting IP cannot be greater than the ending IP')
            return ia.version, int(ia), int(ib)
        ip = ipaddress.ip_address(text)
        return ip.version, int(ip), int(ip)

    def _pack6(self, ranges, path):
        '''IPv6 twin of _pack: 32 bytes per [start,end], big-endian.'''
        buf = b''.join(s.to_bytes(16, 'big') + e.to_bytes(16, 'big') for s, e in ranges)
        with open(path, 'wb') as f:
            f.write(buf)
        os.chmod(path, 0o644)
        return len(ranges)

    def _pack_set(self, name, v4, v6):
        self._pack(v4, RULE_DIR + name + '.bin')
        self._pack6(v6, RULE_DIR + name + '.bin6')

    def _self_ips(self):
        '''Every address this server answers on, v4 and v6. Exempt from all
        rules: SSR apps fetch their own public hostname from here.'''
        import ipaddress
        found = set()
        out, _ = public.ExecShell('ip -o addr show 2>/dev/null')
        for m in re.finditer(r'\sinet6?\s+([0-9a-fA-F:.]+)/', out or ''):
            found.add(m.group(1))
        for line in (public.readFile('/www/server/panel/data/iplist.txt') or '').split('\n'):
            if line.strip():
                found.add(line.strip())
        v4, v6 = [], []
        for ip in found:
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                continue
            (v4 if a.version == 4 else v6).append([int(a), int(a)])
        return self._merge(v4), self._merge(v6)

    # loopback, private, link-local and unique-local IPv6
    PRIVATE_V6 = ('::1/128', 'fc00::/7', 'fe80::/10')

    # ----------------------------------------------------------------
    # status / engine
    # ----------------------------------------------------------------
    ENGINE_FILES = ('wafpro.lua', 'detect.lua', 'init.lua', 'worker.lua', 'waf.lua', 'header.lua', 'body.lua')
    # other lua WAFs that hook the same nginx phases; two access_by_lua_file
    # in one http block is a duplicate directive
    CONFLICTS = (
        ('/www/server/panel/vhost/nginx/btwaf.conf', 'aaPanel Nginx WAF (btwaf)'),
        ('/www/server/panel/vhost/nginx/free_waf.conf', 'Nginx free firewall (free_waf)'),
    )

    def _engine_files_current(self):
        '''True when /www/server/wafpro runs the lua shipped with this plugin.'''
        for f in self.ENGINE_FILES:
            a = public.readFile(PLUGIN_PATH + 'engine/' + f)
            b = public.readFile(ENGINE_PATH + f)
            if a and a != b:
                return False
        return True

    def _engine_sync(self):
        '''Copy the plugin's lua into place. The engine is cached at nginx
        start, so a changed copy only runs after the next reload.'''
        if not os.path.exists(ENGINE_PATH):
            os.makedirs(ENGINE_PATH)
        os.chmod(ENGINE_PATH, 0o755)
        for f in self.ENGINE_FILES:
            src = PLUGIN_PATH + 'engine/' + f
            if os.path.exists(src):
                public.writeFile(ENGINE_PATH + f, public.readFile(src))
                os.chmod(ENGINE_PATH + f, 0o644)

    def _conflicts(self):
        out = [label for path, label in self.CONFLICTS if os.path.exists(path)]
        conf = public.readFile(self.NGINX_CONF) or ''
        if re.search(r'^\s*include\s+luawaf\.conf\s*;', conf, re.M):
            out.append('nginx.conf includes luawaf.conf (old panel WAF)')
        return out

    def _nginx_has_lua(self):
        out, err = public.ExecShell('/www/server/nginx/sbin/nginx -V 2>&1')
        return 'lua_nginx_module' in ((out or '') + (err or '')) or 'openresty' in ((out or '') + (err or ''))

    def _engine_health(self):
        '''What the workers report running vs what the panel last compiled.'''
        try:
            want = int(public.readFile(RULE_DIR + 'version') or 0)
        except Exception:
            want = 0
        st = (public.readFile(WAF_LOG_DIR + 'engine.status') or '').strip().split('|')
        running, beat, ver = None, 0, ''
        if len(st) >= 2 and st[0].lstrip('-').isdigit():
            running, beat = int(st[0]), int(st[1]) if st[1].isdigit() else 0
            ver = st[2] if len(st) > 2 else ''
        age = int(time.time()) - beat if beat else None
        return {'rule_version': want, 'running_version': running,
                'engine_version': ver, 'heartbeat_age': age,
                # workers heartbeat every 30s; give them a little slack
                'alive': age is not None and age < 120,
                'in_sync': running == want}

    def _engine_state(self):
        '''Our own engine: shipped with the plugin, wired by the Global tab.'''
        return {
            'installed': os.path.exists(ENGINE_PATH + 'wafpro.lua'),
            'wired': os.path.exists(self.WAFPRO_CONF),
            'current': self._engine_files_current(),
            'conflicts': self._conflicts(),
            # who decides SQLi/XSS: libinjection when install.sh could build it
            'semantic': 'libinjection' if os.path.exists(ENGINE_PATH + 'libinjection.so') else 'built-in',
        }

    def get_status(self, get):
        cfg = self._config()
        e = self._engine_state()
        return {
            'status': True,
            'engine_installed': e['installed'],
            'nginx_wired': e['wired'],
            'engine': e,
            'health': self._engine_health() if e['wired'] else None,
            'open': bool(cfg.get('open', False)),
            'sites': len(self._sites()),
            'start_time': cfg.get('start_time', 0),
        }

    def engine_wire(self, get):
        '''Wire our engine into nginx (or unwire it).

        Guarded because a bad nginx config here takes every site on the box
        down: we write the conf, run `nginx -t`, and roll back on failure —
        only reloading once the test passes.
        '''
        on = str(getattr(get, 'open', '1')) in ('1', 'true', 'True')
        src = PLUGIN_PATH + 'engine/wafpro.conf'
        backup = None
        if os.path.exists(self.WAFPRO_CONF):
            backup = public.readFile(self.WAFPRO_CONF)
        try:
            if on:
                if not os.path.exists(src):
                    return public.returnMsg(False, 'engine/wafpro.conf missing from the plugin')
                conflicts = self._conflicts()
                if conflicts:
                    return public.returnMsg(False, 'Another WAF is hooked into nginx: {}. '
                                                   'Only one lua WAF can run; uninstall it first.'
                                            .format('; '.join(conflicts)))
                if not self._nginx_has_lua():
                    return public.returnMsg(False, 'This nginx was built without lua_nginx_module. '
                                                   'Reinstall nginx from the App Store (it includes lua).')
                self._engine_sync()
                self._compile()
                public.writeFile(self.WAFPRO_CONF, public.readFile(src))
            else:
                if os.path.exists(self.WAFPRO_CONF):
                    os.remove(self.WAFPRO_CONF)
            ok, out = self._nginx_test()
            if not ok:
                # put it back exactly as it was before touching nginx
                if backup:
                    public.writeFile(self.WAFPRO_CONF, backup)
                elif os.path.exists(self.WAFPRO_CONF):
                    os.remove(self.WAFPRO_CONF)
                return public.returnMsg(False, 'nginx config test failed, rolled back: {}'.format(
                    out.strip().split('\n')[-1][:200]))
            public.serviceReload()
            public.WriteLog('WAF Pro', 'Engine {}'.format('wired into nginx' if on else 'unwired'))
            return public.returnMsg(True, 'Engine {}'.format('enabled' if on else 'disabled'))
        except Exception as e:
            if backup:
                public.writeFile(self.WAFPRO_CONF, backup)
            return public.returnMsg(False, 'Wiring failed: {}'.format(e))

    def engine_update(self, get):
        '''After a plugin update: put the new lua in place and reload nginx
        (the engine is cached at nginx start, so copying alone is not enough).'''
        if not os.path.exists(self.WAFPRO_CONF):
            self._engine_sync()
            return public.returnMsg(True, 'Engine files updated (not wired, nothing to reload)')
        backup = {f: public.readFile(ENGINE_PATH + f) for f in self.ENGINE_FILES}
        self._engine_sync()
        self._compile()
        conf_src = public.readFile(PLUGIN_PATH + 'engine/wafpro.conf')
        conf_old = public.readFile(self.WAFPRO_CONF)
        if conf_src:
            public.writeFile(self.WAFPRO_CONF, conf_src)
        ok, out = self._nginx_test()
        if not ok:
            for f, body in backup.items():
                if body:
                    public.writeFile(ENGINE_PATH + f, body)
            if conf_old:
                public.writeFile(self.WAFPRO_CONF, conf_old)
            return public.returnMsg(False, 'nginx test failed, kept the old engine: {}'.format(
                out.strip().split('\n')[-1][:200]))
        public.serviceReload()
        return public.returnMsg(True, 'Engine updated and nginx reloaded')

    # ----------------------------------------------------------------
    # plugin self-update
    # ----------------------------------------------------------------
    # The store's own Update button only exists for plugins aaPanel hosts
    # (it asks their API by soft_id), so a third-party plugin updates itself:
    # GitHub's latest release carries wafpro-<version>.zip, laid out like the
    # zip users upload by hand (a wafpro/ folder). Installing does what the
    # panel's input_zip does: copy over the plugin dir (settings and data
    # files are not in the zip, so they stay) and run install.sh, which
    # recompiles the rules and reloads nginx only on a passing nginx -t.
    UPDATE_FILE = PLUGIN_PATH + 'update.json'
    UPDATE_API = 'https://api.github.com/repos/ByEzel93/wafpro/releases/latest'
    UPDATE_CRON = '/etc/cron.d/wafpro_update'
    UPDATE_TTL = 6 * 3600

    def _version(self):
        info = self._read_json(PLUGIN_PATH + 'info.json', {}) or {}
        return str(info.get('versions') or info.get('version') or '0')

    @staticmethod
    def _vtuple(v):
        return tuple(int(x) for x in re.findall(r'\d+', str(v))[:4])

    def _update_state(self):
        st = self._read_json(self.UPDATE_FILE, {}) or {}
        st['auto'] = bool(st.get('auto')) and os.path.exists(self.UPDATE_CRON)
        return st

    def _fetch_release(self):
        import urllib.request
        req = urllib.request.Request(self.UPDATE_API, headers={
            'User-Agent': 'wafpro', 'Accept': 'application/vnd.github+json'})
        rel = json.loads(urllib.request.urlopen(req, timeout=20).read().decode('utf-8'))
        ver = str(rel.get('tag_name') or '').lstrip('vV')
        asset = None
        for a in rel.get('assets') or []:
            if a.get('name') == 'wafpro-{}.zip'.format(ver):
                asset = a
                break
        if not ver or not asset:
            raise ValueError('the latest release has no wafpro-{}.zip'.format(ver or '?'))
        digest = str(asset.get('digest') or '')
        return {
            'version': ver,
            'notes': rel.get('body') or '',
            'url': asset.get('browser_download_url'),
            'size': asset.get('size') or 0,
            'sha256': digest[7:] if digest.startswith('sha256:') else '',
            'page': rel.get('html_url') or '',
            'date': (rel.get('published_at') or '')[:10],
        }

    def update_check(self, get=None):
        '''Latest release vs the installed version. Cached for a few hours
        (GitHub allows 60 anonymous API calls an hour per IP); force=1 skips
        the cache.'''
        st = self._update_state()
        force = str(self._arg(get, 'force', '0')) == '1' if get else False
        if force or not st.get('latest') or time.time() - st.get('checked', 0) > self.UPDATE_TTL:
            try:
                st['latest'] = self._fetch_release()
                st['checked'] = int(time.time())
                st.pop('error', None)
            except Exception as e:
                st['error'] = 'Could not reach GitHub: {}'.format(e)
                st['checked'] = int(time.time())
            self._write_json(self.UPDATE_FILE, st)
        cur = self._version()
        latest = st.get('latest') or {}
        return {
            'status': True,
            'current': cur,
            'latest': latest,
            'available': bool(latest) and self._vtuple(latest.get('version')) > self._vtuple(cur),
            'auto': st['auto'],
            'checked': time.strftime('%Y-%m-%d %H:%M', time.localtime(st['checked'])) if st.get('checked') else '',
            'error': st.get('error', ''),
            'last': st.get('last') or {},
        }

    def update_install(self, get=None):
        import hashlib
        import shutil
        import zipfile
        import urllib.request
        chk = self.update_check(get)
        rel = chk['latest']
        if not chk['available']:
            return public.returnMsg(False, chk['error'] or 'Already on the latest version ({})'.format(chk['current']))
        tmp = '/www/server/panel/temp/wafpro_update/'
        bak = tmp + 'backup/'
        shutil.rmtree(tmp, ignore_errors=True)
        os.makedirs(bak)

        def fail(msg):
            shutil.rmtree(tmp, ignore_errors=True)
            self._update_log(rel['version'], False, msg)
            return public.returnMsg(False, msg)

        try:
            req = urllib.request.Request(rel['url'], headers={'User-Agent': 'wafpro'})
            body = urllib.request.urlopen(req, timeout=120).read()
        except Exception as e:
            return fail('Download failed: {}'.format(e))
        if rel.get('sha256') and hashlib.sha256(body).hexdigest() != rel['sha256']:
            return fail('Download is corrupt (sha256 does not match the release)')
        zpath = tmp + 'wafpro.zip'
        with open(zpath, 'wb') as f:
            f.write(body)
        try:
            with zipfile.ZipFile(zpath) as z:
                names = z.namelist()
                if any(n.startswith('/') or '..' in n.split('/') or not n.startswith('wafpro/') for n in names):
                    return fail('Unexpected layout in the release zip')
                z.extractall(tmp + 'new/')
        except zipfile.BadZipFile:
            return fail('Release zip cannot be opened')
        src = tmp + 'new/wafpro/'
        info = self._read_json(src + 'info.json', {}) or {}
        if info.get('name') != 'wafpro' or not os.path.exists(src + 'wafpro_main.py') \
                or self._vtuple(info.get('versions')) != self._vtuple(rel['version']):
            return fail('Release zip does not contain WAF Pro {}'.format(rel['version']))

        # keep the files the zip replaces, to put them back if install.sh fails
        files = [os.path.relpath(os.path.join(d, f), src) for d, _, fs in os.walk(src) for f in fs]
        for f in files:
            if os.path.isfile(PLUGIN_PATH + f):
                os.makedirs(os.path.dirname(bak + f), exist_ok=True)
                shutil.copy2(PLUGIN_PATH + f, bak + f)
        old = self._version()
        public.ExecShell('\\cp -a -r {}* {}'.format(src, PLUGIN_PATH))
        out = public.ExecShell('cd {} && bash install.sh update 2>&1'.format(PLUGIN_PATH))[0]
        if 'Successify' not in out:
            for f in files:
                if os.path.exists(bak + f):
                    shutil.copy2(bak + f, PLUGIN_PATH + f)
                elif os.path.exists(PLUGIN_PATH + f):
                    os.remove(PLUGIN_PATH + f)
            public.ExecShell('cd {} && bash install.sh update 2>&1'.format(PLUGIN_PATH))
            return fail('install.sh failed, restored {}: {}'.format(old, out.strip().split('\n')[-1][:200]))
        shutil.rmtree(tmp, ignore_errors=True)
        icon = PLUGIN_PATH + 'icon.png'
        if os.path.exists(icon):
            shutil.copyfile(icon, '/www/server/panel/BTPanel/static/img/soft_ico/ico-wafpro.png')
        msg = 'Updated from {} to {}'.format(old, rel['version'])
        self._update_log(rel['version'], True, msg)
        return public.returnMsg(True, msg)

    def _update_log(self, version, ok, msg):
        st = self._read_json(self.UPDATE_FILE, {}) or {}
        st['last'] = {'version': version, 'ok': ok, 'msg': msg, 'time': time.strftime('%Y-%m-%d %H:%M:%S')}
        self._write_json(self.UPDATE_FILE, st)
        public.WriteLog('WAF Pro', 'Plugin update: ' + msg)

    def update_auto(self, get):
        '''Automatic updates: a daily cron job (minute picked at random so
        servers don't all ask GitHub at once) runs `wafpro_main.py
        auto_update`. Off unless turned on here.'''
        import random
        on = str(getattr(get, 'open', '0')) in ('1', 'true', 'True')
        st = self._read_json(self.UPDATE_FILE, {}) or {}
        if on:
            line = '{} {} * * * root cd /www/server/panel && /www/server/panel/pyenv/bin/python3 ' \
                   '{}wafpro_main.py auto_update >/dev/null 2>&1\n'.format(
                       random.randint(0, 59), random.randint(2, 5), PLUGIN_PATH)
            if not public.writeFile(self.UPDATE_CRON, line):
                return public.returnMsg(False, 'Could not write ' + self.UPDATE_CRON)
            os.chmod(self.UPDATE_CRON, 0o644)
        elif os.path.exists(self.UPDATE_CRON):
            os.remove(self.UPDATE_CRON)
        st['auto'] = on
        self._write_json(self.UPDATE_FILE, st)
        public.WriteLog('WAF Pro', 'Automatic updates -> {}'.format(on))
        return public.returnMsg(True, 'Automatic updates {}'.format('enabled' if on else 'disabled'))

    def set_switch(self, get):
        cfg = self._config()
        cfg['open'] = str(getattr(get, 'open', '1')) in ('1', 'true', 'True')
        if cfg['open'] and not cfg.get('start_time'):
            cfg['start_time'] = int(time.time())
        self._write_json(self.CONFIG, cfg)
        self._compile()
        public.WriteLog('WAF Pro', 'Firewall switch -> {}'.format(cfg['open']))
        return public.returnMsg(True, 'Firewall {}'.format('enabled' if cfg['open'] else 'disabled'))

    # ----------------------------------------------------------------
    # dashboard
    # ----------------------------------------------------------------
    def overview(self, get):
        try:
            day = (getattr(get, 'date', '') or '').strip()
            if day and not re.match(r'^\d{4}-\d{2}-\d{2}$', day):
                day = ''
            if day == time.strftime('%Y-%m-%d'):
                day = ''
            data = self._dash().overview(day or None)
            data['day'] = day or time.strftime('%Y-%m-%d')
            data['engine_installed'] = True
            data['engine'] = self._engine_state()
            return data
        except Exception as e:
            return {'status': False, 'msg': 'overview failed: {}'.format(e)}

    def realtime(self, get):
        try:
            return {'status': True, 'qps': self._dash().realtime_qps()}
        except Exception as e:
            return {'status': False, 'msg': str(e)}

    # ----------------------------------------------------------------
    # logs (with the filtering the old module never had)
    # ----------------------------------------------------------------
    def get_log_dates(self, get):
        '''Available log dates + the managed site list.

        Our engine writes one file per day (YYYY-MM-DD.log) with the site inside
        each record, so dates come from filenames and sites from the panel — not
        from a <site>_<date>.log naming scheme like the free WAF used.
        '''
        dates = set()
        if os.path.isdir(WAF_LOG_DIR):
            for f in os.listdir(WAF_LOG_DIR):
                if not f.endswith('.log') or f == 'debug.log':
                    continue
                d = f[:-4]
                if re.match(r'^\d{4}-\d{2}-\d{2}$', d):
                    dates.add(d)
        return {'status': True, 'dates': sorted(dates, reverse=True),
                'sites': self._panel_sites()}

    # engine rule id -> human readable name for the Filter column and the
    # type dropdown. Keys must match what deny()/log_block() actually write.
    FILTER_NAMES = {
        'get': 'SQL/XSS in query', 'post': 'SQL/XSS in body', 'cookie': 'Cookie attack',
        'user-agent': 'Scanner (UA)', 'scan': 'Sensitive path probe',
        'cc': 'CC flood', 'cc-blocked': 'CC flood', 'smart-cc': 'Smart CC',
        'crawl': 'Crawl limit', 'waiting-room': 'Waiting room',
        'banned': 'Auto-banned IP', 'ip-black': 'IP blacklist', 'url-black': 'URL blacklist',
        'malicious-ip': 'Malicious IP feed', 'fake-spider': 'Fake spider',
        'deny-ext': 'Forbidden file', 'upload-ext': 'Webshell upload',
        'php-path': 'PHP in upload dir', 'method': 'Bad HTTP method', 'header': 'Oversized header',
        'region:intercept': 'Region blocked', 'region:pass': 'Region not allowed',
        'region': 'Region rule', 'sensitive': 'Sensitive word',
        'traffic': 'Traffic limit', 'traffic-block': 'Traffic limit (block)',
        'custom': 'Custom rule',
        'ua-black': 'UA blacklist', 'url-keyword': 'URL keyword',
        'http-package': 'Oversized request body', 'deny-path': 'Forbidden URL',
        'hotlink': 'Anti-leech', 'protected-url': 'Protected URL', 'api': 'API defense',
        'php2shell': 'PHP2Shell guard', 'form-data': 'Malformed form-data',
        'challenge': 'Browser verification', 'nday': 'Known exploit (N-day)',
        'idc': 'Datacenter (IDC) IP', 'url-method': 'URL request type', 'url-cc': 'URL CC defense',
        'sqli': 'SQL injection', 'xss': 'XSS', 'cmdi': 'Command execution', 'lfi': 'File access / traversal',
        'weak-password': 'Weak password', 'dir-scan': 'Directory scan',
    }

    def _log_files(self, site, date):
        '''Pick the log files matching a site + date filter.
        date: '' or 'all' = every day, 'today', 'yesterday', or YYYY-MM-DD.'''
        want = None
        if date in ('today', ''):
            want = time.strftime('%Y-%m-%d') if date == 'today' else None
        elif date == 'yesterday':
            want = time.strftime('%Y-%m-%d', time.localtime(time.time() - 86400))
        elif date and date != 'all':
            want = date
        # Our engine writes one file per day (YYYY-MM-DD.log) with the site
        # inside each record — not the free WAF's per-site <site>_<date>.log.
        # So the site filter is applied when reading the records, not here.
        files = []
        if not os.path.isdir(WAF_LOG_DIR):
            return files
        for f in sorted(os.listdir(WAF_LOG_DIR), reverse=True):
            if not f.endswith('.log') or f == 'debug.log':
                continue
            d = f[:-4]
            if not re.match(r'^\d{4}-\d{2}-\d{2}$', d):
                continue
            if want and d != want:
                continue
            files.append((site or '', WAF_LOG_DIR + f))
        return files

    def clear_logs(self, get):
        '''Delete WAF log records: every site (whole day files), or just one
        site's rows — the day files hold all sites, so those are rewritten.'''
        site = (getattr(get, 'siteName', '') or '').strip()
        date = getattr(get, 'date', 'all')
        removed = 0
        for _s, path in self._log_files('', date):
            try:
                if not site:
                    os.remove(path)
                    removed += 1
                    continue
                keep = []
                with open(path, 'r', errors='ignore') as fh:
                    for line in fh:
                        try:
                            if json.loads(line).get('site') == site:
                                removed += 1
                                continue
                        except Exception:
                            pass
                        keep.append(line)
                public.writeFile(path, ''.join(keep))
                os.system('chown www:www {} 2>/dev/null'.format(path))
            except Exception:
                pass
        what = 'record(s) of ' + site if site else 'log file(s)'
        public.WriteLog('WAF Pro', 'Cleared {} WAF {}'.format(removed, what))
        return public.returnMsg(True, 'Cleared {} {}'.format(removed, what))

    def rule_hits(self, get):
        '''Rule hit record: how often each filter fired, per site — counted
        from our own block log rather than a counters file.'''
        rows = {}
        want_site = getattr(get, 'siteName', '')
        for _s, path in self._log_files('', getattr(get, 'date', '')):
            try:
                f = open(path, 'r')
            except Exception:
                continue
            for line in f:
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                if want_site and d.get('site') != want_site:
                    continue
                k = (d.get('rule', '?').split(':')[0], d.get('site', '?'))
                rows[k] = rows.get(k, 0) + 1
            f.close()
        # UI wants three things: a per-filter total (with a readable name), a
        # per-site breakdown, and the grand total.
        by_rule, per_site, total = {}, [], 0
        for (rule, site), v in rows.items():
            by_rule[rule] = by_rule.get(rule, 0) + v
            per_site.append({'rule': rule, 'name': self.FILTER_NAMES.get(rule, rule),
                             'site': site, 'count': v})
            total += v
        rules = [{'rule': k, 'name': self.FILTER_NAMES.get(k, k), 'count': v}
                 for k, v in by_rule.items()]
        rules.sort(key=lambda x: x['count'], reverse=True)
        per_site.sort(key=lambda x: x['count'], reverse=True)
        return {'status': True, 'total': total, 'rules': rules,
                'per_site': per_site, 'data': per_site}

    # ----------------------------------------------------------------
    # Report — attack analytics over a date range, from the block log.
    # ----------------------------------------------------------------
    def _report_files(self, date, start, end):
        '''Log files for a report: an explicit start..end range wins, else the
        named window (today/yesterday/all).'''
        if not os.path.isdir(WAF_LOG_DIR):
            return []
        if start and end:
            out = []
            for f in sorted(os.listdir(WAF_LOG_DIR), reverse=True):
                if not f.endswith('.log') or f == 'debug.log':
                    continue
                d = f[:-4]
                if re.match(r'^\d{4}-\d{2}-\d{2}$', d) and start <= d <= end:
                    out.append(WAF_LOG_DIR + f)
            return out
        return [p for _s, p in self._log_files('', date or 'today')]

    def _report_records(self, get):
        date = getattr(get, 'date', 'today')
        start = (getattr(get, 'start', '') or '').strip()
        end = (getattr(get, 'end', '') or '').strip()
        site = (getattr(get, 'siteName', '') or '').strip()
        recs = []
        for path in self._report_files(date, start, end):
            try:
                f = open(path, 'r')
            except Exception:
                continue
            for line in f:
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                if site and d.get('site') != site:
                    continue
                recs.append(d)
            f.close()
        return recs

    def report(self, get):
        '''IP report, URI report, protection-type breakdown and a country
        leaderboard for the selected window — all from one log pass.'''
        recs = self._report_records(get)
        types, ip_stat, uri_stat = {}, {}, {}
        for d in recs:
            rule = (d.get('rule') or '?').split(':')[0]
            types[rule] = types.get(rule, 0) + 1
            ip = d.get('ip') or '?'
            ip_stat[ip] = ip_stat.get(ip, 0) + 1
            uri = (d.get('uri') or '/').split('?')[0]
            uri_stat[uri] = uri_stat.get(uri, 0) + 1
        total = len(recs)

        # geo-resolve the top attackers only (bounded work)
        top_ips = sorted(ip_stat.items(), key=lambda x: -x[1])[:300]
        geo = {}
        try:
            dash = self._dash()
            for ip, _c in top_ips:
                try:
                    geo[ip] = dash.geo_lookup(ip).get('country') or 'Unknown'
                except Exception:
                    geo[ip] = 'Unknown'
        except Exception:
            pass

        ip_report, country = [], {}
        for ip, cnt in top_ips:
            loc = geo.get(ip, 'Unknown')
            ip_report.append({'ip': ip, 'location': loc, 'count': cnt,
                              'ratio': round(cnt * 100.0 / total, 1) if total else 0})
            country[loc] = country.get(loc, 0) + cnt

        uri_report = [{'uri': u, 'count': c,
                       'ratio': round(c * 100.0 / total, 1) if total else 0}
                      for u, c in sorted(uri_stat.items(), key=lambda x: -x[1])[:300]]

        protection = [{'rule': k, 'name': self.FILTER_NAMES.get(k, k), 'count': v}
                      for k, v in sorted(types.items(), key=lambda x: -x[1])]
        leaderboard = [{'country': k, 'count': v}
                       for k, v in sorted(country.items(), key=lambda x: -x[1])[:12]]

        return {'status': True, 'total': total,
                'ip_report': ip_report, 'uri_report': uri_report,
                'protection': protection, 'leaderboard': leaderboard,
                'unique_ips': len(ip_stat)}

    def report_search(self, get):
        '''Find log records whose IP or URI contains the query.'''
        q = (getattr(get, 'q', '') or '').strip().lower()
        if not q:
            return {'status': False, 'msg': 'Enter an IP or URI to search'}
        out = []
        for d in self._report_records(get):
            if q in (d.get('ip') or '').lower() or q in (d.get('uri') or '').lower():
                out.append({'time': d.get('time'), 'ip': d.get('ip'),
                            'site': d.get('site'), 'uri': d.get('uri'),
                            'rule': d.get('rule'),
                            'name': self.FILTER_NAMES.get((d.get('rule') or '').split(':')[0], d.get('rule')),
                            'status': d.get('status')})
                if len(out) >= 500:
                    break
        return {'status': True, 'data': out, 'count': len(out)}

    def report_ip_detail(self, get):
        '''Every block this IP triggered in the window — for the Details link.'''
        ip = (getattr(get, 'ip', '') or '').strip()
        if not ip:
            return {'status': False, 'msg': 'No IP'}
        rows, by_rule = [], {}
        for d in self._report_records(get):
            if d.get('ip') != ip:
                continue
            r = (d.get('rule') or '?').split(':')[0]
            by_rule[r] = by_rule.get(r, 0) + 1
            if len(rows) < 200:
                rows.append({'time': d.get('time'), 'site': d.get('site'),
                             'uri': d.get('uri'), 'rule': d.get('rule'),
                             'name': self.FILTER_NAMES.get(r, r),
                             'payload': d.get('payload'), 'status': d.get('status')})
        loc = 'Unknown'
        try:
            loc = self._dash().geo_lookup(ip).get('country') or 'Unknown'
        except Exception:
            pass
        breakdown = [{'name': self.FILTER_NAMES.get(k, k), 'count': v}
                     for k, v in sorted(by_rule.items(), key=lambda x: -x[1])]
        return {'status': True, 'ip': ip, 'location': loc,
                'rows': rows, 'breakdown': breakdown}

    # ---- Attack Map ----
    MAP_FILE = PLUGIN_PATH + 'map_location.json'

    def _server_location(self):
        '''Where the "Local IP" marker sits. A manual override (Modify) wins;
        otherwise geo-locate the panel's own public IP.'''
        saved = self._read_json(self.MAP_FILE, None)
        if isinstance(saved, dict) and saved.get('lat') is not None:
            return saved
        ip = ''
        try:
            ip = (public.readFile('/www/server/panel/data/iplist.txt') or '').strip().split('\n')[0]
        except Exception:
            pass
        loc = {'ip': ip, 'lat': None, 'lon': None, 'country': '', 'city': ''}
        if ip:
            try:
                g = self._dash().geo_lookup(ip)
                loc.update({'lat': g.get('lat'), 'lon': g.get('lon'),
                            'country': g.get('country') or '', 'city': g.get('city') or ''})
            except Exception:
                pass
        return loc

    def attack_map(self, get):
        '''Attacker coordinates + the server marker, for the world map.'''
        recs = self._report_records(get)
        pts = {}
        try:
            dash = self._dash()
        except Exception:
            dash = None
        for d in recs:
            ip = d.get('ip') or ''
            if not ip or not dash:
                continue
            try:
                g = dash.geo_lookup(ip)
            except Exception:
                continue
            lat, lon = g.get('lat'), g.get('lon')
            if lat is None or lon is None:
                continue
            key = '{:.2f},{:.2f}'.format(lat, lon)
            p = pts.get(key)
            if not p:
                p = {'lat': lat, 'lon': lon, 'count': 0,
                     'country': g.get('country') or 'Unknown', 'city': g.get('city') or ''}
                pts[key] = p
            p['count'] += 1
        return {'status': True, 'points': list(pts.values()),
                'server': self._server_location()}

    def set_map_location(self, get):
        '''Manually set the Local IP marker's coordinates.'''
        try:
            lat = float(getattr(get, 'lat'))
            lon = float(getattr(get, 'lon'))
        except Exception:
            return public.returnMsg(False, 'Latitude and longitude must be numbers')
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            return public.returnMsg(False, 'Coordinates out of range')
        cur = self._server_location()
        cur.update({'lat': lat, 'lon': lon})
        self._write_json(self.MAP_FILE, cur)
        return public.returnMsg(True, 'Map location updated')

    def get_logs(self, get):
        '''Filterable, paged WAF log reader.

        args: siteName, date(all|today|yesterday|YYYY-MM-DD), p, size,
              ip, url, type, keyword, q (searches IP/URL/UA/domain/region)
        '''
        import html
        site = getattr(get, 'siteName', '')
        date = getattr(get, 'date', time.strftime('%Y-%m-%d'))
        try:
            p = max(int(getattr(get, 'p', 1)), 1)
        except Exception:
            p = 1
        try:
            size = min(max(int(getattr(get, 'size', 20)), 5), 200)
        except Exception:
            size = 20
        f_ip = (getattr(get, 'ip', '') or '').strip()
        f_url = (getattr(get, 'url', '') or '').strip().lower()
        f_type = (getattr(get, 'type', '') or '').strip()
        f_kw = (getattr(get, 'keyword', '') or '').strip().lower()
        f_q = (getattr(get, 'q', '') or '').strip().lower()

        try:
            geo = self._dash()
        except Exception:
            geo = None

        rows = []
        for s, path in self._log_files(site, date):
            try:
                with open(path, 'rb') as fh:
                    body = fh.read().decode('utf-8', 'ignore')
            except Exception:
                continue
            for line in body.split('\n'):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if not isinstance(rec, dict):
                    continue
                # our engine's record: one JSON object per block
                r = {'time': time.strftime('%Y-%m-%d %H:%M:%S',
                                           time.localtime(rec.get('time', 0))),
                     'ip': rec.get('ip', ''), 'method': rec.get('method', ''),
                     'url': rec.get('uri', ''), 'ua': rec.get('ua', ''),
                     'type': rec.get('rule', ''), 'rule': rec.get('payload', ''),
                     'site': rec.get('site', ''), 'status': rec.get('status', 0),
                     'rx': rec.get('rx', '')}
                if site and r['site'] != site:
                    continue
                if f_ip and f_ip not in r['ip']:
                    continue
                if f_url and f_url not in r['url'].lower():
                    continue
                if f_type and r['type'] != f_type:
                    continue
                if f_kw and f_kw not in (r['url'] + ' ' + r['ua'] + ' ' + str(r['rule'])).lower():
                    continue
                rows.append(r)

        rows.sort(key=lambda x: x['time'], reverse=True)

        # geo + friendly filter name, then the free-text search across everything
        out = []
        for r in rows:
            g = geo.geo_lookup(r['ip']) if geo else {}
            r['location'] = g.get('country', '') or 'Unknown'
            if g.get('city'):
                r['location'] += ' / ' + g['city']
            r['filter_name'] = type(self).FILTER_NAMES.get(r['type'], r['type'])
            if f_q:
                hay = ' '.join([r['ip'], r['url'], r['ua'], r['site'],
                                r['location'], r['filter_name'], str(r['rule'])]).lower()
                if f_q not in hay:
                    continue
            out.append(r)

        total = len(out)
        page = out[(p - 1) * size: p * size]
        for r in page:  # escape once, on output
            for k in ('ip', 'method', 'url', 'ua', 'type', 'rule', 'site',
                      'location', 'filter_name', 'rx'):
                r[k] = html.escape(str(r[k]), True)
        types = sorted({r['type'] for r in out})
        return {'status': True, 'total': total, 'p': p, 'size': size,
                'pages': max((total + size - 1) // size, 1),
                'data': page, 'types': types,
                'type_names': {t: type(self).FILTER_NAMES.get(t, t) for t in types}}

    def export_logs(self, get):
        '''Export the filtered log set as CSV (returns a download path).'''
        get.size = 100000
        get.p = 1
        res = self.get_logs(get)
        rows = res.get('data', [])
        out = ['Start time,User IP,Domain name,Type,URL address,Status,IP location,Filter,Rule,User-Agent']

        def esc(v):
            v = str(v).replace('"', '""')
            return '"{}"'.format(v)

        for r in rows:
            out.append(','.join([esc(r['time']), esc(r['ip']), esc(r['site']),
                                 esc(r['method']), esc(r['url']), esc('Intercepted'),
                                 esc(r.get('location', '')), esc(r.get('filter_name', r['type'])),
                                 esc(r['rule']), esc(r['ua'])]))
        if not os.path.exists(PLUGIN_PATH + 'export'):
            os.makedirs(PLUGIN_PATH + 'export', 0o700)
        fname = 'wafpro_logs_{}.csv'.format(time.strftime('%Y%m%d_%H%M%S'))
        path = PLUGIN_PATH + 'export/' + fname
        public.writeFile(path, '\n'.join(out))
        return {'status': True, 'path': path, 'rows': len(rows), 'filename': fname}

    def download_export(self, get):
        '''Stream a previously generated CSV back to the browser.'''
        fname = os.path.basename(getattr(get, 'filename', ''))
        path = PLUGIN_PATH + 'export/' + fname
        if not fname.endswith('.csv') or not os.path.exists(path):
            return public.returnMsg(False, 'Export not found')
        from flask import send_file
        return send_file(path, as_attachment=True, download_name=fname)

    # ----------------------------------------------------------------
    # site + global config passthrough (single source of truth: the engine)
    # ----------------------------------------------------------------
    def get_config(self, get):
        cfg = dict(self._config())
        cfg['status'] = True
        cfg['engine'] = self._engine_state()
        cfg['health'] = self._engine_health() if cfg['engine']['wired'] else None
        return cfg

    def save_config(self, get):
        cfg = self._config()
        try:
            patch = json.loads(getattr(get, 'config', '{}'))
        except Exception:
            return public.returnMsg(False, 'Invalid config payload')
        for k, v in patch.items():
            if k not in self.DEFAULT_CONFIG:
                continue
            if k in self.CONFIG_CHOICES:
                if v in self.CONFIG_CHOICES[k]:
                    cfg[k] = v
            elif isinstance(self.DEFAULT_CONFIG[k], bool):
                cfg[k] = bool(v)
            else:
                try:
                    cfg[k] = int(v)
                except Exception:
                    continue
        self._write_json(self.CONFIG, cfg)
        self._compile()
        public.WriteLog('WAF Pro', 'global settings saved')
        return public.returnMsg(True, 'Settings saved')

    # ---- config export / import / restore (Global tab) ----

    # what a config bundle carries — everything a user tunes, nothing runtime
    EXPORT_PARTS = ('config', 'sites', 'region_rules', 'traffic_rules',
                    'custom_rules', 'methods', 'hdr_limits', 'site_rules',
                    'ip_white', 'ip_black', 'url_white', 'url_black', 'sensitive',
                    'url_keyword', 'ua_white', 'ua_black')

    def _part_path(self, part):
        m = {'config': self.CONFIG, 'sites': self.SITES,
             'region_rules': self.RULES_JSON, 'traffic_rules': self.TRAFFIC_JSON,
             'custom_rules': self.CUSTOM_JSON, 'methods': self.METHODS_FILE,
             'hdr_limits': self.HDR_FILE, 'site_rules': self.SITE_RULES_JSON}
        return m.get(part) or self._list_path(part)

    def export_config(self, get):
        '''Bundle every user-tunable setting into one JSON blob for download.'''
        bundle = {'_wafpro': 1, 'exported': time.strftime('%Y-%m-%d %H:%M:%S')}
        for part in self.EXPORT_PARTS:
            bundle[part] = self._read_json(self._part_path(part), None)
        return {'status': True, 'data': bundle,
                'filename': 'wafpro-config-{}.json'.format(time.strftime('%Y%m%d-%H%M%S'))}

    def import_config(self, get):
        '''Replace settings from a bundle produced by export_config.'''
        try:
            bundle = json.loads(getattr(get, 'data', '{}'))
        except Exception:
            return public.returnMsg(False, 'The file is not valid JSON')
        if not isinstance(bundle, dict) or not bundle.get('_wafpro'):
            return public.returnMsg(False, 'Not a WAF Pro config file')
        applied = []
        for part in self.EXPORT_PARTS:
            if part in bundle and bundle[part] is not None:
                self._write_json(self._part_path(part), bundle[part])
                applied.append(part)
        self._compile()
        public.WriteLog('WAF Pro', 'config imported ({} parts)'.format(len(applied)))
        return public.returnMsg(True, 'Imported {} section(s). Settings applied.'.format(len(applied)))

    def restore_config(self, get):
        '''Wipe every user setting back to first-install defaults.'''
        for part in self.EXPORT_PARTS:
            path = self._part_path(part)
            try:
                if os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass
        # regenerate config + per-site defaults, then recompile
        self._config()
        self._sites()
        self._compile()
        public.WriteLog('WAF Pro', 'config restored to defaults')
        return public.returnMsg(True, 'All settings restored to defaults')

    # ----------------------------------------------------------------
    # origin-response tracking (opt-in nginx log format change)
    # ----------------------------------------------------------------
    NGINX_CONF = '/www/server/nginx/conf/nginx.conf'
    VHOST_DIR = '/www/server/panel/vhost/nginx/'
    # Our log_format lives in its own vhost include, NOT in nginx.conf: an
    # nginx upgrade from the panel regenerates nginx.conf, which dropped the
    # format while the site confs still used it -> nginx refused to start with
    # 'unknown log format "wafpro"' (issue #3). The "0." prefix sorts it before
    # every site conf, which is required: access_log looks the format up at
    # parse time.
    RT_FORMAT_FILE = '/www/server/panel/vhost/nginx/0.wafpro_log_format.conf'
    RT_FORMAT = ("log_format wafpro '$remote_addr - $remote_user [$time_local] \"$request\" '\n"
                 "                  '$status $body_bytes_sent \"$http_referer\" \"$http_user_agent\" '\n"
                 "                  'rt=$request_time urt=$upstream_response_time';\n")
    RT_USE_RE = re.compile(r'access_log\s+\S+\s+wafpro\s*;')

    def _rt_skip(self, f):
        return (not f.endswith('.conf') or f.startswith('0.') or
                f in ('wafpro.conf', 'phpfpm_status.conf'))

    def _rt_strip_main_conf(self):
        '''Remove the format a pre-2.1 version inserted into nginx.conf (a
        second definition next to our include would be a duplicate).'''
        conf = public.readFile(self.NGINX_CONF) or ''
        new = re.sub(r"\n?[ \t]*log_format wafpro '[^;]*;\n?", '\n', conf)
        if new != conf:
            public.writeFile(self.NGINX_CONF, new)
            return conf
        return None

    def _rt_heal(self):
        '''Self-repair for issue #3: site confs reference the wafpro format
        but its definition is gone. Recreate it in our own include.'''
        try:
            if os.path.exists(self.RT_FORMAT_FILE):
                return False
            if 'log_format wafpro' in (public.readFile(self.NGINX_CONF) or ''):
                return False
            for f in os.listdir(self.VHOST_DIR):
                if self._rt_skip(f):
                    continue
                if self.RT_USE_RE.search(public.readFile(self.VHOST_DIR + f) or ''):
                    public.writeFile(self.RT_FORMAT_FILE, self.RT_FORMAT)
                    return True
        except Exception:
            pass
        return False

    def rt_status(self, get):
        '''Is origin-response tracking wired into nginx?'''
        self._rt_heal()
        has_fmt = os.path.exists(self.RT_FORMAT_FILE) or \
            'log_format wafpro' in (public.readFile(self.NGINX_CONF) or '')
        sites, applied = [], []
        try:
            for f in os.listdir(self.VHOST_DIR):
                if self._rt_skip(f):
                    continue
                c = public.readFile(self.VHOST_DIR + f) or ''
                if 'access_log' not in c:
                    continue
                name = f[:-5]
                sites.append(name)
                if self.RT_USE_RE.search(c):
                    applied.append(name)
        except Exception:
            pass
        return {'status': True, 'format_defined': has_fmt,
                'sites': sites, 'applied': applied,
                'enabled': bool(has_fmt and applied)}

    def _nginx_test(self):
        out, err = public.ExecShell('/www/server/nginx/sbin/nginx -t 2>&1')
        res = (out or '') + (err or '')
        return 'successful' in res, res

    def enable_rt(self, get):
        '''Add a log_format carrying $upstream_response_time and point the site
        access_log lines at it. Everything is backed up first and nginx is
        syntax-checked before reload; on failure we roll back.'''
        backups = {}
        created = False
        try:
            old_main = self._rt_strip_main_conf()
            if old_main is not None:
                backups[self.NGINX_CONF] = old_main
            if not os.path.exists(self.RT_FORMAT_FILE):
                public.writeFile(self.RT_FORMAT_FILE, self.RT_FORMAT)
                created = True

            changed = []
            for f in os.listdir(self.VHOST_DIR):
                if self._rt_skip(f):
                    continue
                path = self.VHOST_DIR + f
                c = public.readFile(path) or ''
                if 'access_log' not in c or self.RT_USE_RE.search(c):
                    continue
                # only touch real file logs, never "access_log off;" or syslog
                new_c = re.sub(r'access_log\s+(/\S+\.log)\s*;', r'access_log  \1 wafpro;', c)
                if new_c != c:
                    backups[path] = c
                    public.writeFile(path, new_c)
                    changed.append(f)

            ok, result = self._nginx_test()
            if not ok:
                for p, b in backups.items():
                    public.writeFile(p, b)
                if created and os.path.exists(self.RT_FORMAT_FILE):
                    os.remove(self.RT_FORMAT_FILE)
                return public.returnMsg(False, 'nginx test failed, changes reverted: {}'.format(result.strip()[:250]))

            public.serviceReload()
            public.WriteLog('WAF Pro', 'Origin-response tracking enabled ({} sites)'.format(len(changed)))
            return public.returnMsg(True, 'Origin response tracking enabled for {} site(s). '
                                          'Data appears as new requests come in.'.format(len(changed)))
        except Exception as e:
            for p, b in backups.items():
                try:
                    public.writeFile(p, b)
                except Exception:
                    pass
            return public.returnMsg(False, 'Failed: {}'.format(e))

    def disable_rt(self, get):
        '''Revert the access_log lines to the default format, then drop the
        format definition (sites first: a format still in use cannot go).'''
        backups = {}
        try:
            changed = 0
            for f in os.listdir(self.VHOST_DIR):
                if not f.endswith('.conf'):
                    continue
                path = self.VHOST_DIR + f
                c = public.readFile(path) or ''
                new_c = re.sub(r'(access_log\s+/\S+\.log)\s+wafpro\s*;', r'\1;', c)
                if new_c != c:
                    backups[path] = c
                    public.writeFile(path, new_c)
                    changed += 1
            fmt = public.readFile(self.RT_FORMAT_FILE) if os.path.exists(self.RT_FORMAT_FILE) else None
            if fmt is not None:
                os.remove(self.RT_FORMAT_FILE)
            old_main = self._rt_strip_main_conf()
            if old_main is not None:
                backups[self.NGINX_CONF] = old_main
            ok, result = self._nginx_test()
            if not ok:
                for p, b in backups.items():
                    public.writeFile(p, b)
                if fmt is not None:
                    public.writeFile(self.RT_FORMAT_FILE, fmt)
                return public.returnMsg(False, 'nginx test failed, changes reverted: {}'.format(result.strip()[:250]))
            public.serviceReload()
            return public.returnMsg(True, 'Origin response tracking disabled ({} sites)'.format(changed))
        except Exception as e:
            return public.returnMsg(False, 'Failed: {}'.format(e))

    # ----------------------------------------------------------------
    # list + rule management
    #
    # The engine's own signatures are inconsistent (IP lists want
    # start_ip/end_ip as dotted strings but are STORED as [[o,o,o,o],[...]],
    # URL lists want url_rule, deletes want an index, rules want
    # ruleName/ruleValue/ps). This layer hides all of that behind one
    # predictable API and — importantly — reports real success/failure.
    # ----------------------------------------------------------------
    # ----------------------------------------------------------------
    # IP / URL lists — our own storage
    #
    # Kept as plain JSON in the plugin dir and compiled into packed ranges
    # (ip_*.bin) or regex lines (url_white.txt) by _compile().
    # ----------------------------------------------------------------
    IP_LISTS = ('ip_white', 'ip_black')
    # regex lists. ua_* match the User-Agent, url_keyword the decoded request
    # line, sensitive the request line + urlencoded body
    URL_LISTS = ('url_white', 'url_black', 'sensitive', 'url_keyword', 'ua_white', 'ua_black')
    RULE_NAMES = ('get', 'post', 'cookie', 'ua', 'scan', 'nday')
    REMARKS_FILE = PLUGIN_PATH + 'remarks.json'

    def _ip_to_str(self, octets):
        try:
            return '.'.join(str(int(x)) for x in octets)
        except Exception:
            return str(octets)

    # ---- remarks ----
    def _remarks(self):
        return self._read_json(self.REMARKS_FILE, {}) or {}

    def _remark_get(self, list_name, key):
        return self._remarks().get(list_name, {}).get(key, '')

    def _remark_set(self, list_name, key, note):
        data = self._remarks()
        data.setdefault(list_name, {})
        if note:
            data[list_name][key] = note
        else:
            data[list_name].pop(key, None)
        public.writeFile(self.REMARKS_FILE, json.dumps(data))

    def _remark_del(self, list_name, key):
        self._remark_set(list_name, key, '')

    def _list_path(self, name):
        return PLUGIN_PATH + name + '.json'

    def _list_load(self, name):
        d = self._read_json(self._list_path(name), [])
        return d if isinstance(d, list) else []

    def _list_save(self, name, data):
        self._write_json(self._list_path(name), data)
        self._compile()

    LIST_TYPES = {'url_white': 'URL', 'url_black': 'URL', 'sensitive': 'Word',
                  'url_keyword': 'Word', 'ua_white': 'User-Agent', 'ua_black': 'User-Agent'}

    def list_get(self, get):
        name = getattr(get, 'list_name', '')
        if name not in self.IP_LISTS + self.URL_LISTS:
            return {'status': False, 'msg': 'Unknown list'}
        items = []
        for i, v in enumerate(self._list_load(name)):
            ip = v.get('ip') if isinstance(v, dict) else v
            if name in self.IP_LISTS:
                typ = 'IPv6' if ':' in str(ip) else 'IPv4'
            else:
                typ = self.LIST_TYPES.get(name, 'URL')
            items.append({
                'index': i,
                'value': ip,
                'remark': (v.get('ps') if isinstance(v, dict) else '') or self._remark_get(name, ip),
                'type': typ,
                'time': v.get('time', 0) if isinstance(v, dict) else 0,
            })
        return {'status': True, 'data': items}

    def list_add(self, get):
        '''IP lists take start_ip (+ optional end_ip): single IP, range or CIDR.
        URL lists take value (a PCRE fragment matched against the request URI).'''
        name = getattr(get, 'list_name', '')
        remark = (getattr(get, 'remark', '') or '').strip()
        if name not in self.IP_LISTS + self.URL_LISTS:
            return public.returnMsg(False, 'Unknown list')
        data = self._list_load(name)
        if name in self.IP_LISTS:
            start = getattr(get, 'start_ip', '') or getattr(get, 'value', '')
            end = getattr(get, 'end_ip', '')
            try:
                val = self._parse_ip_input(start, end)
            except ValueError as ve:
                return public.returnMsg(False, str(ve))
        else:
            val = (getattr(get, 'value', '') or '').strip()
            if not val:
                return public.returnMsg(False, 'Value is required')
            try:
                re.compile(val)
            except re.error as ex:
                return public.returnMsg(False, 'Invalid regular expression: {}'.format(ex))
        if any((x.get('ip') if isinstance(x, dict) else x) == val for x in data):
            return public.returnMsg(False, 'Already in the list')
        data.append({'ip': val, 'ps': remark, 'time': int(time.time())})
        self._list_save(name, data)
        public.WriteLog('WAF Pro', '{} += {}'.format(name, val))
        return public.returnMsg(True, 'Added')

    def list_del(self, get):
        name = getattr(get, 'list_name', '')
        if name not in self.IP_LISTS + self.URL_LISTS:
            return public.returnMsg(False, 'Unknown list')
        try:
            idx = int(getattr(get, 'index', -1))
        except Exception:
            idx = -1
        data = self._list_load(name)
        if idx < 0 or idx >= len(data):
            return public.returnMsg(False, 'Item not found')
        v = data.pop(idx)
        self._list_save(name, data)
        self._remark_del(name, v.get('ip') if isinstance(v, dict) else v)
        return public.returnMsg(True, 'Removed')

    def list_empty(self, get):
        name = getattr(get, 'list_name', '')
        if name not in self.IP_LISTS + self.URL_LISTS:
            return public.returnMsg(False, 'Unknown list')
        self._list_save(name, [])
        return public.returnMsg(True, 'List cleared')

    def list_export(self, get):
        '''Write the list to a one-value-per-line file the UI then downloads
        (the UI expects rows + filename; returning only the data left the
        Export button reporting "undefined rows exported").'''
        name = getattr(get, 'list_name', '')
        if name not in self.IP_LISTS + self.URL_LISTS:
            return {'status': False, 'msg': 'Unknown list'}
        vals = [x.get('ip') if isinstance(x, dict) else x for x in self._list_load(name)]
        if not os.path.exists(PLUGIN_PATH + 'export'):
            os.makedirs(PLUGIN_PATH + 'export', 0o700)
        fname = 'wafpro_{}_{}.csv'.format(name, time.strftime('%Y%m%d_%H%M%S'))
        public.writeFile(PLUGIN_PATH + 'export/' + fname, '\n'.join(str(v) for v in vals) + '\n')
        return {'status': True, 'rows': len(vals), 'filename': fname, 'data': vals}

    def list_import(self, get):
        name = getattr(get, 'list_name', '')
        if name not in self.IP_LISTS + self.URL_LISTS:
            return public.returnMsg(False, 'Unknown list')
        body = getattr(get, 'body', '') or ''
        data = self._list_load(name)
        have = set(x.get('ip') if isinstance(x, dict) else x for x in data)
        added, bad = 0, 0
        for line in body.replace(',', '\n').split('\n'):
            v = line.strip()
            if not v or v in have:
                continue
            if name in self.IP_LISTS:
                try:
                    v = self._parse_ip_input(v, '')
                except ValueError:
                    bad += 1
                    continue
            else:
                try:
                    re.compile(v)
                except re.error:
                    bad += 1
                    continue
            if v in have:
                continue
            data.append({'ip': v, 'ps': '', 'time': int(time.time())})
            have.add(v)
            added += 1
        self._list_save(name, data)
        return public.returnMsg(True, 'Imported {}{}'.format(
            added, ', {} skipped as invalid'.format(bad) if bad else ''))

    # ----------------------------------------------------------------
    # rule sets (regex) — Custom rules tab
    # ----------------------------------------------------------------
    def rule_get(self, get):
        name = getattr(get, 'rule_name', '')
        if name not in self.RULE_NAMES:
            return {'status': False, 'msg': 'Unknown rule set'}
        data = self._rule_set(name)
        return {'status': True, 'data': [
            {'index': i, 'rule': x.get('rule', ''), 'ps': x.get('ps', ''),
             'open': bool(x.get('open'))}
            for i, x in enumerate(data)]}

    def exclusive_rules(self, get):
        '''Exclusive Rules tab: the N-day virtual patches, the global switch
        that gates them, and how often each fired (from the block log).'''
        hits = {}
        for _s, path in self._log_files('', 'all'):
            try:
                with open(path, 'r', errors='ignore') as fh:
                    for line in fh:
                        if '"rule":"nday"' not in line:
                            continue
                        try:
                            rx = json.loads(line).get('rx', '')
                        except Exception:
                            continue
                        hits[rx] = hits.get(rx, 0) + 1
            except Exception:
                continue
        rows = [{'index': i, 'id': 10001 + i, 'rule': x.get('rule', ''), 'ps': x.get('ps', ''),
                 'open': bool(x.get('open')), 'hits': hits.get(x.get('rule', ''), 0)}
                for i, x in enumerate(self._rule_set('nday'))]
        return {'status': True, 'data': rows, 'enabled': bool(self._config().get('m_nday', True))}

    def rule_add(self, get):
        name = getattr(get, 'rule_name', '')
        if name not in self.RULE_NAMES:
            return public.returnMsg(False, 'Unknown rule set')
        rule = (getattr(get, 'rule', '') or '').strip()
        if not rule:
            return public.returnMsg(False, 'Rule is required')
        try:
            re.compile(rule)
        except re.error as ex:
            return public.returnMsg(False, 'Invalid regular expression: {}'.format(ex))
        data = self._rule_set(name)
        if any(x.get('rule') == rule for x in data):
            return public.returnMsg(False, 'Rule already exists')
        data.append({'rule': rule, 'ps': (getattr(get, 'ps', '') or '').strip(), 'open': True})
        self._save_rule_set(name, data)
        self._compile()
        public.WriteLog('WAF Pro', 'rule {} += {}'.format(name, rule))
        return public.returnMsg(True, 'Rule added')

    def rule_del(self, get):
        name = getattr(get, 'rule_name', '')
        if name not in self.RULE_NAMES:
            return public.returnMsg(False, 'Unknown rule set')
        try:
            idx = int(getattr(get, 'index', -1))
        except Exception:
            idx = -1
        data = self._rule_set(name)
        if idx < 0 or idx >= len(data):
            return public.returnMsg(False, 'Rule not found')
        data.pop(idx)
        self._save_rule_set(name, data)
        self._compile()
        return public.returnMsg(True, 'Rule removed')

    def rule_toggle(self, get):
        name = getattr(get, 'rule_name', '')
        if name not in self.RULE_NAMES:
            return public.returnMsg(False, 'Unknown rule set')
        try:
            idx = int(getattr(get, 'index', -1))
        except Exception:
            idx = -1
        data = self._rule_set(name)
        if idx < 0 or idx >= len(data):
            return public.returnMsg(False, 'Rule not found')
        on = str(getattr(get, 'open', '1')) in ('1', 'true', 'True')
        data[idx]['open'] = on
        self._save_rule_set(name, data)
        self._compile()
        return public.returnMsg(True, 'Rule {}'.format('enabled' if on else 'disabled'))

    # ---- IP helpers -------------------------------------------------
    @staticmethod
    def _ip2int(ip):
        parts = ip.strip().split('.')
        if len(parts) != 4:
            raise ValueError('not an IPv4 address: {}'.format(ip))
        n = 0
        for p in parts:
            v = int(p)
            if v < 0 or v > 255:
                raise ValueError('octet out of range: {}'.format(ip))
            n = (n << 8) | v
        return n

    @staticmethod
    def _int2ip(n):
        return '.'.join(str((n >> s) & 0xFF) for s in (24, 16, 8, 0))

    def _parse_ip_input(self, start, end=''):
        '''Normalise what the UI accepts into one stored value:
             1.2.3.4  /  2001:db8::1          single address
             1.2.3.4 + end 1.2.3.9            range (also "a-b")
             192.168.100.6-100                short IPv4 range
             192.168.1.0/24  /  2001:db8::/32 CIDR, kept as CIDR
        Raises ValueError with a message the UI can show.'''
        import ipaddress
        start = (start or '').strip()
        end = (end or '').strip()
        if not start:
            raise ValueError('Start IP is empty')
        text = '{}-{}'.format(start, end) if end else start
        try:
            fam, s, e = self._any_range(text)
        except ValueError as ex:
            msg = str(ex)
            if 'does not appear' in msg or 'not a valid' in msg:
                msg = 'Not a valid IPv4/IPv6 address: {}'.format(text)
            raise ValueError(msg)
        if '/' in text:
            return str(ipaddress.ip_network(text, strict=False))
        a, b = ipaddress.ip_address(s), ipaddress.ip_address(e)
        return str(a) if s == e else '{}-{}'.format(a, b)

    # ----------------------------------------------------------------
    # Region restriction — standalone
    #
    # This does not touch the free WAF. Our own engine (/www/server/wafpro)
    # enforces it, so the data model is ours: one rule per row, each with its
    # own areas, its own type and its own status code — which is exactly what
    # the stock engines cannot express (they share a single global cn.json).
    #
    # Panel side owns region_rules.json and compiles it down to what the lua
    # reads: rule/<id>.bin (packed, sorted, merged ranges) + rule/region.txt
    # + rule/version. Bumping version is what makes workers pick it up; no
    # nginx reload is involved.
    # ----------------------------------------------------------------
    RULES_JSON = PLUGIN_PATH + 'region_rules.json'
    COUNTRY_DB = '/www/server/panel/data/firewall/GeoLite2-Country.json'
    COUNTRY_CACHE = PLUGIN_PATH + 'countries.json'
    COUNTRY_CACHE_V = 2
    RULE_TYPES = ('intercept', 'pass')
    # Loopback/LAN are compiled into lan.bin and checked before any rule, so a
    # rule can never cut off localhost or the private network.
    PRIVATE_RANGES = [
        ('10.0.0.0', '10.255.255.255'),
        ('172.16.0.0', '172.31.255.255'),
        ('127.0.0.0', '127.255.255.255'),
        ('192.168.0.0', '192.168.255.255'),
        ('169.254.0.0', '169.254.255.255'),
    ]
    STATUS_CODES = [
        {'code': 444, 'name': '444 Close connection (No content returned)'},
        {'code': 403, 'name': '403 Access denied'},
        {'code': 404, 'name': '404 File not exist'},
        {'code': 502, 'name': '502 Connection timed out'},
        {'code': 503, 'name': '503 Server is unavailable'},
        {'code': 200, 'name': '200 Normal access'},
    ]
    REGION_PAGES = PLUGIN_PATH + 'region_pages/'

    def _region_sites(self, r):
        '''Sites a region rule covers; pre-2.2 rules hold one in 'site'.'''
        sites = r.get('sites') or [r.get('site', '')]
        return [x for x in sites if x]

    def _country_names(self):
        '''ISO 3166-1 alpha-2 -> English name, from CLDR via babel.

        The name has to come from the code alone. The GeoIP DB stores only
        'brief' + 'ips', and naming a block by geo-locating its first address
        is wrong: US starts at 1.1.1.0/32 (Cloudflare's resolver, registered to
        APNIC/AU), which used to label the United States "Australia".
        The panel's own country.txt is mis-keyed ("CH": "United States") and
        countryCode.json covers only 179 of the 250 codes, so neither is usable.
        '''
        try:
            from babel import Locale
            return dict(Locale('en').territories)
        except Exception:
            return {}

    def country_list(self, get):
        '''250 countries with ISO code, readable name and CIDR count.

        Source is the panel's own GeoLite2-Country.json, not the free WAF's —
        it ships with the panel, so this works with no WAF plugin installed.
        '''
        cached = self._read_json(self.COUNTRY_CACHE, None)
        if isinstance(cached, dict) and cached.get('v') == self.COUNTRY_CACHE_V and cached.get('data'):
            return {'status': True, 'data': cached['data']}
        db = self._read_json(self.COUNTRY_DB, [])
        if not isinstance(db, list) or not db:
            return {'status': False, 'msg': 'Country database not found on this panel'}
        names = self._country_names()
        out = []
        for x in db:
            code = x.get('brief') or ''
            ips = x.get('ips') or []
            out.append({'code': code, 'name': names.get(code) or code, 'cidr': len(ips)})
        out.sort(key=lambda x: x['name'])
        public.writeFile(self.COUNTRY_CACHE, json.dumps({'v': self.COUNTRY_CACHE_V, 'data': out}))
        return {'status': True, 'data': out}

    # ---------- compiling rules down for the engine ----------

    def _cidr_range(self, cidr):
        ip, bits = cidr.split('/', 1)
        bits = int(bits)
        base = self._ip2int(ip)
        mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        return base & mask, (base & mask) | (~mask & 0xFFFFFFFF)

    def _merge(self, ranges):
        '''Sort and coalesce touching/overlapping ranges.

        Both correctness and speed depend on this: the lua binary-searches the
        result, which requires sorted non-overlapping pairs, and merging alone
        takes US from 115,345 CIDRs down to ~43k ranges.
        '''
        ranges.sort()
        out = []
        for s, e in ranges:
            if out and s <= out[-1][1] + 1:
                if e > out[-1][1]:
                    out[-1][1] = e
            else:
                out.append([s, e])
        return out

    # Country ranges come from DB-IP's free country list (CC BY 4.0, monthly),
    # IPv4 and IPv6, one packed file per country and family. The panel's own
    # GeoLite2-Country.json is the IPv4 fallback until that list is
    # downloaded; it is IPv4 only and the panel stopped refreshing it, so
    # reassigned blocks keep their old country (131.222.0.0/15 was still
    # "US" in it after part of it moved to a Turkish ISP). RIR delegation
    # files were considered too, but they hold the registrant's country:
    # Hetzner's Finnish IPv6 shows up there as Germany.
    GEO_DIR = PLUGIN_PATH + 'geo/'
    GEO_META = PLUGIN_PATH + 'geo.json'
    GEO_URL = 'https://download.db-ip.com/free/dbip-country-lite-{}.csv.gz'

    def _geo_read(self, codes, ext, size):
        out = []
        for cc in codes:
            if not re.match(r'^[A-Z]{2}$', cc or ''):
                continue
            try:
                with open(self.GEO_DIR + cc + ext, 'rb') as f:
                    buf = f.read()
            except (IOError, OSError):
                continue
            half = size // 2
            for i in range(0, len(buf) - size + 1, size):
                out.append([int.from_bytes(buf[i:i + half], 'big'),
                            int.from_bytes(buf[i + half:i + size], 'big')])
        return self._merge(out)

    def _ranges_for(self, codes):
        '''Merged IPv4 ranges of the given countries, or None without data.'''
        if os.path.isdir(self.GEO_DIR):
            return self._geo_read(codes, '.bin', 8)
        db = self._read_json(self.COUNTRY_DB, [])
        if not isinstance(db, list) or not db:
            return None
        wanted, out = set(codes), []
        for x in db:
            if x.get('brief') not in wanted:
                continue
            for cidr in (x.get('ips') or []):
                try:
                    s, e = self._cidr_range(cidr)
                    out.append([s, e])
                except Exception:
                    continue
        return self._merge(out)

    def _ranges6_for(self, codes):
        '''Merged IPv6 ranges of the given countries, or None without data.'''
        if not os.path.isdir(self.GEO_DIR):
            return None
        return self._geo_read(codes, '.bin6', 32)

    def geo_status(self, get=None):
        m = self._read_json(self.GEO_META, None)
        return {'status': True, 'have': isinstance(m, dict) and os.path.isdir(self.GEO_DIR),
                'meta': m or {}}

    def geo_update(self, get=None):
        '''Download DB-IP's country list and rebuild the per-country files.'''
        import gzip
        import io
        import shutil
        import ipaddress
        import urllib.request
        t = time.localtime()
        prev = (t.tm_year, t.tm_mon - 1) if t.tm_mon > 1 else (t.tm_year - 1, 12)
        body, month = None, ''
        # the new month's file appears a day or two late
        for month in (time.strftime('%Y-%m', t), '%04d-%02d' % prev):
            try:
                req = urllib.request.Request(self.GEO_URL.format(month), headers={'User-Agent': 'wafpro'})
                body = urllib.request.urlopen(req, timeout=60).read()
                break
            except Exception:
                body = None
        if not body:
            return public.returnMsg(False, 'Could not download the country list from db-ip.com. '
                                           'Check the server\'s outbound access.')
        v4, v6 = {}, {}
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(body)) as f:
                for raw in f:
                    parts = raw.decode('ascii', 'ignore').strip().split(',')
                    if len(parts) != 3 or not re.match(r'^[A-Z]{2}$', parts[2]):
                        continue
                    try:
                        a = int(ipaddress.ip_address(parts[0]))
                        b = int(ipaddress.ip_address(parts[1]))
                    except ValueError:
                        continue
                    (v6 if ':' in parts[0] else v4).setdefault(parts[2], []).append([a, b])
        except Exception as e:
            return public.returnMsg(False, 'Country list is damaged: {}'.format(e))
        if len(v4) < 200 or len(v6) < 100:
            return public.returnMsg(False, 'Country list looks incomplete, kept the old one')

        tmp = self.GEO_DIR.rstrip('/') + '.new/'
        shutil.rmtree(tmp, ignore_errors=True)
        os.makedirs(tmp)
        n4 = n6 = 0
        for cc, ranges in v4.items():
            n4 += self._pack(self._merge(ranges), tmp + cc + '.bin')
        for cc, ranges in v6.items():
            n6 += self._pack6(self._merge(ranges), tmp + cc + '.bin6')
        shutil.rmtree(self.GEO_DIR, ignore_errors=True)
        os.rename(tmp, self.GEO_DIR)
        self._write_json(self.GEO_META, {'updated': time.strftime('%Y-%m-%d %H:%M:%S'),
                                         'edition': month, 'ranges': n4, 'ranges6': n6})
        # region rules rebuild their packed ranges from the new data
        for fn in os.listdir(RULE_DIR) if os.path.isdir(RULE_DIR) else []:
            if re.match(r'^r\d+\.bin6?$', fn):
                os.remove(RULE_DIR + fn)
        self._compile()
        msg = 'Country data updated: {} IPv4 + {} IPv6 ranges ({})'.format(n4, n6, month)
        public.WriteLog('WAF Pro', msg)
        return public.returnMsg(True, msg)

    def _pack(self, ranges, path):
        buf = b''.join(struct.pack('>II', s, e) for s, e in ranges)
        with open(path, 'wb') as f:
            f.write(buf)
        # nginx workers run as www: they must be able to read every rule file
        os.chmod(path, 0o644)
        return len(ranges)

    def _rules(self):
        r = self._read_json(self.RULES_JSON, [])
        return r if isinstance(r, list) else []

    def _region_build(self, rules):
        public.writeFile(self.RULES_JSON, json.dumps(rules))
        return self._compile()

    # ---------- API used by the Region tab ----------

    def region_rules(self, get):
        '''Rows for the table + everything needed to render the add dialog.'''
        rules = self._rules()
        names = self._country_names()
        rows = []
        for r in rules:
            rows.append({
                'id': r['id'],
                'site': r.get('site', ''),
                'sites': self._region_sites(r),
                'areas': r['areas'],
                'page': os.path.exists(self.REGION_PAGES + r['id'] + '.html'),
                'area_text': ', '.join(names.get(c) or c for c in r['areas']),
                'type': r['type'],
                'status': r['status'],
                'open': bool(r.get('open')),
                'ranges': r.get('ranges', 0),
            })
        return {
            'status': True,
            'rules': rows,
            'sites': self._panel_sites(),
            'status_codes': self.STATUS_CODES,
            'engine': self.region_engine_state(),
            'geo': self.geo_status(),
        }

    def region_engine_state(self):
        '''Is our engine actually wired into nginx? The table means nothing if
        it is not, so the UI has to be able to say so.'''
        return self._engine_state()

    def region_rule_add(self, get):
        '''args: areas (JSON array of ISO codes), site, type, status_code'''
        try:
            areas = json.loads(getattr(get, 'areas', '[]'))
        except Exception:
            return public.returnMsg(False, 'Invalid areas payload')
        if not isinstance(areas, list) or not areas:
            return public.returnMsg(False, 'Select at least one area')
        # sites: JSON list of site names, '*' meaning every site; the old
        # single 'site' arg still works
        try:
            sites = json.loads(getattr(get, 'sites', '') or '[]')
        except Exception:
            sites = []
        if not isinstance(sites, list):
            sites = []
        one = (getattr(get, 'site', '') or '').strip()
        if one:
            sites.append(one)
        known = set(self._panel_sites())
        sites = ['*'] if '*' in sites else sorted({x for x in sites if x in known})
        if not sites:
            return public.returnMsg(False, 'Please choose Website...')
        site = sites[0]
        typ = getattr(get, 'type', 'intercept')
        if typ not in self.RULE_TYPES:
            return public.returnMsg(False, 'Type must be intercept or pass')
        try:
            status = int(getattr(get, 'status_code', 444))
        except Exception:
            status = 444
        if status not in [c['code'] for c in self.STATUS_CODES]:
            return public.returnMsg(False, 'Unsupported status code')

        ranges = self._ranges_for(areas)
        if not ranges:
            return public.returnMsg(False, 'No IP ranges found for the selected areas')

        rid = 'r{}'.format(int(time.time() * 1000))
        if not os.path.exists(RULE_DIR):
            os.makedirs(RULE_DIR, 0o700)
        n = self._pack(ranges, RULE_DIR + rid + '.bin')
        rules = self._rules()
        rules.append({'id': rid, 'site': site, 'sites': sites, 'areas': areas, 'type': typ,
                      'status': status, 'open': True, 'ranges': n,
                      'created': time.strftime('%Y-%m-%d %H:%M:%S')})
        self._region_build(rules)
        public.WriteLog('WAF Pro', 'Region rule added: {} {} on {} ({} ranges)'.format(
            typ, ','.join(areas), ','.join(sites), n))
        return public.returnMsg(True, 'Rule added ({} ranges)'.format(n))

    def region_rule_del(self, get):
        rid = getattr(get, 'id', '')
        rules = [r for r in self._rules() if r['id'] != rid]
        if re.match(r'^r\d+$', rid or '') and os.path.exists(self.REGION_PAGES + rid + '.html'):
            os.remove(self.REGION_PAGES + rid + '.html')
        self._region_build(rules)
        return public.returnMsg(True, 'Rule removed')

    def region_page_get(self, get):
        '''The page a region rule answers with ("Response" in the table).
        Empty = the shared block page (or a bare status for 444/200...).'''
        rid = getattr(get, 'id', '')
        if not re.match(r'^r\d+$', rid or ''):
            return public.returnMsg(False, 'Bad rule id')
        return {'status': True, 'html': public.readFile(self.REGION_PAGES + rid + '.html') or '',
                'default': self._page('block')}

    def region_page_save(self, get):
        rid = getattr(get, 'id', '')
        if not re.match(r'^r\d+$', rid or '') or rid not in [r['id'] for r in self._rules()]:
            return public.returnMsg(False, 'Bad rule id')
        h = getattr(get, 'html', '') or ''
        if len(h) > 200000:
            return public.returnMsg(False, 'Page is too large')
        path = self.REGION_PAGES + rid + '.html'
        if h.strip():
            if not os.path.isdir(self.REGION_PAGES):
                os.makedirs(self.REGION_PAGES, 0o700)
            public.writeFile(path, h)
        elif os.path.exists(path):
            os.remove(path)
        self._compile()
        return public.returnMsg(True, 'Response page saved' if h.strip() else 'Response page reset to default')

    def region_rule_toggle(self, get):
        rid = getattr(get, 'id', '')
        on = str(getattr(get, 'open', '1')) in ('1', 'true', 'True')
        rules = self._rules()
        for r in rules:
            if r['id'] == rid:
                r['open'] = on
        self._region_build(rules)
        return public.returnMsg(True, 'Rule {}'.format('enabled' if on else 'disabled'))

    def region_rule_status(self, get):
        rid = getattr(get, 'id', '')
        try:
            status = int(getattr(get, 'status_code', 444))
        except Exception:
            return public.returnMsg(False, 'Bad status code')
        if status not in [c['code'] for c in self.STATUS_CODES]:
            return public.returnMsg(False, 'Unsupported status code')
        rules = self._rules()
        for r in rules:
            if r['id'] == rid:
                r['status'] = status
        self._region_build(rules)
        return public.returnMsg(True, 'Response set to {}'.format(status))

    # ----------------------------------------------------------------
    # Traffic limit — per-URL rate limiting, lowest priority.
    # Meant for API endpoints: cap how often one IP (or IP+UA) may hit a
    # specific URL per second, then return a status code or block the IP.
    # ----------------------------------------------------------------
    TRAFFIC_JSON = PLUGIN_PATH + 'traffic_rules.json'
    # stock model: condition 1 = single IP, 2 = IP+UA, 3 = all IPs together
    TRAFFIC_CONDS = {1: 'ip', 2: 'ipua', 3: 'all'}
    TRAFFIC_ACTIONS = ('status_403', 'status_404', 'status_502', 'status_503', 'content', 'drop')
    TRAFFIC_RETURNS = ('html', 'json', '444')

    def _traffic(self):
        r = self._read_json(self.TRAFFIC_JSON, [])
        return [self._traffic_upgrade(x) for x in r] if isinstance(r, list) else []

    def _traffic_upgrade(self, t):
        '''2.1 rules (site/url regex/dim/rate/action status|block) -> 2.2 fields.'''
        if 'cond' in t:
            return t
        t = dict(t)
        t['sites'] = [t.get('site', '')]
        t['types'] = 'url'
        t['path'] = t.get('url', '')
        t['regex'] = True                  # 2.1 stored a regex, keep matching it as one
        t['cond'] = {'ip': 1, 'ipua': 2}.get(t.get('dim'), 1)
        t['req'] = int(t.get('rate') or 0)
        t['cnt_time'] = 0
        t['cnt_num'] = 0
        t['action'] = 'drop' if t.get('action') == 'block' else 'status_{}'.format(
            t.get('status') if t.get('status') in (403, 404, 502, 503) else 503)
        t['ret'] = 'html'
        return t

    def _traffic_compiled(self, t):
        '''What the engine needs from a rule.'''
        if t.get('types') == 'all':
            url = '^/'
        elif t.get('regex'):
            url = t.get('path', '')
        else:
            # a path entered in the form matches that URL and everything below it
            url = '^' + re.escape(t.get('path', ''))
        act = t.get('action', 'status_503')
        return {'sites': t.get('sites') or [], 'url': url,
                'dim': self.TRAFFIC_CONDS.get(t.get('cond'), 'ip'),
                'rate': int(t.get('req') or 0),
                'win': int(t.get('cnt_time') or 0), 'winmax': int(t.get('cnt_num') or 0),
                'action': 'block' if act == 'drop' else 'content' if act == 'content' else 'status',
                'status': int(act.split('_')[1]) if act.startswith('status_') else 503,
                'ret': t.get('ret') if t.get('ret') in self.TRAFFIC_RETURNS else 'html'}

    def _traffic_save(self, rules):
        public.writeFile(self.TRAFFIC_JSON, json.dumps(rules))
        self._compile()

    def traffic_rules(self, get):
        return {'status': True, 'rules': self._traffic(),
                'sites': self._panel_sites(),
                'engine': self.region_engine_state()}

    def _int(self, get, key):
        try:
            return int(getattr(get, key, 0) or 0)
        except Exception:
            return 0

    def _traffic_validate(self, get):
        '''Same checks as the stock form.'''
        name = (self._arg(get, 'name') or '').strip()
        if not name:
            return None, 'Please enter the rule name'
        try:
            sites = json.loads(getattr(get, 'sites', '') or '[]')
        except Exception:
            sites = []
        known = set(self._panel_sites())
        sites = ['*'] if '*' in sites else sorted({x for x in sites if x in known})
        if not sites:
            return None, 'Please select a website'
        types = getattr(get, 'types', 'url')
        path = (getattr(get, 'url', '') or '').strip()
        if types == 'all':
            path = '/'
        else:
            types = 'url'
            if not path:
                return None, 'Please enter URL'
            if path == '/':
                return None, 'URL cannot be /'
            if not path.startswith('/'):
                return None, 'URL must start with /'
        cond = self._int(get, 'condition')
        if cond not in self.TRAFFIC_CONDS:
            return None, 'Bad access restriction'
        req = self._int(get, 'req')
        cnt_time = self._int(get, 'cnt_time')
        cnt_num = self._int(get, 'cnt_num')
        if not req and not cnt_time:
            return None, 'Please select at least one restriction condition'
        if getattr(get, 'req', '') not in ('', None) and req < 1 and not cnt_time:
            return None, 'Access limit per second cannot be less than 1'
        if cnt_time or cnt_num:
            if cnt_time < 30:
                return None, 'Time access limit cannot be less than 30 seconds'
            if cnt_num < 20:
                return None, 'Time access limit count cannot be less than 20 times'
        action = self._arg(get, 'action', 'status_503')
        if action not in self.TRAFFIC_ACTIONS:
            return None, 'Bad action'
        ret = getattr(get, 'ret', 'html')
        if ret not in self.TRAFFIC_RETURNS:
            ret = 'html'
        return {'name': name, 'sites': sites, 'site': sites[0], 'types': types, 'path': path,
                'cond': cond, 'req': max(req, 0), 'cnt_time': cnt_time, 'cnt_num': cnt_num,
                'action': action, 'ret': ret}, None

    def traffic_add(self, get):
        rule, err = self._traffic_validate(get)
        if err:
            return public.returnMsg(False, err)
        rule['id'] = 't{}'.format(int(time.time() * 1000))
        rule['open'] = True
        rules = self._traffic()
        rules.append(rule)
        self._traffic_save(rules)
        public.WriteLog('WAF Pro', 'Traffic rule added: {} on {}'.format(
            rule['name'], ','.join(rule['sites'])))
        return public.returnMsg(True, 'Traffic restriction added')

    def traffic_edit(self, get):
        rid = getattr(get, 'id', '')
        rule, err = self._traffic_validate(get)
        if err:
            return public.returnMsg(False, err)
        rules = self._traffic()
        found = False
        for i, r in enumerate(rules):
            if r['id'] == rid:
                rule['id'] = rid
                rule['open'] = r.get('open', True)
                rules[i] = rule
                found = True
        if not found:
            return public.returnMsg(False, 'Rule not found')
        self._traffic_save(rules)
        return public.returnMsg(True, 'Traffic restriction updated')

    def traffic_del(self, get):
        rid = getattr(get, 'id', '')
        self._traffic_save([r for r in self._traffic() if r['id'] != rid])
        return public.returnMsg(True, 'Traffic restriction removed')

    def traffic_toggle(self, get):
        rid = getattr(get, 'id', '')
        on = str(getattr(get, 'open', '1')) in ('1', 'true', 'True')
        rules = self._traffic()
        for r in rules:
            if r['id'] == rid:
                r['open'] = on
        self._traffic_save(rules)
        return public.returnMsg(True, 'Rule {}'.format('enabled' if on else 'disabled'))

    # ----------------------------------------------------------------
    # Custom rules — user-defined multi-condition matching.
    # Each rule: {id, name, site, action, status, open, conds:[...]}
    # A condition: {field, op, extra, value}. Fields ip/country match against
    # compiled IP ranges; the rest are text fields with string operators.
    # ----------------------------------------------------------------
    CUSTOM_JSON = PLUGIN_PATH + 'custom_rules.json'
    CUSTOM_FIELDS = ('ip', 'country', 'method', 'uri', 'uri_args', 'uri_param',
                     'args', 'user_agent', 'referer', 'cookie', 'header')
    CUSTOM_TEXT_OPS = ('eq', 'ne', 'contains', 'ncontains', 'prefix', 'suffix',
                       'regex', 'in', 'exists', 'nexists')
    CUSTOM_ACTIONS = ('block', 'code', 'allow', 'verify')
    CUSTOM_STATUS = (403, 444, 404, 502, 503)

    def _custom(self):
        r = self._read_json(self.CUSTOM_JSON, [])
        return r if isinstance(r, list) else []

    def _custom_save(self, rules):
        public.writeFile(self.CUSTOM_JSON, json.dumps(rules))
        self._compile()

    def _enc_pipe(self, v):
        # '|' is our field separator and '%' is the escape char — order matters
        return str(v).replace('%', '%25').replace('|', '%7C')

    def _split_csv(self, v):
        return [x.strip() for x in str(v).split(',') if x.strip()]

    def _ip_value_ranges(self, v):
        '''An ip condition value: CIDR, a-b range, or a single address (v4 or
        v6) — possibly several, comma separated. Returns (v4, v6) merged.'''
        v4, v6 = [], []
        for part in self._split_csv(v):
            try:
                fam, s, e = self._any_range(part)
            except Exception:
                continue
            (v4 if fam == 4 else v6).append([s, e])
        return self._merge(v4), self._merge(v6)

    def _custom_validate(self, get):
        name = (self._arg(get, 'name') or '').strip()
        if not name:
            return None, 'Rule name is required'
        try:
            sites = json.loads(getattr(get, 'sites', '') or '[]')
        except Exception:
            sites = []
        if not isinstance(sites, list):
            sites = []
        one = (getattr(get, 'site', '') or '').strip()
        if one:
            sites.append(one)
        known = set(self._panel_sites())
        sites = ['*'] if '*' in sites else sorted({x for x in sites if x in known})
        if not sites:
            return None, 'Please select a website'
        site = sites[0]
        action = self._arg(get, 'action', 'block')
        if action not in self.CUSTOM_ACTIONS:
            return None, 'Bad action'
        try:
            status = int(getattr(get, 'status_code', 403))
        except Exception:
            status = 403
        if status not in self.CUSTOM_STATUS:
            status = 403
        try:
            conds = json.loads(getattr(get, 'conds', '[]'))
        except Exception:
            return None, 'Invalid conditions payload'
        if not isinstance(conds, list) or not conds:
            return None, 'Add at least one condition'
        clean = []
        for c in conds:
            if not isinstance(c, dict):
                continue
            field = c.get('field')
            op = c.get('op')
            if field not in self.CUSTOM_FIELDS:
                return None, 'Unknown field: {}'.format(field)
            value = str(c.get('value', ''))
            extra = str(c.get('extra', ''))
            if field in ('ip', 'country'):
                op = c.get('op', 'match')
                if op not in ('match', 'notmatch'):
                    op = 'match'
                if not self._split_csv(value):
                    return None, '{} condition needs a value'.format(field)
            else:
                if op not in self.CUSTOM_TEXT_OPS:
                    return None, 'Bad operator: {}'.format(op)
                if field in ('uri_param', 'header') and not extra:
                    return None, 'This field needs a parameter/header name'
                if op == 'regex':
                    try:
                        re.compile(value)
                    except Exception as e:
                        return None, 'Invalid regex: {}'.format(e)
                elif op not in ('exists', 'nexists') and value == '':
                    return None, 'Condition value is required'
            try:
                g = max(int(c.get('g', 0)), 0)
            except Exception:
                g = 0
            clean.append({'field': field, 'op': op, 'extra': extra, 'value': value, 'g': g})
        # the engine reads a group's conditions as one contiguous run
        clean.sort(key=lambda x: x['g'])
        return {'name': name, 'site': site, 'sites': sites, 'action': action,
                'status': status, 'conds': clean}, None

    def custom_rules(self, get):
        hits = self._custom_hits()
        rows = []
        for r in self._custom():
            rows.append(dict(r, hits=hits.get('custom:' + r['id'], 0)))
        return {'status': True, 'rules': rows, 'sites': self._panel_sites(),
                'fields': self.CUSTOM_FIELDS, 'engine': self.region_engine_state()}

    def _custom_hits(self):
        '''Count custom-rule intercepts from today's block log.'''
        out = {}
        for _s, path in self._log_files('', ''):
            try:
                f = open(path, 'r')
            except Exception:
                continue
            for line in f:
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                rule = d.get('rule', '')
                if rule.startswith('custom:'):
                    out[rule] = out.get(rule, 0) + 1
            f.close()
        return out

    def custom_add(self, get):
        rule, err = self._custom_validate(get)
        if err:
            return public.returnMsg(False, err)
        rule['id'] = 'c{}'.format(int(time.time() * 1000))
        rule['open'] = True
        rules = self._custom()
        rules.append(rule)
        self._custom_save(rules)
        public.WriteLog('WAF Pro', 'Custom rule added: {} on {}'.format(rule['name'], rule['site']))
        return public.returnMsg(True, 'Custom rule added')

    def custom_edit(self, get):
        rid = getattr(get, 'id', '')
        rule, err = self._custom_validate(get)
        if err:
            return public.returnMsg(False, err)
        rules = self._custom()
        found = False
        for i, r in enumerate(rules):
            if r['id'] == rid:
                rule['id'] = rid
                rule['open'] = r.get('open', True)
                rules[i] = rule
                found = True
        if not found:
            return public.returnMsg(False, 'Rule not found')
        self._custom_save(rules)
        return public.returnMsg(True, 'Custom rule updated')

    def custom_copy(self, get):
        rid = getattr(get, 'id', '')
        rules = self._custom()
        src = next((r for r in rules if r['id'] == rid), None)
        if not src:
            return public.returnMsg(False, 'Rule not found')
        import copy
        dup = copy.deepcopy(src)
        dup['id'] = 'c{}'.format(int(time.time() * 1000))
        dup['name'] = (src.get('name', 'rule') + '_copy')[:60]
        rules.append(dup)
        self._custom_save(rules)
        return public.returnMsg(True, 'Rule copied')

    def custom_del(self, get):
        rid = getattr(get, 'id', '')
        self._custom_save([r for r in self._custom() if r['id'] != rid])
        return public.returnMsg(True, 'Custom rule removed')

    def custom_toggle(self, get):
        rid = getattr(get, 'id', '')
        on = str(getattr(get, 'open', '1')) in ('1', 'true', 'True')
        rules = self._custom()
        for r in rules:
            if r['id'] == rid:
                r['open'] = on
        self._custom_save(rules)
        return public.returnMsg(True, 'Rule {}'.format('enabled' if on else 'disabled'))

    def geo_batch(self, get):
        '''Resolve a batch of IPs to country/city via the panel's GeoIP DB.'''
        try:
            ips = json.loads(getattr(get, 'ips', '[]'))
        except Exception:
            return {'status': False, 'msg': 'Invalid ips payload'}
        try:
            d = self._dash()
        except Exception as e:
            return {'status': False, 'msg': str(e)}
        out = {}
        for ip in ips[:500]:
            out[ip] = d.geo_lookup(ip)
        return {'status': True, 'data': out}

    # ----------------------------------------------------------------
    # per-site settings (WebSite tab) — our own model
    # ----------------------------------------------------------------
    def get_sites(self, get):
        sites = self._sites()
        hits = self._site_hits()
        types = self._panel_site_types()
        domains = {}
        for h, site in self._site_domains().items():
            domains.setdefault(site, []).append(h)
        rules = self._site_rules()
        out = []
        for name, c in sorted(sites.items()):
            if not isinstance(c, dict):
                continue
            hit = hits.get(name, {})
            row = {'name': name, 'intercepts': hit.get('total', 0),
                   'cc_hits': hit.get('cc', 0), 'smart_hits': hit.get('smart', 0),
                   'project_type': types.get(name, ''),
                   'in_panel': name in types,
                   'domains': sorted(domains.get(name, [])),
                   'rule_counts': {k: len(rules.get(name, {}).get(k, []))
                                   for k in self.SITE_RULE_KINDS}}
            for k in self.SITE_BOOL_FIELDS:
                row[k] = bool(c.get(k, self.DEFAULT_SITE[k]))
            for k in self.SITE_INT_FIELDS:
                try:
                    row[k] = int(c.get(k, self.DEFAULT_SITE[k]))
                except Exception:
                    row[k] = self.DEFAULT_SITE[k]
            for k in self.SITE_TEXT_FIELDS:
                row[k] = c.get(k, '')
            for k in self.SITE_CHOICE_FIELDS:
                row[k] = c.get(k, self.DEFAULT_SITE[k])
            out.append(row)
        return {'status': True, 'data': out, 'mal_open': bool(self._config().get('mal_open'))}

    def _site_hits(self):
        '''Blocks per site for today, straight from our own log:
        {site: {'total': n, 'cc': n, 'smart': n}} — the WebSite table shows
        the total plus the CC / Smart CC counts next to those switches.'''
        out = {}
        path = WAF_LOG_DIR + time.strftime('%Y-%m-%d') + '.log'
        if not os.path.exists(path):
            return out
        try:
            with open(path, 'r') as f:
                for line in f:
                    try:
                        s = json.loads(line)
                    except Exception:
                        continue
                    n = s.get('site')
                    if not n:
                        continue
                    c = out.setdefault(n, {'total': 0, 'cc': 0, 'smart': 0})
                    c['total'] += 1
                    rule = s.get('rule', '')
                    if rule in ('cc', 'cc-blocked'):
                        c['cc'] += 1
                    elif rule == 'smart-cc':
                        c['smart'] += 1
        except Exception:
            pass
        return out

    def set_site_field(self, get):
        name = getattr(get, 'siteName', '')
        field = getattr(get, 'field', '')
        data = self._sites()
        if name not in data:
            return public.returnMsg(False, 'Site not found')
        if field in self.SITE_BOOL_FIELDS:
            data[name][field] = str(getattr(get, 'value', '1')) in ('1', 'true', 'True')
        elif field in self.SITE_INT_FIELDS:
            try:
                data[name][field] = int(getattr(get, 'value', 0))
            except Exception:
                return public.returnMsg(False, 'Value must be a number')
        elif field in self.SITE_TEXT_FIELDS:
            data[name][field] = re.sub(r'[|\t\r\n]', '', str(getattr(get, 'value', '')))
        elif field in self.SITE_CHOICE_FIELDS:
            v = str(getattr(get, 'value', ''))
            if v not in self.SITE_CHOICE_FIELDS[field]:
                return public.returnMsg(False, 'Invalid value')
            data[name][field] = v
        else:
            return public.returnMsg(False, 'Field not allowed: {}'.format(field))
        self._write_json(self.SITES, data)
        self._compile()
        public.WriteLog('WAF Pro', 'site {} -> {}={}'.format(name, field, data[name][field]))
        return public.returnMsg(True, 'Updated')

    def set_site_switch(self, get):
        get.field = 'open'
        get.value = getattr(get, 'open', '1')
        return self.set_site_field(get)

    def get_site_detail(self, get):
        name = getattr(get, 'siteName', '')
        data = self._sites()
        if name not in data:
            return {'status': False, 'msg': 'Site not found'}
        c = dict(data[name])
        c['status'] = True
        c['name'] = name
        return c

    def save_site_detail(self, get):
        name = getattr(get, 'siteName', '')
        try:
            patch = json.loads(getattr(get, 'config', '{}'))
        except Exception:
            return public.returnMsg(False, 'Invalid config payload')
        data = self._sites()
        if name not in data:
            return public.returnMsg(False, 'Site not found')
        for k in self.SITE_BOOL_FIELDS:
            if k in patch:
                data[name][k] = bool(patch[k])
        for k in self.SITE_INT_FIELDS:
            if k in patch:
                try:
                    data[name][k] = int(patch[k])
                except Exception:
                    pass
        for k in self.SITE_TEXT_FIELDS:
            if k in patch:
                # tab separates sites.txt fields; never let one through
                data[name][k] = re.sub(r'[|\t\r\n]', '', str(patch[k]))
        for k, choices in self.SITE_CHOICE_FIELDS.items():
            if k in patch and patch[k] in choices:
                data[name][k] = patch[k]
        self._write_json(self.SITES, data)
        self._compile()
        public.WriteLog('WAF Pro', 'site {} settings saved'.format(name))
        return public.returnMsg(True, 'Site settings saved')

    # ----------------------------------------------------------------
    # Per-site rule lists — Website tab > site settings.
    #   dpath  forbidden URL        {rule}
    #   leech  anti-hotlink         {exts, domains, allow_empty}
    #   purl   protected URL        {path, param, value}
    #   api    API defense          {path, methods, per_min}
    #   repl   content replace      {from, to}
    # Stored as {site: {kind: [entry, ...]}}; compiled to rule/site_rules.txt.
    # ----------------------------------------------------------------
    SITE_RULES_JSON = PLUGIN_PATH + 'site_rules.json'
    # ucc: URL CC defense, uverify: URL enhancement mode (browser check),
    # vwhite: machine verification whitelist, umethod: URL request type
    SITE_RULE_KINDS = ('dpath', 'leech', 'purl', 'api', 'repl', 'ucc', 'uverify', 'vwhite', 'umethod')
    API_METHODS = ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS')

    def _site_rules(self):
        d = self._read_json(self.SITE_RULES_JSON, {})
        return d if isinstance(d, dict) else {}

    def _site_rule_clean(self, kind, raw):
        '''Validate one entry from the UI -> (entry, error).'''
        def regex(v, label):
            v = str(v or '').strip()
            if not v:
                return None, '{} is required'.format(label)
            try:
                re.compile(v)
            except re.error as ex:
                return None, 'Invalid regular expression: {}'.format(ex)
            return v, None

        if kind == 'dpath':
            v, err = regex(raw.get('rule'), 'URL pattern')
            return ({'rule': v}, None) if not err else (None, err)
        if kind == 'leech':
            exts = ','.join(x.strip().lstrip('.').lower() for x in str(raw.get('exts', '')).split(',')
                            if x.strip())
            if not exts or not re.match(r'^[a-z0-9,]+$', exts):
                return None, 'Extensions: comma separated, e.g. jpg,png,mp4'
            domains = ','.join(x.strip().lower() for x in str(raw.get('domains', '')).split(',')
                               if x.strip())
            if domains and not re.match(r'^[a-z0-9.*,-]+$', domains):
                return None, 'Allowed domains: comma separated host names'
            return {'exts': exts, 'domains': domains,
                    'allow_empty': bool(raw.get('allow_empty', True))}, None
        if kind == 'purl':
            v, err = regex(raw.get('path'), 'URL pattern')
            if err:
                return None, err
            param = str(raw.get('param', '')).strip()
            value = str(raw.get('value', '')).strip()
            if not re.match(r'^[A-Za-z0-9_.-]{1,64}$', param):
                return None, 'Parameter name: letters, digits, _ . -'
            if len(value) < 6:
                return None, 'Use a parameter value of at least 6 characters'
            return {'path': v, 'param': param, 'value': value}, None
        if kind == 'api':
            v, err = regex(raw.get('path'), 'API path pattern')
            if err:
                return None, err
            methods = [m.strip().upper() for m in str(raw.get('methods', '')).split(',') if m.strip()]
            if any(m not in self.API_METHODS for m in methods):
                return None, 'Methods: any of ' + ', '.join(self.API_METHODS)
            try:
                per_min = max(int(raw.get('per_min', 0)), 0)
            except Exception:
                per_min = 0
            if not methods and not per_min:
                return None, 'Set allowed methods, a rate limit, or both'
            return {'path': v, 'methods': ','.join(methods), 'per_min': per_min}, None
        if kind == 'ucc':
            v, err = regex(raw.get('path'), 'URL')
            if err:
                return None, err
            try:
                limit, cycle = int(raw.get('limit', 0)), int(raw.get('cycle', 0))
            except Exception:
                return None, 'Frequency and cycle must be numbers'
            if cycle < 1 or limit < 1:
                return None, 'Frequency and cycle must be at least 1'
            return {'path': v, 'limit': limit, 'cycle': cycle}, None
        if kind in ('uverify', 'vwhite'):
            v, err = regex(raw.get('path'), 'URL')
            return ({'path': v}, None) if not err else (None, err)
        if kind == 'umethod':
            v, err = regex(raw.get('path'), 'URL')
            if err:
                return None, err
            methods = [m.strip().upper() for m in str(raw.get('methods', '')).split(',') if m.strip()]
            if not methods or any(m not in self.API_METHODS for m in methods):
                return None, 'Choose at least one request type'
            mode = raw.get('mode') if raw.get('mode') in ('allow', 'refuse') else 'refuse'
            return {'path': v, 'mode': mode, 'methods': ','.join(methods)}, None
        if kind == 'repl':
            frm = str(raw.get('from', ''))
            if not frm.strip():
                return None, 'Text to find is required'
            if len(frm) > 500 or len(str(raw.get('to', ''))) > 2000:
                return None, 'Text is too long'
            return {'from': frm, 'to': str(raw.get('to', ''))}, None
        return None, 'Unknown rule type'

    def _site_ok(self, site):
        '''A real site, or "*" for the global lists.'''
        return site == '*' or site in self._sites()

    def site_rules_get(self, get):
        site = getattr(get, 'siteName', '')
        if not self._site_ok(site):
            return {'status': False, 'msg': 'Site not found'}
        cur = self._site_rules().get(site, {})
        return {'status': True, 'site': site,
                'data': {k: cur.get(k, []) for k in self.SITE_RULE_KINDS},
                'domains': sorted(h for h, s in self._site_domains().items() if s == site)}

    def site_rule_add(self, get):
        site = getattr(get, 'siteName', '')
        kind = getattr(get, 'kind', '')
        if not self._site_ok(site):
            return public.returnMsg(False, 'Site not found')
        if kind not in self.SITE_RULE_KINDS:
            return public.returnMsg(False, 'Unknown rule type')
        try:
            raw = json.loads(getattr(get, 'data', '{}'))
        except Exception:
            return public.returnMsg(False, 'Invalid payload')
        entry, err = self._site_rule_clean(kind, raw if isinstance(raw, dict) else {})
        if err:
            return public.returnMsg(False, err)
        data = self._site_rules()
        lst = data.setdefault(site, {}).setdefault(kind, [])
        if entry in lst:
            return public.returnMsg(False, 'Already exists')
        lst.append(entry)
        self._write_json(self.SITE_RULES_JSON, data)
        self._compile()
        public.WriteLog('WAF Pro', 'site {} {} rule added'.format(site, kind))
        return public.returnMsg(True, 'Added')

    def site_rule_del(self, get):
        site = getattr(get, 'siteName', '')
        kind = getattr(get, 'kind', '')
        try:
            idx = int(getattr(get, 'index', -1))
        except Exception:
            idx = -1
        data = self._site_rules()
        lst = data.get(site, {}).get(kind, [])
        if idx < 0 or idx >= len(lst):
            return public.returnMsg(False, 'Rule not found')
        lst.pop(idx)
        self._write_json(self.SITE_RULES_JSON, data)
        self._compile()
        return public.returnMsg(True, 'Removed')

    def _site_rules_compiled(self):
        enc = lambda v: str(v).replace('%', '%25').replace('|', '%7C').replace('\t', '%09') \
            .replace('\r', '').replace('\n', ' ')
        sites = self._sites()
        out = []
        for site, kinds in sorted(self._site_rules().items()):
            if (site != '*' and site not in sites) or not isinstance(kinds, dict):
                continue
            for x in kinds.get('dpath', []):
                out.append('|'.join(['dpath', site, enc(x['rule'])]))
            for x in kinds.get('leech', []):
                out.append('|'.join(['leech', site, enc(x['exts']), enc(x['domains']),
                                     '1' if x.get('allow_empty') else '0']))
            for x in kinds.get('purl', []):
                out.append('|'.join(['purl', site, enc(x['path']), enc(x['param']), enc(x['value'])]))
            for x in kinds.get('api', []):
                out.append('|'.join(['api', site, enc(x['path']), enc(x['methods']), str(int(x['per_min']))]))
            for x in kinds.get('repl', []):
                out.append('|'.join(['repl', site, enc(x['from']), enc(x['to'])]))
            for x in kinds.get('ucc', []):
                out.append('|'.join(['ucc', site, enc(x['path']), str(int(x['limit'])), str(int(x['cycle']))]))
            for k in ('uverify', 'vwhite'):
                for x in kinds.get(k, []):
                    out.append('|'.join([k, site, enc(x['path'])]))
            for x in kinds.get('umethod', []):
                out.append('|'.join(['umethod', site, enc(x['path']), x['mode'], enc(x['methods'])]))
        return '\n'.join(out)

    # ----------------------------------------------------------------
    # Self-test — the "Simulated attack" of the stock WAF, but run for real:
    # the panel sends attack-shaped requests to each site through nginx and
    # reads back whether the engine stopped them and with which rule.
    #
    # Requests come from this server, which the engine normally exempts, so
    # they carry a secret X-WafPro-Test header (rule/test_token.txt) that
    # makes the engine judge them like a stranger — without banning us.
    # ----------------------------------------------------------------
    # PHP releases carrying the PHP2Shell fix (CVE-2026-109618/109619)
    PHP2SHELL_FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}

    def _selftest_cases(self, sc):
        mp_progress = ('--wpX\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
                       'x\r\n--wpX--\r\n')
        mp_shell = ('--wpX\r\nContent-Disposition: form-data; name="f"; filename="shell.php"\r\n'
                    'Content-Type: application/octet-stream\r\n\r\n<?php echo 1; ?>\r\n--wpX--\r\n')
        mp_ct = 'multipart/form-data; boundary=wpX'
        return [
            # id, label, switch that must be on, path+query, ua, body, content-type
            ('baseline', 'Normal page request (must pass)', None, '/', None, None, None),
            ('sqli', 'SQL injection in the query string', 'get', '/?id=1%20union%20select%201,2,3', None, None, None),
            ('xss', 'XSS in the query string', 'get', '/?q=%3Cscript%3Ealert(1)%3C/script%3E', None, None, None),
            ('lfi', 'Path traversal / local file read', 'get', '/?f=../../../../etc/passwd', None, None, None),
            ('log4shell', 'Log4Shell', 'get', '/?x=%24%7Bjndi:ldap://x/a%7D', None, None, None),
            ('scan', 'Exposed .env probe', 'scan', '/.env', None, None, None),
            ('scanner_ua', 'Scanner user-agent (sqlmap)', 'ua', '/', 'sqlmap/1.8', None, None),
            ('post_sqli', 'SQL injection in a POST body', 'post', '/',
             None, 'a=1 union select 1,2', 'application/x-www-form-urlencoded'),
            ('php2shell', 'PHP2Shell: session upload-progress field', 'php_guard', '/',
             None, mp_progress, mp_ct),
            ('webshell', 'Webshell upload (shell.php)', 'upload_ext', '/',
             None, mp_shell, mp_ct),
        ]

    def _vhost_https(self, site):
        for fn in os.listdir(NGINX_CONF_D):
            base = fn[:-5]
            if not fn.endswith('.conf'):
                continue
            if base == site or any(base == p + site for p in self.VHOST_PREFIXES):
                body = public.readFile(NGINX_CONF_D + fn) or ''
                return bool(re.search(r'listen\s+(\[::\]:)?443', body))
        return False

    def _curl(self, scheme, host, path, ua, body, ctype, token):
        import subprocess
        port = '443' if scheme == 'https' else '80'
        cmd = ['curl', '-sk', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '10',
               '--resolve', '{}:{}:127.0.0.1'.format(host, port),
               '-H', 'X-WafPro-Test: ' + token,
               '-A', ua or 'Mozilla/5.0 (WAF Pro self-test)',
               '{}://{}{}'.format(scheme, host, path)]
        if body is not None:
            cmd[1:1] = ['--data-binary', body, '-H', 'Content-Type: ' + ctype]
        try:
            r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            code = (r.stdout or b'').decode().strip() or '000'
            # 444 closes the connection: curl reports 000 / exit 52
            return int(code) if code.isdigit() else 0, r.returncode
        except Exception:
            return 0, -1

    def self_test(self, get):
        '''args: siteName (optional; default every site the engine guards)'''
        import uuid
        e = self._engine_state()
        if not e['wired']:
            return public.returnMsg(False, 'The engine is not wired into nginx; enable it on the Global tab first.')
        cfg = self._config()
        if not cfg.get('open'):
            return public.returnMsg(False, 'The protection switch is off.')
        token = self._secret('test.key')
        sites = self._sites()
        want = getattr(get, 'siteName', '')
        domains = {}
        for h, s in self._site_domains().items():
            if '*' not in h:
                domains.setdefault(s, []).append(h)
        results = []
        for site, sc in sorted(sites.items()):
            if want and site != want:
                continue
            hosts = sorted(domains.get(site, []), key=lambda h: (h != site, len(h)))
            if not hosts:
                continue
            host = hosts[0]
            scheme = 'https' if self._vhost_https(site) else 'http'
            rows = []
            for cid, label, switch, path, ua, body, ctype in self._selftest_cases(sc):
                marker = uuid.uuid4().hex[:12]
                p = path + ('&' if '?' in path else '?') + 'wafpro_test=' + marker
                code, rc = self._curl(scheme, host, p, ua, body, ctype, token)
                rows.append({'id': cid, 'label': label, 'marker': marker, 'status': code,
                             'expect': (switch is None) or (bool(sc.get(switch)) if switch != 'upload_ext'
                                                             else bool(str(sc.get('upload_ext', '')).strip())),
                             'baseline': switch is None})
            # the engine writes its block log synchronously; match by marker
            hits = self._log_markers([r['marker'] for r in rows])
            ok = True
            for r in rows:
                rule = hits.get(r['marker'])
                r['blocked'] = rule is not None
                r['rule'] = rule or ''
                r['rule_name'] = self.FILTER_NAMES.get((rule or '').split(':')[0], rule or '')
                if r['baseline']:
                    r['pass'] = not r['blocked']
                elif r['expect']:
                    r['pass'] = r['blocked']
                else:
                    r['pass'] = None          # that protection is switched off
                if r['pass'] is False:
                    ok = False
                del r['marker']
            results.append({'site': site, 'host': host, 'scheme': scheme, 'ok': ok, 'tests': rows})
        return {'status': True, 'sites': results, 'php': self._php_versions(),
                'health': self._engine_health()}

    def _log_markers(self, markers):
        out = {}
        path = WAF_LOG_DIR + time.strftime('%Y-%m-%d') + '.log'
        try:
            with open(path, 'rb') as fh:
                size = os.path.getsize(path)
                fh.seek(max(size - 2 * 1048576, 0))
                tail = fh.read().decode('utf-8', 'ignore')
        except Exception:
            return out
        for line in tail.split('\n'):
            for m in markers:
                if m in line:
                    try:
                        out[m] = json.loads(line).get('rule', '?')
                    except Exception:
                        out[m] = '?'
        return out

    def _php_versions(self):
        '''Installed PHP builds and whether they carry the PHP2Shell fix.'''
        out = []
        base = '/www/server/php/'
        if not os.path.isdir(base):
            return out
        for d in sorted(os.listdir(base)):
            b = base + d + '/bin/php'
            if not os.path.exists(b):
                continue
            v, _ = public.ExecShell(b + ' -r "echo PHP_VERSION;" 2>/dev/null')
            v = (v or '').strip()
            m = re.match(r'^(\d+)\.(\d+)\.(\d+)', v)
            if not m:
                continue
            major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
            fixed = self.PHP2SHELL_FIXED.get((major, minor))
            if fixed is None:
                # 8.1 and older never get the fix; 8.6+ is newer than it
                safe = (major, minor) > (8, 5)
            else:
                safe = patch >= fixed
            out.append({'dir': d, 'version': v, 'php2shell_safe': safe,
                        'fixed_in': '{}.{}.{}'.format(major, minor, fixed) if fixed else ''})
        return out

    # ----------------------------------------------------------------
    # Webshell scan — wafpro_webshell.py does the work in the background.
    # ----------------------------------------------------------------
    WS_DIR = PLUGIN_PATH + 'webshell/'
    QUAR_DIR = PLUGIN_PATH + 'webshell/quarantine/'
    PANEL_PY = '/www/server/panel/pyenv/bin/python3'

    def _ws_status(self):
        st = self._read_json(self.WS_DIR + 'status.json', {}) or {}
        # a crashed/killed scan leaves running=true behind
        pid = st.get('pid')
        if st.get('running') and pid and not os.path.exists('/proc/{}'.format(pid)):
            st['running'] = False
            st['error'] = st.get('error') or 'scan process exited unexpectedly'
        return st

    def webshell_scan(self, get):
        '''args: siteName (optional; default every PHP site)'''
        st = self._ws_status()
        if st.get('running'):
            return public.returnMsg(False, 'A scan is already running')
        want = getattr(get, 'siteName', '')
        targets = []
        try:
            for r in public.M('sites').field('name,path,project_type').select():
                if want and r['name'] != want:
                    continue
                if not want and (r.get('project_type') or '') not in self.PHP_PROJECT_TYPES:
                    continue
                if r.get('path') and os.path.isdir(r['path']):
                    targets.append({'site': r['name'], 'path': r['path']})
        except Exception:
            pass
        if not targets:
            return public.returnMsg(False, 'No site directory to scan')
        if not os.path.exists(self.WS_DIR):
            os.makedirs(self.WS_DIR, 0o700)
        self._write_json(self.WS_DIR + 'targets.json', targets)
        py = self.PANEL_PY if os.path.exists(self.PANEL_PY) else 'python3'
        public.ExecShell('nohup {} {}wafpro_webshell.py scan >/dev/null 2>&1 &'.format(py, PLUGIN_PATH))
        public.WriteLog('WAF Pro', 'Webshell scan started ({} site(s))'.format(len(targets)))
        return public.returnMsg(True, 'Scan started for {} site(s)'.format(len(targets)))

    def webshell_status(self, get):
        return {'status': True, 'scan': self._ws_status()}

    def webshell_results(self, get):
        res = self._read_json(self.WS_DIR + 'results.json', {}) or {}
        files = [f for f in res.get('files', []) if os.path.exists(f.get('file', ''))]
        return {'status': True, 'time': res.get('time', 0), 'scanned': res.get('scanned', 0),
                'files': files, 'quarantine': self._quarantine_list(),
                'scan': self._ws_status()}

    def _ws_known(self, path):
        '''Only files the scanner reported may be read/moved through the UI.'''
        res = self._read_json(self.WS_DIR + 'results.json', {}) or {}
        return any(f.get('file') == path for f in res.get('files', []))

    def webshell_view(self, get):
        path = getattr(get, 'file', '')
        if not self._ws_known(path) or not os.path.isfile(path):
            return public.returnMsg(False, 'File not in the scan results')
        with open(path, 'rb') as fh:
            body = fh.read(20000).decode('utf-8', 'replace')
        return {'status': True, 'file': path, 'body': body,
                'truncated': os.path.getsize(path) > 20000}

    def _quarantine_list(self):
        idx = self._read_json(self.QUAR_DIR + 'index.json', []) or []
        return [q for q in idx if os.path.exists(self.QUAR_DIR + q.get('id', ''))]

    def webshell_quarantine(self, get):
        '''Move a reported file out of the web root (restorable).'''
        import shutil
        path = getattr(get, 'file', '')
        if not self._ws_known(path) or not os.path.isfile(path):
            return public.returnMsg(False, 'File not in the scan results')
        if not os.path.exists(self.QUAR_DIR):
            os.makedirs(self.QUAR_DIR, 0o700)
        qid = '{}_{}'.format(int(time.time() * 1000), re.sub(r'[^A-Za-z0-9._-]', '_', os.path.basename(path)))
        st = os.stat(path)
        shutil.move(path, self.QUAR_DIR + qid)
        os.chmod(self.QUAR_DIR + qid, 0o600)
        idx = self._read_json(self.QUAR_DIR + 'index.json', []) or []
        idx.append({'id': qid, 'file': path, 'time': int(time.time()),
                    'mode': st.st_mode & 0o7777, 'uid': st.st_uid, 'gid': st.st_gid})
        self._write_json(self.QUAR_DIR + 'index.json', idx)
        public.WriteLog('WAF Pro', 'Webshell quarantined: {}'.format(path))
        return public.returnMsg(True, 'Moved to quarantine')

    def webshell_restore(self, get):
        import shutil
        qid = os.path.basename(getattr(get, 'id', ''))
        idx = self._read_json(self.QUAR_DIR + 'index.json', []) or []
        rec = next((q for q in idx if q.get('id') == qid), None)
        if not rec or not os.path.exists(self.QUAR_DIR + qid):
            return public.returnMsg(False, 'Not in quarantine')
        if os.path.exists(rec['file']):
            return public.returnMsg(False, 'A file already exists at the original path')
        shutil.move(self.QUAR_DIR + qid, rec['file'])
        try:
            os.chmod(rec['file'], rec.get('mode', 0o644))
            os.chown(rec['file'], rec.get('uid', 0), rec.get('gid', 0))
        except Exception:
            pass
        self._write_json(self.QUAR_DIR + 'index.json', [q for q in idx if q.get('id') != qid])
        return public.returnMsg(True, 'Restored')

    def webshell_delete(self, get):
        qid = os.path.basename(getattr(get, 'id', ''))
        idx = self._read_json(self.QUAR_DIR + 'index.json', []) or []
        if not any(q.get('id') == qid for q in idx):
            return public.returnMsg(False, 'Not in quarantine')
        try:
            os.remove(self.QUAR_DIR + qid)
        except Exception:
            pass
        self._write_json(self.QUAR_DIR + 'index.json', [q for q in idx if q.get('id') != qid])
        return public.returnMsg(True, 'Deleted permanently')

    def webshell_ignore(self, get):
        '''Mark a reported file as a false positive (by content hash, so an
        edited file is scanned again).'''
        path = getattr(get, 'file', '')
        res = self._read_json(self.WS_DIR + 'results.json', {}) or {}
        rec = next((f for f in res.get('files', []) if f.get('file') == path), None)
        if not rec or not rec.get('hash'):
            return public.returnMsg(False, 'File not in the scan results')
        ign = self._read_json(self.WS_DIR + 'ignore.json', []) or []
        if rec['hash'] not in ign:
            ign.append(rec['hash'])
        self._write_json(self.WS_DIR + 'ignore.json', ign)
        res['files'] = [f for f in res.get('files', []) if f.get('file') != path]
        self._write_json(self.WS_DIR + 'results.json', res)
        return public.returnMsg(True, 'Marked as safe')

    def cc_apply_all(self, get):
        '''Push the Global CC initial rule onto every existing site.'''
        cfg = self._config()
        data = self._sites()
        for name, conf in data.items():
            if not isinstance(conf, dict):
                continue
            conf.update({'cc_limit': int(cfg['cc_def_limit']), 'cc_cycle': int(cfg['cc_def_cycle']),
                         'cc_block': int(cfg['cc_def_block']), 'cc_mode': cfg['cc_def_mode'],
                         'cc_key': cfg['cc_def_key']})
        self._write_json(self.SITES, data)
        self._compile()
        public.WriteLog('WAF Pro', 'CC initial rule applied to all sites')
        return public.returnMsg(True, 'CC rule applied to {} site(s)'.format(len(data)))


if __name__ == '__main__':
    # cron entry for automatic updates (see update_auto)
    if len(sys.argv) > 1 and sys.argv[1] == 'auto_update':
        m = wafpro_main()
        if m._update_state().get('auto'):
            class _Get:
                force = '1'
            print(m.update_install(_Get())['msg'])


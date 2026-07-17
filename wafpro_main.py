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
    }
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
    }
    SITE_BOOL_FIELDS = ('open', 'get', 'post', 'cookie', 'ua', 'scan', 'cc_open',
                        'cdn', 'fake_spider', 'smart_cc', 'crawl', 'wait')
    SITE_INT_FIELDS = ('cc_limit', 'cc_cycle', 'cc_block', 'crawl_limit', 'wait_limit')
    SITE_TEXT_FIELDS = ('deny_ext', 'upload_ext', 'php_path')

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
        for name in self._panel_sites():
            if name not in data:
                data[name] = dict(self.DEFAULT_SITE)
                changed = True
        # Backfill keys added by a later version, or sites saved before that
        # version keep compiling with the field empty (silently unprotected).
        for name, conf in data.items():
            if not isinstance(conf, dict):
                continue
            for k, v in self.DEFAULT_SITE.items():
                if k not in conf:
                    conf[k] = v
                    changed = True
        if changed:
            self._write_json(self.SITES, data)
        return data

    def _panel_sites(self):
        try:
            rows = public.M('sites').field('name').order('name asc').select()
            if isinstance(rows, list):
                return [r['name'] for r in rows if r.get('name')]
        except Exception:
            pass
        return []

    METHODS_FILE = PLUGIN_PATH + 'methods.json'
    HDR_FILE = PLUGIN_PATH + 'hdr_limits.json'
    DROP_LOG = WAF_LOG_DIR + 'drop_ip.log'
    UNBAN_FILE = RULE_DIR + 'unban.txt'

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

    def bans(self, get):
        '''Currently auto-banned IPs.

        The ban itself lives in the engine's shared dict, which we cannot read
        from here, so the engine mirrors every ban into drop_ip.log and we
        report the entries that have not expired yet.
        '''
        now = int(time.time())
        rows = {}
        try:
            body = public.readFile(self.DROP_LOG) or ''
        except Exception:
            body = ''
        unbanned = set(x.strip() for x in (public.readFile(self.UNBAN_FILE) or '').split('\n') if x.strip())
        for line in body.split('\n'):
            f = line.split('|')
            if len(f) < 3:
                continue
            try:
                until = int(f[1])
            except Exception:
                continue
            if until <= now or f[0] in unbanned:
                continue
            # later lines win: an IP can be re-banned
            rows[f[0]] = {'ip': f[0], 'until': until, 'left': until - now,
                          'hits': int(f[2]) if f[2].isdigit() else 0,
                          'site': f[3] if len(f) > 3 else '',
                          'rule': f[4] if len(f) > 4 else ''}
        # The engine only ever appends here, so compact once it gets big:
        # rewrite with just the live bans and drop the expired history.
        try:
            if len(body) > 200000:
                public.writeFile(self.DROP_LOG, '\n'.join(
                    '{}|{}|{}|{}|{}'.format(r['ip'], r['until'], r['hits'], r['site'], r['rule'])
                    for r in rows.values()))
        except Exception:
            pass
        out = sorted(rows.values(), key=lambda x: x['until'], reverse=True)
        cfg = self._config()
        return {'status': True, 'data': out,
                'retry': cfg.get('retry', 0), 'retry_cycle': cfg.get('retry_cycle', 60),
                'retry_time': cfg.get('retry_time', 600)}

    def unban(self, get):
        '''Lift an auto-ban. The engine drops the key on its next resync (~2s),
        so the version bump is what actually applies this.'''
        ip = (getattr(get, 'ip', '') or '').strip()
        try:
            self._ip2int(ip)          # raises on anything that is not IPv4
        except Exception:
            return public.returnMsg(False, 'Invalid IP')
        cur = [x.strip() for x in (public.readFile(self.UNBAN_FILE) or '').split('\n') if x.strip()]
        if ip not in cur:
            cur.append(ip)
        public.writeFile(self.UNBAN_FILE, '\n'.join(cur[-500:]))
        self._compile()
        public.WriteLog('WAF Pro', 'unbanned {}'.format(ip))
        return public.returnMsg(True, 'Unbanned {} — takes effect within a few seconds'.format(ip))

    def unban_all(self, get):
        rows = self.bans(get)['data']
        if not rows:
            return public.returnMsg(True, 'Nothing to unban')
        cur = [x.strip() for x in (public.readFile(self.UNBAN_FILE) or '').split('\n') if x.strip()]
        for r in rows:
            if r['ip'] not in cur:
                cur.append(r['ip'])
        public.writeFile(self.UNBAN_FILE, '\n'.join(cur[-500:]))
        self._compile()
        return public.returnMsg(True, 'Cleared {} ban(s)'.format(len(rows)))

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
    ]
    # UA fragments that claim to be one of the crawlers above
    SPIDER_UA = r'(googlebot|adsbot-google|mediapartners-google|storebot-google|' \
                r'google-inspectiontool|bingbot|adidxbot|bingpreview|msnbot)'

    def _spiders(self):
        return self._read_json(self.SPIDER_FILE, None)

    def spider_status(self, get):
        d = self._spiders()
        return {'status': True,
                'have': isinstance(d, dict) and bool(d.get('ranges')),
                'count': len(d.get('ranges', [])) if isinstance(d, dict) else 0,
                'updated': (d or {}).get('updated', ''),
                'sources': [n for n, _ in self.SPIDER_SOURCES]}

    def spider_update(self, get):
        '''Refresh the verified-crawler IP list from the official sources.'''
        import urllib.request
        got, failed = [], []
        for name, url in self.SPIDER_SOURCES:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'wafpro'})
                body = urllib.request.urlopen(req, timeout=20).read()
                data = json.loads(body)
                n = 0
                for pfx in data.get('prefixes', []):
                    v4 = pfx.get('ipv4Prefix')
                    if not v4:
                        continue          # ipv6 — our matcher is v4 only
                    try:
                        got.append(list(self._cidr_range(v4)))
                        n += 1
                    except Exception:
                        continue
                if not n:
                    failed.append(name)
            except Exception:
                failed.append(name)
        if not got:
            return public.returnMsg(False, 'Could not fetch any crawler list ({}). '
                                           'Check the server\'s outbound access.'.format(
                                               ', '.join(failed)))
        merged = self._merge(got)
        self._write_json(self.SPIDER_FILE, {
            'ranges': merged, 'updated': time.strftime('%Y-%m-%d %H:%M:%S'),
            'failed': failed})
        self._compile()
        msg = 'Verified crawler IPs updated: {} ranges'.format(len(merged))
        if failed:
            msg += ' ({} unreachable, kept the rest)'.format(', '.join(failed))
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
                'count': len(d.get('ranges', [])) if isinstance(d, dict) else 0,
                'updated': (d or {}).get('updated', ''),
                'open': bool(self._config().get('mal_open')),
                'sources': [n for n, _ in self.MAL_SOURCES]}

    def malicious_update(self, get):
        '''Refresh the known-malicious IP list from the public feeds.'''
        import urllib.request
        got, failed, seen = [], [], 0
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
                        if '/' in line:
                            got.append(list(self._cidr_range(line)))
                        else:
                            v = self._ip2int(line)
                            got.append([v, v])
                        n += 1
                    except Exception:
                        continue
                seen += n
                if not n:
                    failed.append(name)
            except Exception:
                failed.append(name)
        if not got:
            return public.returnMsg(False, 'Could not fetch any feed ({}). '
                                           'Check outbound access.'.format(', '.join(failed)))
        merged = self._merge(got)
        # Our own IPs must never end up in a feed-driven block list.
        self._write_json(self.MAL_FILE, {
            'ranges': merged, 'updated': time.strftime('%Y-%m-%d %H:%M:%S'),
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

    def get_waiting_html(self, get):
        return {'status': True, 'html': self._waiting_html()}

    def save_waiting_html(self, get):
        h = getattr(get, 'html', '') or ''
        if len(h) > 200000:
            return public.returnMsg(False, 'Page is too large')
        public.writeFile(self.WAIT_FILE, h or self.DEFAULT_WAIT_HTML)
        self._compile()
        return public.returnMsg(True, 'Waiting page saved')

    # .bin files _compile() writes itself; anything else matching *.bin is a
    # stale region rule and gets cleaned up.
    FIXED_BINS = ('lan.bin', 'ip_white.bin', 'ip_black.bin', 'spider.bin',
                  'malicious.bin')

    # ---------- compile: panel json -> engine files ----------

    def _compile(self):
        '''Render config/sites/rules into the engine's formats and bump the
        version. Workers pick it up within ~2s; no nginx reload involved.'''
        if not os.path.exists(RULE_DIR):
            os.makedirs(RULE_DIR, 0o700)
        if not os.path.exists(WAF_LOG_DIR):
            os.makedirs(WAF_LOG_DIR, 0o755)

        cfg = self._config()
        kv = []
        for k, v in sorted(cfg.items()):
            if isinstance(v, bool):
                v = 'true' if v else 'false'
            kv.append('{}={}'.format(k, v))
        kv.append('methods={}'.format(','.join(self._methods())))
        public.writeFile(RULE_DIR + 'config.txt', '\n'.join(kv))

        lines = []
        for name, s in sorted(self._sites().items()):
            lines.append('|'.join([
                name,
                '1' if s.get('open') else '0',
                '1' if s.get('get') else '0',
                '1' if s.get('post') else '0',
                '1' if s.get('cookie') else '0',
                '1' if s.get('ua') else '0',
                '1' if s.get('scan') else '0',
                '1' if s.get('cc_open') else '0',
                str(int(s.get('cc_limit', 120))),
                str(int(s.get('cc_cycle', 60))),
                str(int(s.get('cc_block', 600))),
                str(s.get('deny_ext', '')).replace('|', ''),
                str(s.get('upload_ext', '')).replace('|', ''),
                str(s.get('php_path', '')).replace('|', ''),
                '1' if s.get('cdn') else '0',
                '1' if s.get('fake_spider') else '0',
                '1' if s.get('smart_cc') else '0',
                '1' if s.get('crawl') else '0',
                str(int(s.get('crawl_limit', 30))),
                '1' if s.get('wait') else '0',
                str(int(s.get('wait_limit', 200))),
            ]))
        public.writeFile(RULE_DIR + 'sites.txt', '\n'.join(lines))

        self._pack([[self._ip2int(s), self._ip2int(e)] for s, e in self.PRIVATE_RANGES],
                   RULE_DIR + 'lan.bin')
        for name in ('ip_white', 'ip_black'):
            self._pack(self._ip_ranges(name), RULE_DIR + name + '.bin')
        for name in ('get', 'post', 'cookie', 'ua', 'scan'):
            rules = [r['rule'] for r in self._rule_set(name) if r.get('open')]
            public.writeFile(RULE_DIR + 'r_' + name + '.txt', '\n'.join(rules))
        for name in ('url_white', 'url_black', 'sensitive'):
            public.writeFile(RULE_DIR + name + '.txt',
                             '\n'.join((x.get('ip') or x.get('rule') or '')
                                       for x in self._list_load(name)))
        public.writeFile(RULE_DIR + 'hdr_limits.txt', '\n'.join(
            '{}|{}'.format(x['h'], int(x['max'])) for x in self._hdr_limits()))
        sp = self._spiders()
        self._pack((sp or {}).get('ranges', []), RULE_DIR + 'spider.bin')
        public.writeFile(RULE_DIR + 'spider_ua.txt', self.SPIDER_UA)
        public.writeFile(RULE_DIR + 'crawl_ua.txt', self.CRAWL_UA)
        ml = self._malicious()
        self._pack((ml or {}).get('ranges', []), RULE_DIR + 'malicious.bin')
        public.writeFile(RULE_DIR + 'waiting.html', self._waiting_html())

        region = self._rules()
        rl = []
        keep = set()
        for r in region:
            keep.add(r['id'] + '.bin')
            rl.append('|'.join([r['id'], r['site'], r['type'], str(r['status']),
                                '1' if r.get('open') else '0']))
        public.writeFile(RULE_DIR + 'region.txt', '\n'.join(rl))

        # traffic limit: id|site|url|dim|rate|action|status|open
        tl = []
        for t in self._traffic():
            tl.append('|'.join([t['id'], t['site'], str(t['url']).replace('|', ''),
                                t['dim'], str(int(t['rate'])), t['action'],
                                str(int(t['status'])), '1' if t.get('open') else '0']))
        public.writeFile(RULE_DIR + 'traffic.txt', '\n'.join(tl))

        # custom rules -> multi-line format the engine reads:
        #   R|id|site|action|status|open
        #   C|field|op|extra|value        (extra = param/header name or bin file)
        # ip/country conditions compile their ranges to a .bin kept alongside
        # the region bins (added to `keep` so the cleanup below spares them).
        cl = []
        for r in self._custom():
            cl.append('|'.join(['R', r['id'], r['site'], r['action'],
                               str(int(r.get('status', 403))),
                               '1' if r.get('open') else '0']))
            for ci, c in enumerate(r.get('conds', [])):
                field, op = c.get('field', ''), c.get('op', '')
                extra, value = c.get('extra', ''), c.get('value', '')
                if field in ('ip', 'country'):
                    ranges = (self._ranges_for(self._split_csv(value))
                              if field == 'country'
                              else self._ip_value_ranges(value))
                    binname = '{}_{}.bin'.format(r['id'], ci)
                    self._pack(ranges or [], RULE_DIR + binname)
                    keep.add(binname)
                    extra, value = binname, ''
                cl.append('|'.join(['C', field, op,
                                   self._enc_pipe(extra), self._enc_pipe(value)]))
        public.writeFile(RULE_DIR + 'custom.txt', '\n'.join(cl))

        # Drop .bin files for region rules that no longer exist. Only region
        # rules have generated names — every other .bin is a fixed one this
        # method writes, so it must be listed in FIXED_BINS or it gets deleted
        # the moment it is created.
        for fn in os.listdir(RULE_DIR):
            if fn.endswith('.bin') and fn not in keep and fn not in self.FIXED_BINS:
                try:
                    os.remove(RULE_DIR + fn)
                except Exception:
                    pass

        try:
            ver = int(public.readFile(RULE_DIR + 'version') or 0)
        except Exception:
            ver = 0
        public.writeFile(RULE_DIR + 'version', str(ver + 1))
        return True

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
        out = []
        for x in self._read_json(PLUGIN_PATH + name + '.json', []) or []:
            try:
                ip = x['ip'] if isinstance(x, dict) else x
                if '/' in ip:
                    s, e = self._cidr_range(ip)
                elif '-' in ip:
                    a, b = ip.split('-', 1)
                    s, e = self._ip2int(a.strip()), self._ip2int(b.strip())
                else:
                    s = e = self._ip2int(ip)
                if s is not None and e is not None:
                    out.append([s, e])
            except Exception:
                continue
        return self._merge(out)

    # ----------------------------------------------------------------
    # status / engine
    # ----------------------------------------------------------------
    def _engine_state(self):
        '''Our own engine: shipped with the plugin, wired by install.sh.'''
        return {
            'installed': os.path.exists(ENGINE_PATH + 'wafpro.lua'),
            'wired': os.path.exists(self.WAFPRO_CONF),
        }

    def get_status(self, get):
        cfg = self._config()
        e = self._engine_state()
        return {
            'status': True,
            'engine_installed': e['installed'],
            'nginx_wired': e['wired'],
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
                self._compile()
                public.writeFile(self.WAFPRO_CONF, public.readFile(src))
            else:
                if os.path.exists(self.WAFPRO_CONF):
                    os.remove(self.WAFPRO_CONF)
            ok = public.ExecShell('/www/server/nginx/sbin/nginx -t 2>&1')
            out = (ok[0] or '') + (ok[1] or '')
            if 'test is successful' not in out:
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
            data = self._dash().overview()
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
        '''Delete WAF log files (optionally for one site/date).'''
        site = getattr(get, 'siteName', '')
        date = getattr(get, 'date', 'all')
        removed = 0
        for s, path in self._log_files(site, date):
            try:
                os.remove(path)
                removed += 1
            except Exception:
                pass
        public.WriteLog('WAF Pro', 'Cleared {} WAF log file(s)'.format(removed))
        return public.returnMsg(True, 'Cleared {} log file(s)'.format(removed))

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
                     'site': rec.get('site', ''), 'status': rec.get('status', 0)}
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
                      'location', 'filter_name'):
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
            if isinstance(self.DEFAULT_CONFIG[k], bool):
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
                    'custom_rules', 'methods', 'hdr_limits',
                    'ip_white', 'ip_black', 'url_white', 'url_black', 'sensitive')

    def _part_path(self, part):
        m = {'config': self.CONFIG, 'sites': self.SITES,
             'region_rules': self.RULES_JSON, 'traffic_rules': self.TRAFFIC_JSON,
             'custom_rules': self.CUSTOM_JSON, 'methods': self.METHODS_FILE,
             'hdr_limits': self.HDR_FILE}
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
    RT_FORMAT = ("    log_format wafpro '$remote_addr - $remote_user [$time_local] \"$request\" '\n"
                 "                      '$status $body_bytes_sent \"$http_referer\" \"$http_user_agent\" '\n"
                 "                      'rt=$request_time urt=$upstream_response_time';\n")

    def rt_status(self, get):
        '''Is origin-response tracking wired into nginx?'''
        body = public.readFile(self.NGINX_CONF) or ''
        has_fmt = 'log_format wafpro' in body
        sites, applied = [], []
        try:
            for f in os.listdir(self.VHOST_DIR):
                if not f.endswith('.conf') or f.startswith('0.') or f in ('wafpro.conf', 'phpfpm_status.conf'):
                    continue
                c = public.readFile(self.VHOST_DIR + f) or ''
                if 'access_log' not in c:
                    continue
                name = f[:-5]
                sites.append(name)
                if re.search(r'access_log\s+\S+\s+wafpro\s*;', c):
                    applied.append(name)
        except Exception:
            pass
        return {'status': True, 'format_defined': has_fmt,
                'sites': sites, 'applied': applied,
                'enabled': bool(has_fmt and applied)}

    def enable_rt(self, get):
        '''Add a log_format carrying $upstream_response_time and point the site
        access_log lines at it. Everything is backed up first and nginx is
        syntax-checked before reload; on failure we roll back.'''
        backups = {}
        try:
            conf = public.readFile(self.NGINX_CONF)
            if not conf:
                return public.returnMsg(False, 'Cannot read nginx.conf')
            backups[self.NGINX_CONF] = conf

            if 'log_format wafpro' not in conf:
                # insert right after the http { block opens
                m = re.search(r'^\s*http\s*\{\s*$', conf, re.M)
                if not m:
                    return public.returnMsg(False, 'Could not locate the http block in nginx.conf')
                pos = m.end()
                conf = conf[:pos] + '\n' + self.RT_FORMAT + conf[pos:]
                public.writeFile(self.NGINX_CONF, conf)

            changed = []
            for f in os.listdir(self.VHOST_DIR):
                if not f.endswith('.conf') or f.startswith('0.') or f in ('wafpro.conf', 'phpfpm_status.conf'):
                    continue
                path = self.VHOST_DIR + f
                c = public.readFile(path) or ''
                if 'access_log' not in c or re.search(r'access_log\s+\S+\s+wafpro\s*;', c):
                    continue
                backups[path] = c
                # only touch real file logs, never "access_log off;"
                new_c = re.sub(r'access_log\s+(/\S+\.log)\s*;', r'access_log  \1 wafpro;', c)
                if new_c != c:
                    public.writeFile(path, new_c)
                    changed.append(f)

            out, err = public.ExecShell('/www/server/nginx/sbin/nginx -t 2>&1')
            result = (out or '') + (err or '')
            if 'successful' not in result:
                for p, b in backups.items():
                    public.writeFile(p, b)
                return public.returnMsg(False, 'nginx test failed, changes reverted: {}'.format(result.strip()[:250]))

            public.ExecShell('/etc/init.d/nginx reload 2>&1')
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
        '''Revert the access_log lines back to the default format.'''
        try:
            changed = 0
            for f in os.listdir(self.VHOST_DIR):
                if not f.endswith('.conf'):
                    continue
                path = self.VHOST_DIR + f
                c = public.readFile(path) or ''
                new_c = re.sub(r'(access_log\s+/\S+\.log)\s+wafpro\s*;', r'\1;', c)
                if new_c != c:
                    public.writeFile(path, new_c)
                    changed += 1
            public.ExecShell('/etc/init.d/nginx reload 2>&1')
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
    URL_LISTS = ('url_white', 'url_black', 'sensitive')
    RULE_NAMES = ('get', 'post', 'cookie', 'ua', 'scan')
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

    def list_get(self, get):
        name = getattr(get, 'list_name', '')
        if name not in self.IP_LISTS + self.URL_LISTS:
            return {'status': False, 'msg': 'Unknown list'}
        items = []
        for i, v in enumerate(self._list_load(name)):
            ip = v.get('ip') if isinstance(v, dict) else v
            items.append({
                'index': i,
                'value': ip,
                'remark': (v.get('ps') if isinstance(v, dict) else '') or self._remark_get(name, ip),
                'type': 'IPv4' if name in self.IP_LISTS else ('Word' if name == 'sensitive' else 'URL'),
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
                s, e = self._parse_ip_input(start, end)
            except ValueError as ve:
                return public.returnMsg(False, str(ve))
            val = s if s == e else '{}-{}'.format(s, e)
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
        name = getattr(get, 'list_name', '')
        if name not in self.IP_LISTS + self.URL_LISTS:
            return {'status': False, 'msg': 'Unknown list'}
        return {'status': True, 'data': [x.get('ip') if isinstance(x, dict) else x
                                         for x in self._list_load(name)]}

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
                    s, e = self._parse_ip_input(v, '')
                    v = s if s == e else '{}-{}'.format(s, e)
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
        name = getattr(get, 'rule_name', '') or getattr(get, 'name', '')
        if name not in self.RULE_NAMES:
            return {'status': False, 'msg': 'Unknown rule set'}
        data = self._rule_set(name)
        return {'status': True, 'data': [
            {'index': i, 'rule': x.get('rule', ''), 'ps': x.get('ps', ''),
             'open': bool(x.get('open'))}
            for i, x in enumerate(data)]}

    def rule_add(self, get):
        name = getattr(get, 'rule_name', '') or getattr(get, 'name', '')
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
        name = getattr(get, 'rule_name', '') or getattr(get, 'name', '')
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
        name = getattr(get, 'rule_name', '') or getattr(get, 'name', '')
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
        '''Accept the shapes the UI advertises and return (start_ip, end_ip):
             1.2.3.4                -> 1.2.3.4 , 1.2.3.4
             1.2.3.4 + 1.2.3.9      -> range
             1.2.3.4-1.2.3.9        -> range
             192.168.100.6-100      -> 192.168.100.6 , 192.168.100.100
             192.168.1.0/24         -> 192.168.1.1 , 192.168.1.254
        '''
        start = (start or '').strip()
        end = (end or '').strip()
        if not start:
            raise ValueError('Start IP is empty')

        if '/' in start:                       # CIDR
            ip, bits = start.split('/', 1)
            bits = int(bits)
            if bits < 0 or bits > 32:
                raise ValueError('Invalid CIDR prefix')
            base = self._ip2int(ip)
            mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
            net, bcast = base & mask, (base & mask) | (~mask & 0xFFFFFFFF)
            if bits >= 31:                     # /31 and /32 have no host range
                return self._int2ip(net), self._int2ip(bcast)
            return self._int2ip(net + 1), self._int2ip(bcast - 1)

        if not end and '-' in start:           # "a-b" or short "1.2.3.4-100"
            a, b = start.split('-', 1)
            a, b = a.strip(), b.strip()
            if '.' not in b:
                b = a.rsplit('.', 1)[0] + '.' + b
            start, end = a, b

        if not end:
            end = start

        s, e = self._ip2int(start), self._ip2int(end)   # validates both
        if s > e:
            raise ValueError('The starting IP cannot be greater than the ending IP')
        return self._int2ip(s), self._int2ip(e)

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
        {'code': 503, 'name': '503 Server is unavailable'},
        {'code': 200, 'name': '200 Normal access'},
    ]

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

    def _ranges_for(self, codes):
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

    def _pack(self, ranges, path):
        import struct
        buf = b''.join(struct.pack('>II', s, e) for s, e in ranges)
        f = open(path, 'wb')
        f.write(buf)
        f.close()
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
                'site': r['site'],
                'areas': r['areas'],
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
        site = (getattr(get, 'site', '') or '').strip()
        if not site:
            return public.returnMsg(False, 'Select a website')
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
        rules.append({'id': rid, 'site': site, 'areas': areas, 'type': typ,
                      'status': status, 'open': True, 'ranges': n,
                      'created': time.strftime('%Y-%m-%d %H:%M:%S')})
        self._region_build(rules)
        public.WriteLog('WAF Pro', 'Region rule added: {} {} on {} ({} ranges)'.format(
            typ, ','.join(areas), site, n))
        return public.returnMsg(True, 'Rule added ({} ranges)'.format(n))

    def region_rule_del(self, get):
        rid = getattr(get, 'id', '')
        rules = [r for r in self._rules() if r['id'] != rid]
        self._region_build(rules)
        return public.returnMsg(True, 'Rule removed')

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
    TRAFFIC_DIMS = ('ip', 'ipua')
    TRAFFIC_ACTIONS = ('status', 'block')
    TRAFFIC_STATUS = (503, 502, 444, 403)

    def _traffic(self):
        r = self._read_json(self.TRAFFIC_JSON, [])
        return r if isinstance(r, list) else []

    def _traffic_save(self, rules):
        public.writeFile(self.TRAFFIC_JSON, json.dumps(rules))
        self._compile()

    def traffic_rules(self, get):
        return {'status': True, 'rules': self._traffic(),
                'sites': self._panel_sites(),
                'engine': self.region_engine_state()}

    def _traffic_validate(self, get):
        name = (getattr(get, 'name', '') or '').strip()
        if not name:
            return None, 'Rule name is required'
        site = (getattr(get, 'site', '') or '').strip()
        if not site:
            return None, 'Select a website'
        url = (getattr(get, 'url', '') or '').strip()
        if not url:
            return None, 'URL pattern is required'
        try:
            re.compile(url)
        except Exception as e:
            return None, 'Invalid URL pattern: {}'.format(e)
        dim = getattr(get, 'dim', 'ip')
        if dim not in self.TRAFFIC_DIMS:
            return None, 'Bad dimension'
        try:
            rate = int(getattr(get, 'rate', 0))
        except Exception:
            rate = 0
        if rate < 1:
            return None, 'Rate must be at least 1 per second'
        action = getattr(get, 'action', 'status')
        if action not in self.TRAFFIC_ACTIONS:
            return None, 'Bad action'
        try:
            status = int(getattr(get, 'status_code', 503))
        except Exception:
            status = 503
        if status not in self.TRAFFIC_STATUS:
            return None, 'Unsupported status code'
        return {'name': name, 'site': site, 'url': url, 'dim': dim,
                'rate': rate, 'action': action, 'status': status}, None

    def traffic_add(self, get):
        rule, err = self._traffic_validate(get)
        if err:
            return public.returnMsg(False, err)
        rule['id'] = 't{}'.format(int(time.time() * 1000))
        rule['open'] = True
        rules = self._traffic()
        rules.append(rule)
        self._traffic_save(rules)
        public.WriteLog('WAF Pro', 'Traffic rule added: {} on {} ({}/s)'.format(
            rule['name'], rule['site'], rule['rate']))
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
    CUSTOM_ACTIONS = ('block', 'code', 'allow')
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
        '''An ip condition value: CIDR, a-b range, or a single address —
        possibly several, comma separated. Returns merged [start,end] pairs.'''
        out = []
        for part in self._split_csv(v):
            try:
                if '/' in part:
                    out.append(list(self._cidr_range(part)))
                elif '-' in part:
                    a, b = part.split('-', 1)
                    out.append([self._ip2int(a.strip()), self._ip2int(b.strip())])
                else:
                    n = self._ip2int(part)
                    out.append([n, n])
            except Exception:
                continue
        return self._merge(out)

    def _custom_validate(self, get):
        name = (getattr(get, 'name', '') or '').strip()
        if not name:
            return None, 'Rule name is required'
        site = (getattr(get, 'site', '') or '').strip()
        if not site:
            return None, 'Select a website'
        action = getattr(get, 'action', 'block')
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
            clean.append({'field': field, 'op': op, 'extra': extra, 'value': value})
        return {'name': name, 'site': site, 'action': action,
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
        out = []
        for name, c in sorted(sites.items()):
            out.append({
                'name': name,
                'open': bool(c.get('open', True)),
                'get': bool(c.get('get', True)),
                'post': bool(c.get('post', True)),
                'cookie': bool(c.get('cookie', True)),
                'ua': bool(c.get('ua', True)),
                'scan': bool(c.get('scan', True)),
                'cc_open': bool(c.get('cc_open', True)),
                'cc_limit': int(c.get('cc_limit', 120)),
                'cc_cycle': int(c.get('cc_cycle', 60)),
                'cc_block': int(c.get('cc_block', 600)),
                'deny_ext': c.get('deny_ext', ''),
                'upload_ext': c.get('upload_ext', ''),
                'php_path': c.get('php_path', ''),
                'cdn': bool(c.get('cdn', False)),
                'fake_spider': bool(c.get('fake_spider', True)),
                'smart_cc': bool(c.get('smart_cc', False)),
                'crawl': bool(c.get('crawl', False)),
                'crawl_limit': int(c.get('crawl_limit', 30)),
                'wait': bool(c.get('wait', False)),
                'wait_limit': int(c.get('wait_limit', 200)),
                'intercepts': hits.get(name, 0),
            })
        return {'status': True, 'data': out, 'mal_open': bool(self._config().get('mal_open'))}

    def _site_hits(self):
        '''Blocks per site for today, straight from our own log.'''
        out = {}
        path = WAF_LOG_DIR + time.strftime('%Y-%m-%d') + '.log'
        if not os.path.exists(path):
            return out
        try:
            f = open(path, 'r')
            for line in f:
                try:
                    s = json.loads(line)
                except Exception:
                    continue
                n = s.get('site')
                if n:
                    out[n] = out.get(n, 0) + 1
            f.close()
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
            data[name][field] = str(getattr(get, 'value', '')).replace('|', '')
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
                # '|' is our sites.txt field separator; never let it through
                data[name][k] = str(patch[k]).replace('|', '')
        self._write_json(self.SITES, data)
        self._compile()
        public.WriteLog('WAF Pro', 'site {} settings saved'.format(name))
        return public.returnMsg(True, 'Site settings saved')

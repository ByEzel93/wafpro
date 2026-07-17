#!/usr/bin/python
# coding: utf-8
# +-------------------------------------------------------------------
# | WAF Pro — dashboard data layer
# +-------------------------------------------------------------------
# | Aggregates the Overview data from our own sources:
# |   - /www/wwwlogs/<site>.log      nginx access log (traffic/QPS)
# |   - /www/wwwlogs/wafpro/*.log    our engine's block log (attacks)
# | Results are cached briefly because access logs can be large.
# +-------------------------------------------------------------------
import os
import re
import json
import time
import gzip
from collections import defaultdict

PLUGIN_PATH = '/www/server/panel/plugin/wafpro/'
WAF_LOG_DIR = '/www/wwwlogs/wafpro/'
NGX_LOG_DIR = '/www/wwwlogs/'
CACHE_DIR = '/www/server/panel/plugin/wafpro/cache/'
CACHE_TTL = 60          # seconds
MAX_BYTES = 12 * 1024 * 1024   # only tail this much of a big access log

# The panel already ships a GeoIP database, so nothing has to be downloaded.
# NOTE: it uses a NON-standard schema — everything sits flat under "country"
# ({'country': {'country': 'Brazil', 'en_short_code': 'BR', 'city': ...,
# 'latitude': ..., 'longitude': ...}}) — which is why geoip2's .city() returns
# empty and we read it through maxminddb directly.
GEO_DB = '/www/server/panel/config/GeoLite2-City.mmdb'
_geo_reader = None
_geo_cache = {}


def geo_reader():
    global _geo_reader
    if _geo_reader is None:
        try:
            import maxminddb
            _geo_reader = maxminddb.open_database(GEO_DB)
        except Exception:
            _geo_reader = False
    return _geo_reader or None


def geo_lookup(ip):
    '''ip -> {country, code, city, lat, lon}; empty dict when unknown.'''
    if not ip or ip in _geo_cache:
        return _geo_cache.get(ip, {})
    out = {}
    r = geo_reader()
    if r:
        try:
            d = r.get(ip)
            c = (d or {}).get('country') or {}
            if c:
                out = {
                    'country': c.get('country') or '',
                    'code': c.get('en_short_code') or '',
                    'city': c.get('city') or '',
                    'province': c.get('province') or '',
                    'lat': c.get('latitude'),
                    'lon': c.get('longitude'),
                }
        except Exception:
            out = {}
    if len(_geo_cache) < 20000:
        _geo_cache[ip] = out
    return out

# 1.2.3.4 - - [17/Jul/2026:12:52:04 +0300] "POST /path HTTP/1.1" 400 150 "-" "UA"
# Optionally followed by our own fields when origin-response tracking is on:
#   ... "UA" rt=0.123 urt=0.120
ACCESS_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<url>[^"]*?) [^"]*" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
    r'(?:.*?\burt=(?P<urt>[\d.]+|-))?'
)
MONTHS = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
          'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}


def _ensure_cache():
    if not os.path.exists(CACHE_DIR):
        try:
            os.makedirs(CACHE_DIR, 0o700)
        except Exception:
            pass


def cache_get(key):
    _ensure_cache()
    f = CACHE_DIR + key + '.json'
    try:
        if os.path.exists(f) and (time.time() - os.path.getmtime(f)) < CACHE_TTL:
            with open(f) as fh:
                return json.load(fh)
    except Exception:
        pass
    return None


def cache_set(key, data):
    _ensure_cache()
    try:
        with open(CACHE_DIR + key + '.json', 'w') as fh:
            json.dump(data, fh)
    except Exception:
        pass
    return data


def _read_json(path, default=None):
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return default


def get_sites():
    site = _read_json(PLUGIN_PATH + 'site.json', {}) or {}
    return list(site.keys())


def _tail_bytes(path, max_bytes=MAX_BYTES):
    '''Read at most the last max_bytes of a file, aligned to a line start.'''
    try:
        size = os.path.getsize(path)
        with open(path, 'rb') as fh:
            if size > max_bytes:
                fh.seek(size - max_bytes)
                fh.readline()  # drop the partial first line
            return fh.read().decode('utf-8', 'ignore')
    except Exception:
        return ''


def _parse_ts(s):
    # 17/Jul/2026:12:52:04 +0300
    try:
        d, mon, rest = s.split('/', 2)
        year, hh, mm, ss = rest.split(':')[0], rest.split(':')[1], rest.split(':')[2], rest.split(':')[3][:2]
        return (int(year), MONTHS.get(mon, 1), int(d), int(hh), int(mm), int(ss))
    except Exception:
        return None


def access_stats(days=2):
    '''Per-site nginx access aggregation for today and yesterday.

    Returns dict with today/yesterday totals, hourly buckets, top urls,
    top domains by traffic and unique IP counts.
    '''
    cached = cache_get('access_stats')
    if cached:
        return cached

    now = time.localtime()
    today = (now.tm_year, now.tm_mon, now.tm_mday)
    y = time.localtime(time.time() - 86400)
    yday = (y.tm_year, y.tm_mon, y.tm_mday)

    out = {
        'today': {'requests': 0, 'bytes': 0, 'ips': 0},
        'yesterday': {'requests': 0, 'bytes': 0, 'ips': 0},
        'hourly': {'total': [0] * 24, 'traffic': [0] * 24, 'ips': [0] * 24},
        'top_urls': [], 'top_domains': [], 'recent': [],
    }
    today_ips = set()
    yday_ips = set()
    hourly_ips = defaultdict(set)
    url_count = defaultdict(int)
    domain_bytes = defaultdict(int)
    ip_hits = defaultdict(int)

    sites = get_sites()
    if not sites:
        # fall back to every *.log that is not an error log
        try:
            sites = [f[:-4] for f in os.listdir(NGX_LOG_DIR)
                     if f.endswith('.log') and '.error.' not in f and f != 'access.log']
        except Exception:
            sites = []

    for site in sites:
        path = NGX_LOG_DIR + site + '.log'
        if not os.path.exists(path):
            continue
        body = _tail_bytes(path)
        for line in body.split('\n'):
            if not line:
                continue
            m = ACCESS_RE.match(line)
            if not m:
                continue
            ts = _parse_ts(m.group('time'))
            if not ts:
                continue
            day = (ts[0], ts[1], ts[2])
            size = m.group('size')
            size = int(size) if size and size.isdigit() else 0
            ip = m.group('ip')
            if day == today:
                out['today']['requests'] += 1
                out['today']['bytes'] += size
                today_ips.add(ip)
                ip_hits[ip] += 1
                h = ts[3]
                out['hourly']['total'][h] += 1
                out['hourly']['traffic'][h] += size
                hourly_ips[h].add(ip)
                url_count[m.group('url').split('?')[0][:120]] += 1
                domain_bytes[site] += size
            elif day == yday:
                out['yesterday']['requests'] += 1
                out['yesterday']['bytes'] += size
                yday_ips.add(ip)

    out['today']['ips'] = len(today_ips)
    out['yesterday']['ips'] = len(yday_ips)
    out['top_ips'] = sorted([{'ip': k, 'count': v} for k, v in ip_hits.items()],
                            key=lambda x: x['count'], reverse=True)[:60]
    for h in range(24):
        out['hourly']['ips'][h] = len(hourly_ips.get(h, ()))
    out['top_urls'] = sorted(
        [{'url': k, 'count': v} for k, v in url_count.items()],
        key=lambda x: x['count'], reverse=True)[:10]
    out['top_domains'] = sorted(
        [{'domain': k, 'bytes': v} for k, v in domain_bytes.items()],
        key=lambda x: x['bytes'], reverse=True)[:10]
    return cache_set('access_stats', out)


def waf_stats():
    '''Aggregate our engine's block log for today and yesterday.

    Our engine writes one file per day (wafpro/YYYY-MM-DD.log), one JSON
    object per line, with the site inside the record.
    '''
    cached = cache_get('waf_stats')
    if cached:
        return cached

    today_s = time.strftime('%Y-%m-%d')
    yday_s = time.strftime('%Y-%m-%d', time.localtime(time.time() - 86400))
    out = {
        'today': {'blocks': 0}, 'yesterday': {'blocks': 0},
        'hourly': [0] * 24,
        'top_ips': [], 'top_domains': [], 'by_rule': {}, 'recent': [],
    }
    ip_count = defaultdict(int)
    dom_count = defaultdict(int)
    rule_count = defaultdict(int)

    if not os.path.isdir(WAF_LOG_DIR):
        return cache_set('waf_stats', out)

    for day, is_today in ((today_s, True), (yday_s, False)):
        path = WAF_LOG_DIR + day + '.log'
        if not os.path.exists(path):
            continue
        for line in _tail_bytes(path, 4 * 1024 * 1024).split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if not is_today:
                out['yesterday']['blocks'] += 1
                continue
            out['today']['blocks'] += 1
            ip_count[rec.get('ip', '?')] += 1
            dom_count[rec.get('site', '?')] += 1
            rule_count[rec.get('rule', '?')] += 1
            try:
                out['hourly'][int(time.strftime('%H', time.localtime(rec['time'])))] += 1
            except Exception:
                pass
            if len(out['recent']) < 30:
                out['recent'].append({
                    'time': time.strftime('%Y-%m-%d %H:%M:%S',
                                          time.localtime(rec.get('time', 0))),
                    'ip': rec.get('ip', ''), 'method': rec.get('method', ''),
                    'url': (rec.get('uri') or '')[:100],
                    'ua': (rec.get('ua') or '')[:60],
                    'type': rec.get('rule', ''), 'site': rec.get('site', ''),
                })

    out['top_ips'] = sorted([{'ip': k, 'count': v} for k, v in ip_count.items()],
                            key=lambda x: x['count'], reverse=True)[:12]
    out['top_domains'] = sorted([{'domain': k, 'count': v} for k, v in dom_count.items()],
                                key=lambda x: x['count'], reverse=True)[:10]
    out['by_rule'] = dict(rule_count)
    out['recent'].reverse()
    return cache_set('waf_stats', out)


def rt_tracking_enabled():
    '''True when the access logs carry our urt= field (origin response time).'''
    try:
        body = public_read('/www/server/nginx/conf/nginx.conf')
        return 'log_format wafpro' in body
    except Exception:
        return False


def public_read(path):
    try:
        with open(path, 'r', errors='ignore') as fh:
            return fh.read()
    except Exception:
        return ''


def realtime_qps(window=60):
    '''Requests per second over the last <window> seconds, from access logs.
    Also averages upstream response time when tracking is enabled.'''
    now = time.time()
    buckets = defaultdict(int)
    rt_sum = defaultdict(float)
    rt_cnt = defaultdict(int)
    sites = get_sites()
    if not sites:
        try:
            sites = [f[:-4] for f in os.listdir(NGX_LOG_DIR)
                     if f.endswith('.log') and '.error.' not in f and f != 'access.log']
        except Exception:
            sites = []
    for site in sites:
        path = NGX_LOG_DIR + site + '.log'
        if not os.path.exists(path):
            continue
        body = _tail_bytes(path, 512 * 1024)
        for line in body.split('\n')[-4000:]:
            m = ACCESS_RE.match(line) if line else None
            if not m:
                continue
            ts = _parse_ts(m.group('time'))
            if not ts:
                continue
            try:
                epoch = time.mktime((ts[0], ts[1], ts[2], ts[3], ts[4], ts[5], 0, 0, -1))
            except Exception:
                continue
            age = now - epoch
            if 0 <= age <= window:
                sec = int(epoch)
                buckets[sec] += 1
                urt = m.groupdict().get('urt')
                if urt and urt not in ('-', ''):
                    try:
                        rt_sum[sec] += float(urt)
                        rt_cnt[sec] += 1
                    except Exception:
                        pass
    points = []
    rt_points = []
    start = int(now) - window
    for t in range(start, int(now) + 1, 5):
        rng = range(t, t + 5)
        c = sum(buckets.get(x, 0) for x in rng)
        label = time.strftime('%H:%M:%S', time.localtime(t))
        points.append({'t': label, 'v': round(c / 5.0, 2)})
        s = sum(rt_sum.get(x, 0.0) for x in rng)
        n = sum(rt_cnt.get(x, 0) for x in rng)
        rt_points.append({'t': label, 'v': round(s / n * 1000, 1) if n else 0})
    tracked = rt_tracking_enabled()
    last_rt = 0
    for p in reversed(rt_points):
        if p['v']:
            last_rt = p['v']
            break
    return {
        'points': points,
        'now': points[-1]['v'] if points else 0,
        'rt_points': rt_points,
        'rt_now': last_rt,
        'rt_tracked': tracked,
    }


def _pct(cur, prev):
    if not prev:
        return 0 if not cur else 100
    return round((cur - prev) / float(prev) * 100, 2)


def _geo_enrich(top_ips):
    '''Attach country/city/coords to the attacker list and build map points.'''
    points = {}
    countries = defaultdict(int)
    for row in top_ips:
        g = geo_lookup(row['ip'])
        row['country'] = g.get('country', '')
        row['code'] = g.get('code', '')
        row['city'] = g.get('city', '')
        lat, lon = g.get('lat'), g.get('lon')
        # Private/LAN addresses resolve to "Internal network address" at 0,0 —
        # plotting them would drop a bogus marker in the Gulf of Guinea.
        if not g.get('code') or (lat == 0 and lon == 0):
            continue
        if lat is not None and lon is not None:
            key = '{:.2f},{:.2f}'.format(lat, lon)
            if key not in points:
                points[key] = {'lat': lat, 'lon': lon, 'count': 0,
                               'country': row['country'], 'city': row['city']}
            points[key]['count'] += row['count']
        if row['code']:
            countries[row['code']] += row['count']
    map_points = sorted(points.values(), key=lambda x: x['count'], reverse=True)
    by_country = sorted([{'code': k, 'count': v} for k, v in countries.items()],
                        key=lambda x: x['count'], reverse=True)
    return map_points, by_country


def overview():
    '''Everything the Overview page needs in one call.'''
    acc = access_stats()
    waf = waf_stats()
    # "Blocks" map = IPs the WAF actually blocked
    map_points, by_country = _geo_enrich(waf['top_ips'])
    # "Requests" map = every visitor seen in the access logs today
    req_points, req_countries = _geo_enrich(acc.get('top_ips', [])[:40])
    for r in waf['recent']:
        g = geo_lookup(r['ip'])
        r['country'] = g.get('country', '')
        r['code'] = g.get('code', '')

    return {
        'attack_map': map_points,
        'by_country': by_country,
        'request_map': req_points,
        'request_countries': req_countries,
        'top_request_ips': acc.get('top_ips', [])[:15],
        'status': True,
        'cards': {
            'today_request': acc['today']['requests'],
            'today_request_pct': _pct(acc['today']['requests'], acc['yesterday']['requests']),
            'yesterday_request': acc['yesterday']['requests'],
            'malicious_request': waf['today']['blocks'],
            'malicious_request_pct': _pct(waf['today']['blocks'], waf['yesterday']['blocks']),
            'yesterday_malicious': waf['yesterday']['blocks'],
            'today_ips': acc['today']['ips'],
            'today_bytes': acc['today']['bytes'],
        },
        'chart': {
            'hours': ['%02d:00' % h for h in range(24)],
            'total': acc['hourly']['total'],
            'blocked': waf['hourly'],
            'after_filter': [max(acc['hourly']['total'][h] - waf['hourly'][h], 0) for h in range(24)],
            'traffic_mb': [round(acc['hourly']['traffic'][h] / 1048576.0, 2) for h in range(24)],
            'ips': acc['hourly']['ips'],
        },
        'top_attack_ips': waf['top_ips'],
        'attacked_domains': waf['top_domains'],
        'top_urls': acc['top_urls'],
        'top_domains_traffic': acc['top_domains'],
        'by_rule': waf['by_rule'],
        'recent_attacks': waf['recent'],
        'waf_total': waf['today']['blocks'] + waf['yesterday']['blocks'],
    }

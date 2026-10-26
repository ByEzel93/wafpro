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
STATIC_EXT = re.compile(r'\.(?:css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|bmp|woff2?|ttf|otf|eot|mp4|webm|mp3|ogg|wav|pdf|zip|gz|txt|xml|json)$', re.I)


def _client(ua):
    '''(browser, os) from a User-Agent — the coarse families the
    Client distribution card shows.'''
    u = (ua or '').lower()
    if not u or u == '-':
        return 'Unknown', 'Unknown'
    if any(k in u for k in ('bot', 'spider', 'crawl', 'slurp', 'curl', 'wget', 'python', 'go-http', 'java/', 'okhttp', 'axios', 'node')):
        b = 'Bot / tool'
    elif 'edg/' in u or 'edge/' in u:
        b = 'Edge'
    elif 'opr/' in u or 'opera' in u:
        b = 'Opera'
    elif 'samsungbrowser' in u:
        b = 'Samsung Internet'
    elif 'micromessenger' in u:
        b = 'WeChat'
    elif 'firefox/' in u or 'fxios' in u:
        b = 'Firefox'
    elif 'chrome/' in u or 'crios' in u:
        b = 'Chrome'
    elif 'safari/' in u:
        b = 'Safari'
    elif 'msie' in u or 'trident/' in u:
        b = 'IE'
    else:
        b = 'Other'
    if 'windows' in u:
        o = 'Windows'
    elif 'android' in u:
        o = 'Android'
    elif 'iphone' in u or 'ipad' in u or 'ios' in u:
        o = 'iOS'
    elif 'mac os' in u or 'macintosh' in u:
        o = 'macOS'
    elif 'linux' in u:
        o = 'Linux'
    else:
        o = 'Other'
    return b, o


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


def _day_epoch(day):
    '''YYYY-MM-DD -> local midnight epoch; None/'' -> now.'''
    if not day:
        return time.time()
    return time.mktime(time.strptime(day, '%Y-%m-%d'))


def access_stats(day=None):
    '''Per-site nginx access aggregation for one day and the day before.

    Returns dict with day/previous-day totals, hourly buckets, top urls,
    top domains by traffic and unique IP counts. Only the tail of each live
    access log is read, so days older than yesterday come back empty.
    '''
    key = 'access_stats' + ('_' + day if day else '')
    cached = cache_get(key)
    if cached:
        return cached

    base = _day_epoch(day)
    now = time.localtime(base)
    today = (now.tm_year, now.tm_mon, now.tm_mday)
    y = time.localtime(base - 86400)
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
    # Overview detail cards (today only)
    status_count = defaultdict(int)
    browser_count = defaultdict(int)
    os_count = defaultdict(int)
    ref_count = defaultdict(int)
    ip_stat = defaultdict(lambda: [0, 0, 0, 0, ''])     # hits, bytes, static hits, static bytes, site
    url_stat = defaultdict(lambda: [0, 0, 0, 0, ''])
    dyn_static = [0, 0]

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
                path = m.group('url').split('?')[0][:120]
                url_count[path] += 1
                domain_bytes[site] += size
                st = m.group('status')
                status_count[st] += 1
                b, o = _client(m.group('ua'))
                browser_count[b] += 1
                os_count[o] += 1
                ref = m.group('ref') or '-'
                if ref in ('-', ''):
                    ref_count['Direct'] += 1
                else:
                    ref_count[ref.split('/')[2] if '://' in ref else ref[:80]] += 1
                static = bool(STATIC_EXT.search(path))
                dyn_static[1 if static else 0] += 1
                for key, tab in ((ip, ip_stat), (path, url_stat)):
                    r = tab[key]
                    r[0] += 1
                    r[1] += size
                    if static:
                        r[2] += 1
                        r[3] += size
                    r[4] = site
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

    def top(d, n=None):
        return sorted(([k, v] for k, v in d.items()), key=lambda x: x[1], reverse=True)[:n]
    out['status_codes'] = top(status_count)
    out['browsers'] = top(browser_count)
    out['oses'] = top(os_count)
    out['referrers'] = top(ref_count, 50)
    out['dyn_static'] = dyn_static
    out['ip_traffic'] = [{'ip': k, 'site': v[4], 'count': v[0], 'bytes': v[1], 'static': v[2], 'static_bytes': v[3]}
                         for k, v in sorted(ip_stat.items(), key=lambda x: x[1][1], reverse=True)[:100]]
    out['url_traffic'] = [{'url': k, 'site': v[4], 'count': v[0], 'bytes': v[1], 'static': v[2], 'static_bytes': v[3]}
                          for k, v in sorted(url_stat.items(), key=lambda x: x[1][0], reverse=True)[:100]]
    return cache_set(key, out)


def waf_stats(day=None):
    '''Aggregate our engine's block log for one day and the day before.

    Our engine writes one file per day (wafpro/YYYY-MM-DD.log), one JSON
    object per line, with the site inside the record.
    '''
    key = 'waf_stats' + ('_' + day if day else '')
    cached = cache_get(key)
    if cached:
        return cached

    base = _day_epoch(day)
    today_s = time.strftime('%Y-%m-%d', time.localtime(base))
    yday_s = time.strftime('%Y-%m-%d', time.localtime(base - 86400))
    out = {
        'today': {'blocks': 0}, 'yesterday': {'blocks': 0},
        'hourly': [0] * 24,
        'top_ips': [], 'top_domains': [], 'by_rule': {}, 'recent': [],
    }
    ip_count = defaultdict(int)
    dom_count = defaultdict(int)
    rule_count = defaultdict(int)

    if not os.path.isdir(WAF_LOG_DIR):
        return cache_set(key, out)

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
            # newest 30: the file is oldest-first, so keep the tail
            if len(out['recent']) >= 30:
                out['recent'].pop(0)
            out['recent'].append({
                'time': time.strftime('%Y-%m-%d %H:%M:%S',
                                      time.localtime(rec.get('time', 0))),
                'ip': rec.get('ip', ''), 'method': rec.get('method', ''),
                'url': (rec.get('uri') or '')[:100],
                'ua': (rec.get('ua') or '')[:60],
                'type': rec.get('rule', ''), 'site': rec.get('site', ''),
                'payload': (rec.get('payload') or '')[:200], 'rx': (rec.get('rx') or '')[:300],
            })

    out['recent'].reverse()
    out['top_ips'] = sorted([{'ip': k, 'count': v} for k, v in ip_count.items()],
                            key=lambda x: x['count'], reverse=True)[:12]
    out['top_domains'] = sorted([{'domain': k, 'count': v} for k, v in dom_count.items()],
                                key=lambda x: x['count'], reverse=True)[:10]
    out['by_rule'] = dict(rule_count)
    out['recent'].reverse()
    return cache_set(key, out)


def rt_tracking_enabled():
    '''True when the access logs carry our urt= field (origin response time).'''
    # 2.1+ keeps the format in its own include; older installs had it in
    # nginx.conf
    if os.path.exists('/www/server/panel/vhost/nginx/0.wafpro_log_format.conf'):
        return True
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


def realtime_qps(window=300, step=10):
    '''Requests per second over the last <window> seconds, from access logs.
    Also averages upstream response time when tracking is enabled.'''
    now = time.time()
    buckets = defaultdict(int)
    bytes_ = defaultdict(int)
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
        body = _tail_bytes(path, 2 * 1024 * 1024)
        for line in body.split('\n')[-20000:]:
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
                sz = m.group('size')
                bytes_[sec] += int(sz) if sz and sz.isdigit() else 0
                urt = m.groupdict().get('urt')
                if urt and urt not in ('-', ''):
                    try:
                        rt_sum[sec] += float(urt)
                        rt_cnt[sec] += 1
                    except Exception:
                        pass
    points = []
    rt_points = []
    bw_points = []
    start = int(now) - window
    for t in range(start, int(now) + 1, step):
        rng = range(t, t + step)
        c = sum(buckets.get(x, 0) for x in rng)
        label = time.strftime('%H:%M:%S', time.localtime(t))
        points.append({'t': label, 'v': round(c / float(step), 2)})
        bw_points.append({'t': label, 'v': round(sum(bytes_.get(x, 0) for x in rng) / float(step))})
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
        'bw_points': bw_points,
        'bw_now': bw_points[-1]['v'] if bw_points else 0,
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


def _geo_rows(rows):
    for r in rows[:100]:
        g = geo_lookup(r['ip'])
        r['country'] = g.get('country', '')
    return rows


def overview(day=None):
    '''Everything the Overview page needs in one call (day: YYYY-MM-DD,
    default today).'''
    acc = access_stats(day)
    waf = waf_stats(day)
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
        'status_codes': acc.get('status_codes', []),
        'browsers': acc.get('browsers', []),
        'oses': acc.get('oses', []),
        'referrers': acc.get('referrers', []),
        'dyn_static': acc.get('dyn_static', [0, 0]),
        'ip_traffic': _geo_rows(acc.get('ip_traffic', [])),
        'url_traffic': acc.get('url_traffic', []),
        'recent_attacks': waf['recent'],
        'waf_total': waf['today']['blocks'] + waf['yesterday']['blocks'],
    }

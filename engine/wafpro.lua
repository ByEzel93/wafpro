-- +-------------------------------------------------------------------
-- | WAF Pro — standalone engine
-- +-------------------------------------------------------------------
-- | Dependency-free on purpose: no cjson, no ffi, no resty. This nginx is
-- | plain + lua_nginx_module, and the cjson.so on these boxes was compiled
-- | by the free WAF's installer — depending on it would silently require a
-- | plugin we are built to work without.
-- |
-- | So the panel compiles everything down to formats plain Lua can read:
-- |   rule/config.txt   key=value globals
-- |   rule/sites.txt    per-site switches, one line each
-- |   rule/r_*.txt      one regex per line
-- |   rule/*.bin        packed sorted IP ranges (8B/range), binary-searched
-- |   rule/version      bumped on every change -> workers resync, no reload
-- +-------------------------------------------------------------------
local _M = { _VERSION = '1.0' }

local RULE_DIR = '/www/server/wafpro/rule/'
local LOG_DIR = '/www/wwwlogs/wafpro/'

local floor = math.floor
local byte = string.byte
local fmt = string.format

local state = { version = -1 }

-- CC counting skips these: a page pulls dozens of them and they are not the
-- attack surface. Matches btwaf's default static exemption.
local STATIC_EXT = {
    js=true, css=true, png=true, jpg=true, jpeg=true, gif=true, webp=true,
    svg=true, ico=true, woff=true, woff2=true, ttf=true, eot=true, mp4=true,
    webm=true, mp3=true, pdf=true, map=true,
}
local function is_static(uri)
    local ext = uri:match('%.([%w]+)$')
    return ext ~= nil and STATIC_EXT[ext:lower()] == true
end

-- ---------------- io helpers ----------------

local function read_all(path)
    local f = io.open(path, 'rb')
    if not f then return nil end
    local d = f:read('*a')
    f:close()
    return d
end

local function read_lines(path)
    local d = read_all(path)
    if not d then return {} end
    local t = {}
    for line in d:gmatch('[^\r\n]+') do
        if line ~= '' and line:sub(1, 1) ~= '#' then t[#t + 1] = line end
    end
    return t
end

-- ---------------- ip ----------------

local function ip2int(ip)
    if not ip then return nil end
    local a, b, c, d = ip:match('^(%d+)%.(%d+)%.(%d+)%.(%d+)$')
    if not a then return nil end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if a > 255 or b > 255 or c > 255 or d > 255 then return nil end
    return a * 16777216 + b * 65536 + c * 256 + d
end
_M.ip2int = ip2int

local function be32(buf, off)
    local a, b, c, d = byte(buf, off + 1, off + 4)
    return a * 16777216 + b * 65536 + c * 256 + d
end

-- buf: sorted, non-overlapping [start,end] pairs -> binary search
local function in_ranges(buf, ip)
    if not buf or #buf < 8 then return false end
    local lo, hi = 0, floor(#buf / 8) - 1
    while lo <= hi do
        local mid = floor((lo + hi) / 2)
        local off = mid * 8
        if ip < be32(buf, off) then
            hi = mid - 1
        elseif ip > be32(buf, off + 4) then
            lo = mid + 1
        else
            return true
        end
    end
    return false
end
_M.in_ranges = in_ranges

-- ---------------- config loading ----------------

local function parse_kv(path)
    local t = {}
    for _, line in ipairs(read_lines(path)) do
        local k, v = line:match('^([^=]+)=(.*)$')
        if k then
            if v == 'true' then v = true
            elseif v == 'false' then v = false
            elseif tonumber(v) then v = tonumber(v) end
            t[k] = v
        end
    end
    return t
end

-- Split on a single-char separator, keeping empty fields.
-- Not gmatch('[^|]*'): that pattern also matches the empty string between
-- every field, so "a|b" yields {"a","","b",""} and every index shifts — which
-- silently made each site's switches read from the wrong column.
local function split(s, sep)
    local out = {}
    local start = 1
    while true do
        local i = s:find(sep, start, true)
        if not i then
            out[#out + 1] = s:sub(start)
            return out
        end
        out[#out + 1] = s:sub(start, i - 1)
        start = i + 1
    end
end

-- "a, b ,c" -> set{a=true,b=true,c=true}, lowercased
local function parse_set(line)
    local t = {}
    if not line or line == '' then return t end
    for _, v in ipairs(split(line, ',')) do
        v = v:gsub('^%s+', ''):gsub('%s+$', ''):lower()
        if v ~= '' then t[v] = true end
    end
    return t
end

-- "a, b" -> {"a","b"}, lowercased, order kept
local function split_clean(line)
    local out = {}
    if not line or line == '' then return out end
    for _, v in ipairs(split(line, ',')) do
        v = v:gsub('^%s+', ''):gsub('%s+$', ''):lower()
        if v ~= '' then out[#out + 1] = v end
    end
    return out
end

-- name|open|get|post|cookie|ua|scan|cc_open|cc_limit|cc_cycle|cc_block
--     |deny_ext|upload_ext|php_path|cdn|fake_spider
--     |smart_cc|crawl|crawl_limit|wait|wait_limit
local function parse_sites(path)
    local t = {}
    for _, line in ipairs(read_lines(path)) do
        local f = split(line, '|')
        if f[1] and f[1] ~= '' then
            t[f[1]] = {
                open = f[2] == '1', get = f[3] == '1', post = f[4] == '1',
                cookie = f[5] == '1', ua = f[6] == '1', scan = f[7] == '1',
                cc_open = f[8] == '1', cc_limit = tonumber(f[9]) or 120,
                cc_cycle = tonumber(f[10]) or 60, cc_block = tonumber(f[11]) or 600,
                -- parsed once here, not per request
                deny_ext = parse_set(f[12]),
                upload_ext = parse_set(f[13]),
                php_path = split_clean(f[14]),
                cdn = f[15] == '1', fake_spider = f[16] == '1',
                smart_cc = f[17] == '1',
                crawl = f[18] == '1', crawl_limit = tonumber(f[19]) or 30,
                wait = f[20] == '1', wait_limit = tonumber(f[21]) or 200,
            }
        end
    end
    return t
end

-- id|site|type|status|open
local function parse_region(path)
    local rules, by_site = {}, {}
    for _, line in ipairs(read_lines(path)) do
        local id, site, typ, status, open = line:match('^([^|]*)|([^|]*)|([^|]*)|([^|]*)|([^|]*)$')
        if id and open == '1' then
            local buf = read_all(RULE_DIR .. id .. '.bin')
            if buf then
                local r = { id = id, site = site, typ = typ,
                            status = tonumber(status) or 444, ranges = buf }
                rules[#rules + 1] = r
                local b = by_site[site]
                if not b then b = {}; by_site[site] = b end
                b[#b + 1] = r
            end
        end
    end
    return rules, by_site
end

-- Custom rules. A rule spans several lines:
--   R|id|site|action|status|open      one rule header
--   C|field|op|extra|value            one AND-condition (repeats)
-- extra carries the parameter/header name, or a bin filename for ip/country.
-- Value's '|' is percent-encoded by the panel so it survives the split.
local function url_decode_pipe(v)
    return (v or ''):gsub('%%7C', '|'):gsub('%%25', '%%')
end
local function parse_custom(path)
    local rules, by_site, cur = {}, {}, nil
    for _, line in ipairs(read_lines(path)) do
        local f = split(line, '|')
        if f[1] == 'R' and f[2] and f[2] ~= '' then
            cur = { id = f[2], site = f[3], action = f[4],
                    status = tonumber(f[5]) or 403, open = f[6] == '1', conds = {} }
            if cur.open then
                rules[#rules + 1] = cur
                local b = by_site[cur.site]
                if not b then b = {}; by_site[cur.site] = b end
                b[#b + 1] = cur
            end
        elseif f[1] == 'C' and cur then
            local c = { field = f[2], op = f[3], extra = url_decode_pipe(f[4]),
                        value = url_decode_pipe(f[5] or '') }
            if c.field == 'ip' or c.field == 'country' then
                c.bin = read_all(RULE_DIR .. c.extra)   -- extra = bin filename
            end
            cur.conds[#cur.conds + 1] = c
        end
    end
    return rules, by_site
end

-- traffic limit: id|site|url|dim|rate|action|status|open
-- url is a regex, dim is 'ip' or 'ipua', action is 'status' or 'block'
local function parse_traffic(path)
    local rules, by_site = {}, {}
    for _, line in ipairs(read_lines(path)) do
        local f = split(line, '|')
        if f[1] and f[1] ~= '' and f[8] == '1' then
            local r = { id = f[1], site = f[2], url = f[3], dim = f[4],
                        rate = tonumber(f[5]) or 10, action = f[6],
                        status = tonumber(f[7]) or 503 }
            rules[#rules + 1] = r
            local b = by_site[f[2]]
            if not b then b = {}; by_site[f[2]] = b end
            b[#b + 1] = r
        end
    end
    return rules, by_site
end

-- header|limit per line
local function parse_hdr_limits(path)
    local t = {}
    for _, line in ipairs(read_lines(path)) do
        local f = split(line, '|')
        local n = tonumber(f[2])
        if f[1] and f[1] ~= '' and n then t[#t + 1] = { h = f[1]:lower(), max = n } end
    end
    return t
end

function _M.load()
    local cfg = parse_kv(RULE_DIR .. 'config.txt')
    local region, region_by_site = parse_region(RULE_DIR .. 'region.txt')
    local traffic, traffic_by_site = parse_traffic(RULE_DIR .. 'traffic.txt')
    local custom, custom_by_site = parse_custom(RULE_DIR .. 'custom.txt')
    state = {
        version = tonumber(read_all(RULE_DIR .. 'version') or '') or 0,
        cfg = cfg,
        sites = parse_sites(RULE_DIR .. 'sites.txt'),
        region = region,
        region_by_site = region_by_site,
        traffic = traffic,
        traffic_by_site = traffic_by_site,
        custom = custom,
        custom_by_site = custom_by_site,
        lan = read_all(RULE_DIR .. 'lan.bin'),
        ip_white = read_all(RULE_DIR .. 'ip_white.bin'),
        ip_black = read_all(RULE_DIR .. 'ip_black.bin'),
        r_get = read_lines(RULE_DIR .. 'r_get.txt'),
        r_post = read_lines(RULE_DIR .. 'r_post.txt'),
        r_cookie = read_lines(RULE_DIR .. 'r_cookie.txt'),
        r_ua = read_lines(RULE_DIR .. 'r_ua.txt'),
        r_scan = read_lines(RULE_DIR .. 'r_scan.txt'),
        url_white = read_lines(RULE_DIR .. 'url_white.txt'),
        url_black = read_lines(RULE_DIR .. 'url_black.txt'),
        sensitive = read_lines(RULE_DIR .. 'sensitive.txt'),
        methods = parse_set(cfg.methods),
        hdr_limits = parse_hdr_limits(RULE_DIR .. 'hdr_limits.txt'),
        spider = read_all(RULE_DIR .. 'spider.bin'),
        spider_ua = (read_lines(RULE_DIR .. 'spider_ua.txt'))[1],
        mal = read_all(RULE_DIR .. 'malicious.bin'),
        crawl_ua = (read_lines(RULE_DIR .. 'crawl_ua.txt'))[1],
        wait_html = read_all(RULE_DIR .. 'waiting.html'),
        unban = read_lines(RULE_DIR .. 'unban.txt'),
    }
end

-- The panel bumps rule/version on every change; workers poll it. This is why
-- saving a setting here does not need an nginx reload.
function _M.refresh()
    local ver = tonumber(read_all(RULE_DIR .. 'version') or '')
    if not ver or ver == state.version then return end
    _M.load()
    -- A ban lives in the shared dict, which the panel cannot touch. So "unban"
    -- is a list the panel writes; each worker drops those keys from its dict
    -- on the next resync. Runs in the worker timer only — ngx.shared is not
    -- usable from every phase load() may be called in.
    local blocked = ngx.shared.wafpro_block
    if blocked then
        for _, ip in ipairs(state.unban) do blocked:delete(ip) end
    end
end

-- ---------------- logging ----------------

local function esc(s)
    if not s then return '' end
    return tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('[\r\n\t]', ' ')
end

local function log_block(ip, site, rule, payload, status)
    if state.cfg and state.cfg.log == false then return end
    local day = os.date('%Y-%m-%d')
    local f = io.open(LOG_DIR .. day .. '.log', 'a')
    if not f then return end
    -- hand-rolled json: no cjson dependency (see header)
    f:write(fmt('{"time":%d,"ip":"%s","site":"%s","rule":"%s","method":"%s",' ..
                '"uri":"%s","ua":"%s","payload":"%s","status":%d}\n',
        os.time(), esc(ip), esc(site), esc(rule),
        esc(ngx.var.request_method), esc(ngx.var.request_uri),
        esc(ngx.var.http_user_agent), esc((payload or ''):sub(1, 200)), status))
    f:close()
end

-- Auto-ban bookkeeping.
--
-- The ban itself lives in the wafpro_block shared dict (TTL'd, instant, shared
-- across workers). The panel cannot read a shared dict, so every ban is also
-- appended to rule/drop_ip.log purely so the Blockade tab can show it; that
-- file is a display mirror, never the source of truth.
local function auto_ban(ip, site, rule)
    local cfg = state.cfg or {}
    local retry = tonumber(cfg.retry) or 0
    if retry <= 0 then return end                 -- feature off
    local dict = ngx.shared.wafpro_cc
    local blocked = ngx.shared.wafpro_block
    if not dict or not blocked then return end

    local cycle = tonumber(cfg.retry_cycle) or 60
    local key = 'b:' .. ip
    local n = dict:incr(key, 1)
    if not n then
        dict:set(key, 1, cycle)
        n = 1
    end
    if n < retry then return end

    local secs = tonumber(cfg.retry_time) or 600
    blocked:set(ip, ngx.time() + secs, secs)
    dict:delete(key)
    -- LOG_DIR, not RULE_DIR: rule/ is root-owned and the workers run as www,
    -- so a write there fails silently and the panel would show no bans at all.
    local f = io.open(LOG_DIR .. 'drop_ip.log', 'a')
    if f then
        f:write(fmt('%s|%d|%d|%s|%s\n', ip, ngx.time() + secs, n, esc(site), esc(rule)))
        f:close()
    end
end

-- ip is the resolved client address (honours cdn/X-Forwarded-For), not
-- necessarily remote_addr — logging the proxy's IP would make the Blockade
-- and top-attacker views useless behind a CDN.
local function deny(ip, site, rule, payload, status)
    log_block(ip, site, rule, payload, status)
    -- a banned IP's own ban hit must not feed the counter again
    if rule ~= 'banned' then
        pcall(auto_ban, ip, site, rule)
    end
    return ngx.exit(status)
end

-- ---------------- checks ----------------

local function match_any(rules, subject)
    if not subject or #rules == 0 then return nil end
    -- Resolve ngx.re at call time, never at module load: this module is first
    -- require()d from init_by_lua (master, config-parse time) where ngx.re does
    -- not exist. Caching it up top left it nil forever, so every rule silently
    -- never matched and the engine passed all traffic.
    local re_find = ngx.re.find
    for i = 1, #rules do
        -- 'joi': jit-compile + cache the pattern, case-insensitive
        local ok, from = pcall(re_find, subject, rules[i], 'joi')
        -- a bad user-supplied pattern must not take the request down
        if ok and from then return rules[i] end
    end
    return nil
end

-- sc is the site's config: CDN is per site, since one box can host a site
-- behind Cloudflare next to one served directly. Trusting XFF on a site that
-- is NOT behind a proxy would let anyone spoof their IP.
local function client_ip(sc)
    if (sc and sc.cdn) or (state.cfg or {}).cdn then
        local xff = ngx.var.http_x_forwarded_for
        if xff then
            local first = xff:match('^%s*([^,%s]+)')
            if first and ip2int(first) then return first end
        end
        local xr = ngx.var.http_x_real_ip
        if xr and ip2int(xr) then return xr end
    end
    return ngx.var.remote_addr
end

-- Site-wide request rate over the last second, used by Smart CC and the
-- waiting room. Keyed per second so the bucket expires on its own.
local function site_rate(site)
    local dict = ngx.shared.wafpro_cc
    if not dict then return 0 end
    local key = 'r:' .. site .. ':' .. ngx.time()
    local n = dict:incr(key, 1)
    if not n then
        dict:set(key, 1, 2)
        return 1
    end
    return n
end

-- Smart CC: a fixed per-IP limit is either too loose in a flood or too tight on
-- a busy day. When the whole site is above smart_at req/s, every visitor's
-- allowance is tightened (down to a quarter at 4x the threshold), and it
-- relaxes on its own once the surge passes.
local function effective_cc_limit(sc, rate)
    if not sc.smart_cc then return sc.cc_limit, false end
    local at = tonumber(state.cfg.smart_at) or 50
    if rate <= at then return sc.cc_limit, false end
    local over = rate / at
    local div = over >= 4 and 4 or (over >= 2 and 2 or 1.5)
    local lim = floor(sc.cc_limit / div)
    if lim < 5 then lim = 5 end
    return lim, true
end

local function cc_check(site, sc, ip, rate)
    local dict = ngx.shared.wafpro_cc
    if not dict then return end
    local blocked = ngx.shared.wafpro_block
    if blocked and blocked:get(ip) then
        return deny(ip, site, 'cc-blocked', 'rate limit', tonumber(state.cfg.cc_status) or 444)
    end
    local key = ip .. '|' .. site
    local n = dict:incr(key, 1)
    if not n then
        dict:set(key, 1, sc.cc_cycle)
        return
    end
    local limit, smart = effective_cc_limit(sc, rate)
    if n > limit then
        if blocked then blocked:set(ip, 1, sc.cc_block) end
        return deny(ip, site, smart and 'smart-cc' or 'cc',
                    fmt('%d req / %ds (limit %d%s)', n, sc.cc_cycle, limit,
                        smart and fmt(', site at %d/s', rate) or ''),
                    tonumber(state.cfg.cc_status) or 444)
    end
end

-- Custom rules: user-defined multi-condition matching. Each rule is a set of
-- AND-conditions; if they all match, the action fires (allow = skip the rest,
-- block/code = deny). A bad regex or missing field can never take a request
-- down — the whole thing runs under pcall from waf.lua.

-- Pull the subject string for a text field from the request.
local function cust_subject(c, ctx)
    local fld = c.field
    if fld == 'method' then return ctx.method
    elseif fld == 'uri' then return ctx.uri
    elseif fld == 'uri_args' then return ctx.request_uri
    elseif fld == 'user_agent' then return ctx.ua
    elseif fld == 'referer' then return ngx.var.http_referer
    elseif fld == 'cookie' then return ngx.var.http_cookie
    elseif fld == 'args' then return ctx.args
    elseif fld == 'uri_param' then
        local a = ngx.req.get_uri_args()
        local v = a[c.extra]
        if type(v) == 'table' then v = v[1] end
        return v
    elseif fld == 'header' then
        return ngx.var['http_' .. (c.extra or ''):gsub('-', '_'):lower()]
    end
    return nil
end

-- Apply one operator. subj may be nil (field absent) — only the negative
-- operators can be true then.
local function cust_op(op, subj, val)
    if op == 'exists' then return subj ~= nil end
    if op == 'nexists' then return subj == nil end
    if subj == nil then
        -- "not equal / not contains" against a missing field is vacuously true
        return op == 'ne' or op == 'ncontains'
    end
    subj = tostring(subj)
    if op == 'eq' then return subj == val
    elseif op == 'ne' then return subj ~= val
    elseif op == 'contains' then return subj:find(val, 1, true) ~= nil
    elseif op == 'ncontains' then return subj:find(val, 1, true) == nil
    elseif op == 'prefix' then return subj:sub(1, #val) == val
    elseif op == 'suffix' then return #val <= #subj and subj:sub(-#val) == val
    elseif op == 'regex' then
        -- resolve ngx.re at call time, same reason as match_any
        local ok, m = pcall(ngx.re.find, subj, val, 'joi')
        return ok and m ~= nil
    elseif op == 'in' then
        for _, x in ipairs(split(val, ',')) do
            if subj == x:gsub('^%s+', ''):gsub('%s+$', '') then return true end
        end
        return false
    end
    return false
end

local function cust_cond(c, ctx)
    -- ip / country match against a compiled bin of ranges
    if c.field == 'ip' or c.field == 'country' then
        local hit = in_ranges(c.bin, ctx.ip)
        return (c.op == 'notmatch') and (not hit) or (c.op ~= 'notmatch' and hit)
    end
    return cust_op(c.op, cust_subject(c, ctx), c.value)
end

local function custom_check(site, ctx)
    local list = state.custom_by_site[site]
    local wild = state.custom_by_site['*']
    if not list and not wild then return end

    local function apply(rs)
        for i = 1, #rs do
            local r = rs[i]
            local all = true
            for j = 1, #r.conds do
                if not cust_cond(r.conds[j], ctx) then all = false; break end
            end
            if all and #r.conds > 0 then
                if r.action == 'allow' then
                    ctx.allow = true
                    return true                     -- whitelist: stop, let it through
                end
                local st = (r.action == 'code') and r.status or (tonumber(state.cfg.custom_status) or 403)
                return deny(ctx.ips, site, 'custom:' .. r.id, 'custom rule', st)
            end
        end
    end
    if list and apply(list) then return true end
    if wild and apply(wild) then return true end
end

-- Traffic limit: rate-limit a specific URL per IP (or per IP+UA). Lowest
-- priority by design (checked last) and meant for API endpoints, not whole
-- sites — a per-second cap that either returns a status code or blocks the IP.
local function traffic_check(site, ips, ip, uri, ua)
    local list = state.traffic_by_site[site]
    local wild = state.traffic_by_site['*']
    if not list and not wild then return end
    local dict = ngx.shared.wafpro_cc
    if not dict then return end
    local now = ngx.time()

    local function apply(rs)
        for i = 1, #rs do
            local r = rs[i]
            if match_any({ r.url }, uri) then
                local key = 't:' .. r.id .. ':' .. ip
                if r.dim == 'ipua' then key = key .. ':' .. (ua and #ua > 0 and ua or '-') end
                key = key .. ':' .. now
                local n = dict:incr(key, 1)
                if not n then dict:set(key, 1, 2); n = 1 end
                if n > r.rate then
                    if r.action == 'block' then
                        local blocked = ngx.shared.wafpro_block
                        if blocked then blocked:set(ips, now + 600, 600) end
                        return deny(ips, site, 'traffic-block',
                                    fmt('%s %d/s > %d', r.url, n, r.rate),
                                    tonumber(state.cfg.black_status) or 444)
                    end
                    return deny(ips, site, 'traffic',
                                fmt('%s %d/s > %d', r.url, n, r.rate), r.status)
                end
            end
        end
    end
    if list then apply(list) end
    if wild then apply(wild) end
end

-- Crawl protection: bots that are not verified crawlers get their own, much
-- tighter budget. They are not blocked outright — plenty are harmless — they
-- just do not get to hammer the site.
local function crawl_check(site, sc, ip, ua)
    if not ua or not state.crawl_ua then return end
    if not match_any({ state.crawl_ua }, ua) then return end
    local dict = ngx.shared.wafpro_cc
    if not dict then return end
    local key = 'w:' .. ip .. '|' .. site
    local n = dict:incr(key, 1)
    if not n then
        dict:set(key, 1, 60)
        return
    end
    if n > sc.crawl_limit then
        return deny(ip, site, 'crawl', fmt('%d req/min (limit %d)', n, sc.crawl_limit),
                    tonumber(state.cfg.crawl_status) or 429)
    end
end

-- Waiting room: past wait_limit req/s the site would fall over anyway, so the
-- overflow gets a friendly retry page instead of a timeout or a 502.
local function wait_check(site, sc, ip, rate)
    if rate <= sc.wait_limit then return end
    log_block(ip, site, 'waiting-room', fmt('site at %d/s (limit %d)', rate, sc.wait_limit), 503)
    ngx.header['Content-Type'] = 'text/html; charset=utf-8'
    ngx.header['Retry-After'] = '5'
    ngx.status = 503
    ngx.say(state.wait_html or '<h1>Please wait</h1><p>The site is busy. Retrying shortly.</p>')
    return ngx.exit(503)
end

function _M.access()
    local cfg = state.cfg
    if not cfg or cfg.open == false then return end

    local host = ngx.var.host
    if not host then return end
    host = host:lower():gsub(':%d+$', '')

    local sc = state.sites[host]
    if not sc then return end          -- site not managed by us
    if not sc.open then return end

    local ips = client_ip(sc)
    local ip = ip2int(ips)

    -- ipv6 / unparseable: nothing we can decide on, let it through
    if not ip then return end

    -- loopback + LAN always reachable, before any rule can bite
    if in_ranges(state.lan, ip) then return end
    if in_ranges(state.ip_white, ip) then return end
    if in_ranges(state.ip_black, ip) then
        return deny(ips, host, 'ip-black', ips, tonumber(cfg.black_status) or 444)
    end

    -- auto-banned (tripped too many rules recently)
    local blocked = ngx.shared.wafpro_block
    if blocked and blocked:get(ips) then
        return deny(ips, host, 'banned', ips, tonumber(cfg.black_status) or 444)
    end

    -- known-malicious IP feed
    if cfg.mal_open and in_ranges(state.mal, ip) then
        return deny(ips, host, 'malicious-ip', ips, tonumber(cfg.black_status) or 444)
    end

    local uri = ngx.var.request_uri or ngx.var.uri or ''

    -- explicit allow: skip every check below for this path
    if match_any(state.url_white, uri) then return end

    -- custom rules: user-defined, evaluated before the built-in filters so a
    -- custom allow can whitelist and a custom block can pre-empt them.
    if state.custom_by_site[host] or state.custom_by_site['*'] then
        local ctx = {
            ip = ip, ips = ips,
            method = ngx.var.request_method,
            uri = ngx.var.uri or '',
            request_uri = uri,
            args = ngx.var.args,
            ua = ngx.var.http_user_agent,
        }
        if custom_check(host, ctx) then
            if ctx.allow then return end          -- matched an allow rule
            return                                -- deny already exited; belt & braces
        end
    end

    -- request method
    if next(state.methods) and not state.methods[(ngx.var.request_method or ''):lower()] then
        return deny(ips, host, 'method', ngx.var.request_method,
                    tonumber(cfg.method_status) or 405)
    end

    -- oversized headers (buffer-overflow probes, cache poisoning)
    for i = 1, #state.hdr_limits do
        local L = state.hdr_limits[i]
        local v = ngx.var['http_' .. L.h:gsub('-', '_')]
        if v and #v > L.max then
            return deny(ips, host, 'header', L.h .. ' (' .. #v .. 'B)',
                        tonumber(cfg.header_status) or 403)
        end
    end

    -- url blacklist
    local hit = match_any(state.url_black, uri)
    if hit then return deny(ips, host, 'url-black', uri, tonumber(cfg.black_status) or 444) end

    -- extensions the site must never serve directly
    if next(sc.deny_ext) then
        local ext = (ngx.var.uri or ''):lower():match('%.([%w]+)$')
        if ext and sc.deny_ext[ext] then
            return deny(ips, host, 'deny-ext', ext, tonumber(cfg.black_status) or 444)
        end
    end

    -- no PHP execution under these paths (upload dirs etc)
    if #sc.php_path > 0 then
        local path = (ngx.var.uri or ''):lower()
        if path:find('.php', 1, true) then
            for i = 1, #sc.php_path do
                if path:find(sc.php_path[i], 1, true) == 1 then
                    return deny(ips, host, 'php-path', path, tonumber(cfg.black_status) or 444)
                end
            end
        end
    end

    -- region
    local function region_apply(rs)
        if not rs then return end
        for i = 1, #rs do
            local r = rs[i]
            local hit = in_ranges(r.ranges, ip)
            -- intercept: listed areas blocked. pass: only listed get through.
            if (r.typ == 'intercept' and hit) or (r.typ == 'pass' and not hit) then
                return deny(ips, host, 'region:' .. r.typ, ips, r.status)
            end
        end
    end
    region_apply(state.region_by_site[host])
    region_apply(state.region_by_site['*'])

    -- fake spider: claims to be a search engine but is not crawling from the
    -- IPs that engine publishes. Real crawlers are let through untouched.
    if sc.fake_spider and state.spider and state.spider_ua then
        local ua = ngx.var.http_user_agent
        if ua and match_any({ state.spider_ua }, ua) then
            if in_ranges(state.spider, ip) then
                return                       -- verified crawler: skip the rest
            end
            return deny(ips, host, 'fake-spider', ua, tonumber(cfg.ua_status) or 403)
        end
    end

    -- user-agent
    if sc.ua then
        local ua = ngx.var.http_user_agent
        local hit = match_any(state.r_ua, ua)
        if hit then return deny(ips, host, 'user-agent', ua, tonumber(cfg.ua_status) or 403) end
    end

    -- scanner paths
    if sc.scan then
        local hit = match_any(state.r_scan, uri)
        if hit then return deny(ips, host, 'scan', uri, tonumber(cfg.scan_status) or 444) end
    end

    -- query string
    if sc.get then
        local args = ngx.var.args
        if args then
            local dec = ngx.unescape_uri(args)
            local hit = match_any(state.r_get, dec)
            if hit then return deny(ips, host, 'get', dec, tonumber(cfg.get_status) or 403) end
        end
    end

    -- cookie
    if sc.cookie then
        local ck = ngx.var.http_cookie
        local hit = match_any(state.r_cookie, ck)
        if hit then return deny(ips, host, 'cookie', ck, tonumber(cfg.cookie_status) or 403) end
    end

    -- body
    if ngx.var.request_method == 'POST' then
        local ct = ngx.var.content_type or ''
        if sc.post and ct:find('application/x%-www%-form%-urlencoded') then
            ngx.req.read_body()
            local body = ngx.req.get_body_data()
            if body then
                local dec = ngx.unescape_uri(body)
                local h2 = match_any(state.r_post, dec)
                if h2 then return deny(ips, host, 'post', dec, tonumber(cfg.post_status) or 403) end
            end
        end

        -- upload extension filter
        --
        -- Only the filename= parts of a multipart header are inspected, never
        -- the file bodies: reading those would mean buffering every upload
        -- through lua. ngx.req.get_body_data() returns nil once nginx spills a
        -- large body to disk, which is exactly when we still want to catch a
        -- webshell — so the raw body is read from the temp file in that case.
        if next(sc.upload_ext) and ct:find('multipart/form%-data') then
            ngx.req.read_body()
            local body = ngx.req.get_body_data()
            if not body then
                local fp = ngx.req.get_body_file()
                if fp then
                    local f = io.open(fp, 'rb')
                    if f then
                        -- headers live at the front; cap the read so a big
                        -- upload cannot pull megabytes into memory
                        body = f:read(65536)
                        f:close()
                    end
                end
            end
            if body then
                for name in body:gmatch('filename="([^"]+)"') do
                    local ext = name:lower():match('%.([%w]+)%s*$')
                    if ext and sc.upload_ext[ext] then
                        return deny(ips, host, 'upload-ext', name,
                                    tonumber(cfg.post_status) or 403)
                    end
                end
            end
        end
    end

    -- sensitive words: forbidden strings/regex anywhere in the request line or
    -- urlencoded body. Global (not per site) — a leak/keyword blocklist.
    if #state.sensitive > 0 then
        local hay = uri
        if ngx.var.request_method == 'POST' then
            local ct = ngx.var.content_type or ''
            if ct:find('application/x%-www%-form%-urlencoded') then
                ngx.req.read_body()
                local b = ngx.req.get_body_data()
                if b then hay = hay .. ' ' .. ngx.unescape_uri(b) end
            end
        end
        local hit = match_any(state.sensitive, hay)
        if hit then return deny(ips, host, 'sensitive', hit, tonumber(cfg.black_status) or 444) end
    end

    -- rate-driven checks last: only clean requests count toward them.
    -- static assets are exempt from CC (config switch) — a page loads many.
    local skip_cc = state.cfg.static_protect ~= true and is_static(ngx.var.uri or '')
    local rate = (sc.cc_open or sc.wait or sc.smart_cc) and site_rate(host) or 0
    if sc.wait then wait_check(host, sc, ips, rate) end
    if sc.crawl then crawl_check(host, sc, ips, ngx.var.http_user_agent) end
    if sc.cc_open and not skip_cc then cc_check(host, sc, ips, rate) end

    -- traffic limit last of all — lowest priority, per the UI note
    traffic_check(host, ips, ip, uri, ngx.var.http_user_agent)
end

return _M

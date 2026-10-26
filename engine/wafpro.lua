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
-- |   rule/domains.txt  host -> site name (panel site names are not hosts)
-- |   rule/r_*.txt      one regex per line
-- |   rule/*.bin        packed sorted IPv4 ranges (8B/range), binary-searched
-- |   rule/*.bin6       packed sorted IPv6 ranges (32B/range), same idea
-- |   rule/version      bumped on every change -> workers resync, no reload
-- +-------------------------------------------------------------------
local _M = { _VERSION = '2.1' }

local RULE_DIR = '/www/server/wafpro/rule/'
local LOG_DIR = '/www/wwwlogs/wafpro/'

local floor = math.floor
local byte = string.byte
local char = string.char
local fmt = string.format
local concat = table.concat

local state = { version = -1 }

-- CC counting skips these: a page pulls dozens of them and they are not the
-- attack surface. Matches btwaf's default static exemption.
local STATIC_EXT = {
    js=true, css=true, png=true, jpg=true, jpeg=true, gif=true, webp=true,
    svg=true, ico=true, woff=true, woff2=true, ttf=true, eot=true, mp4=true,
    webm=true, mp3=true, pdf=true, map=true, avif=true, mjs=true,
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

-- "a:b::c" -> 16-byte big-endian string, or nil. Kept as a string because
-- LuaJIT compares strings bytewise (memcmp), which is exactly numeric order
-- for fixed-width big-endian values — no bignum needed for 128 bits.
local function hexwords(s)
    local t = {}
    if s == '' then return t end
    for w in (s .. ':'):gmatch('([^:]*):') do
        if not w:match('^%x%x?%x?%x?$') then return nil end
        t[#t + 1] = tonumber(w, 16)
    end
    return t
end

local function ip6bin(ip)
    if not ip or not ip:find(':', 1, true) then return nil end
    ip = ip:gsub('%%.*$', '')                 -- drop a zone id (fe80::1%eth0)
    -- trailing dotted quad (::ffff:1.2.3.4) -> two hex words
    local head, v4 = ip:match('^(.*:)(%d+%.%d+%.%d+%.%d+)$')
    if v4 then
        local n = ip2int(v4)
        if not n then return nil end
        ip = head .. fmt('%x:%x', floor(n / 65536), n % 65536)
    end
    local parts
    local l, r = ip:match('^(.-)::(.*)$')
    if l then
        local a, b = hexwords(l), hexwords(r)
        if not a or not b then return nil end
        local fill = 8 - #a - #b
        if fill < 1 then return nil end
        parts = a
        for _ = 1, fill do parts[#parts + 1] = 0 end
        for i = 1, #b do parts[#parts + 1] = b[i] end
    else
        parts = hexwords(ip)
        if not parts or #parts ~= 8 then return nil end
    end
    local out = {}
    for i = 1, 8 do out[i] = char(floor(parts[i] / 256), parts[i] % 256) end
    return concat(out)
end
_M.ip6bin = ip6bin

-- Canonical text for a 16-byte address, matching Python's ipaddress str()
-- (lowercase, no leading zeros, longest run of 2+ zero words as '::').
-- Bans, logs and the panel all key on this, so two spellings of one address
-- cannot dodge a ban.
local function ip6text(bin)
    local w = {}
    for i = 0, 7 do
        local a, b = byte(bin, i * 2 + 1, i * 2 + 2)
        w[i + 1] = a * 256 + b
    end
    local best, best_len, cur, cur_len = 0, 0, 0, 0
    for i = 1, 8 do
        if w[i] == 0 then
            if cur_len == 0 then cur = i end
            cur_len = cur_len + 1
            if cur_len > best_len then best, best_len = cur, cur_len end
        else
            cur_len = 0
        end
    end
    local hex = {}
    for i = 1, 8 do hex[i] = fmt('%x', w[i]) end
    if best_len < 2 then return concat(hex, ':') end
    local left = concat(hex, ':', 1, best - 1)
    local right = (best + best_len <= 8) and concat(hex, ':', best + best_len, 8) or ''
    return left .. '::' .. right
end
_M.ip6text = ip6text

local V4_MAPPED = string.rep('\0', 10) .. '\255\255'

-- Any textual address -> (kind, numeric key, canonical text).
--   kind 4: key is a number;  kind 6: key is a 16-byte string.
-- IPv4-mapped IPv6 collapses to plain IPv4 so the v4 lists still apply.
local function parse_ip(s)
    if not s or s == '' then return nil end
    local n = ip2int(s)
    if n then return 4, n, s end
    local b = ip6bin(s)
    if not b then return nil end
    if b:sub(1, 12) == V4_MAPPED then
        local a, c, d, e = byte(b, 13, 16)
        local v4 = a * 16777216 + c * 65536 + d * 256 + e
        return 4, v4, fmt('%d.%d.%d.%d', a, c, d, e)
    end
    return 6, b, ip6text(b)
end
_M.parse_ip = parse_ip

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

-- Same search over 32-byte [start16,end16] records.
local function in_ranges6(buf, ip)
    if not buf or #buf < 32 then return false end
    local lo, hi = 0, floor(#buf / 32) - 1
    while lo <= hi do
        local mid = floor((lo + hi) / 2)
        local off = mid * 32
        if ip < buf:sub(off + 1, off + 16) then
            hi = mid - 1
        elseif ip > buf:sub(off + 17, off + 32) then
            lo = mid + 1
        else
            return true
        end
    end
    return false
end
_M.in_ranges6 = in_ranges6

-- One lookup for "is the client in list X", whatever its family.
-- set = { v4 = <bin>, v6 = <bin6> }
local function in_set(set, c)
    if not set then return false end
    if c.kind == 4 then return in_ranges(set.v4, c.key) end
    return in_ranges6(set.v6, c.key)
end

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

-- One site per line: name<TAB>key=value<TAB>key=value...
--
-- Named fields, not columns: the old positional format silently shifted
-- every switch one column the day a field was added, and nothing noticed.
-- Values never contain a tab (the panel strips them).
local SITE_NUM = { cc_limit = 120, cc_cycle = 60, cc_block = 600, crawl_limit = 30,
                   wait_limit = 200, body_max = 0 }
local SITE_SET = { deny_ext = true, upload_ext = true }
local SITE_LIST = { php_path = true }
local SITE_STR = { cc_mode = 'block' }

local function parse_sites(path)
    local t = {}
    for _, line in ipairs(read_lines(path)) do
        local f = split(line, '\t')
        local name = f[1]
        if name and name ~= '' then
            local sc = { name = name }
            for k, v in pairs(SITE_NUM) do sc[k] = v end
            for k, v in pairs(SITE_STR) do sc[k] = v end
            for k in pairs(SITE_SET) do sc[k] = {} end
            for k in pairs(SITE_LIST) do sc[k] = {} end
            for i = 2, #f do
                local k, v = f[i]:match('^([%w_]+)=(.*)$')
                if k then
                    -- parsed once here, not per request
                    if SITE_NUM[k] then sc[k] = tonumber(v) or SITE_NUM[k]
                    elseif SITE_SET[k] then sc[k] = parse_set(v)
                    elseif SITE_LIST[k] then sc[k] = split_clean(v)
                    elseif SITE_STR[k] then sc[k] = v
                    else sc[k] = (v == '1') end
                end
            end
            t[name] = sc
        end
    end
    return t
end

-- Per-site lists, one entry per line: type|site|a|b|c   ('|' and '%' in
-- values are percent-encoded by the panel).
--   dpath|site|regex                      forbidden URL
--   leech|site|exts|domains|allow_empty   anti-hotlink
--   purl|site|path_regex|param|value      protected URL (needs ?param=value)
--   api|site|path_regex|methods|per_min   API defense
--   repl|site|from|to                     response content replace
local function pdec(v)
    return (v or ''):gsub('%%7C', '|'):gsub('%%09', '\t'):gsub('%%25', '%%')
end
local function parse_site_rules(path)
    local out = {}
    for _, line in ipairs(read_lines(path)) do
        local f = split(line, '|')
        local typ, site = f[1], f[2]
        if typ and site and site ~= '' then
            local s = out[site]
            if not s then
                s = { dpath = {}, leech = {}, purl = {}, api = {}, repl = {} }
                out[site] = s
            end
            if typ == 'dpath' then
                s.dpath[#s.dpath + 1] = pdec(f[3])
            elseif typ == 'leech' then
                s.leech[#s.leech + 1] = { exts = parse_set(pdec(f[3])),
                                          domains = split_clean(pdec(f[4])),
                                          allow_empty = f[5] == '1' }
            elseif typ == 'purl' then
                s.purl[#s.purl + 1] = { path = pdec(f[3]), param = pdec(f[4]), value = pdec(f[5]) }
            elseif typ == 'api' then
                s.api[#s.api + 1] = { id = #s.api + 1, path = pdec(f[3]),
                                      methods = parse_set(pdec(f[4])),
                                      per_min = tonumber(f[5]) or 0 }
            elseif typ == 'repl' then
                local from = pdec(f[3])
                if from ~= '' then s.repl[#s.repl + 1] = { from = from, to = pdec(f[4]) } end
            end
        end
    end
    return out
end

-- host|site per line. "*.example.com" entries are suffix matches.
--
-- The panel's site name is NOT always a host: Node/Python/Go projects are
-- named after the project ("market", "server") and every site can carry
-- extra domains. Keying the lookup on the raw Host header used to leave all
-- of those completely unprotected.
local function parse_domains(path)
    local exact, wild = {}, {}
    for _, line in ipairs(read_lines(path)) do
        local h, site = line:match('^([^|]+)|(.+)$')
        if h then
            h = h:lower()
            if h:sub(1, 2) == '*.' then
                wild[#wild + 1] = { suffix = h:sub(2), site = site }
            else
                exact[h] = site
            end
        end
    end
    -- longest suffix first, so a.b.example.com beats example.com
    table.sort(wild, function(a, b) return #a.suffix > #b.suffix end)
    return exact, wild
end

-- The same file, inverted: site -> its own hosts. Anti-leech always trusts
-- a site's own domains as referers.
local function parse_site_domains(path)
    local t = {}
    for _, line in ipairs(read_lines(path)) do
        local h, site = line:match('^([^|]+)|(.+)$')
        if h then
            local l = t[site]
            if not l then l = {}; t[site] = l end
            l[#l + 1] = h:lower()
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
                -- extra = bin filename; ip conditions may also carry v6 ranges
                c.set = { v4 = read_all(RULE_DIR .. c.extra),
                          v6 = read_all(RULE_DIR .. c.extra .. '6') }
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

-- ip|unix-time per line: lift bans that STARTED before that moment. A bare
-- "ip" kept forever (the old format) re-lifted every later ban of the same
-- address on each settings save.
local function parse_unban(path)
    local t = {}
    for _, line in ipairs(read_lines(path)) do
        local ip, ts = line:match('^([^|]+)|(%d+)$')
        if ip then t[#t + 1] = { ip = ip, ts = tonumber(ts) } end
    end
    return t
end

local function ipset(name)
    return { v4 = read_all(RULE_DIR .. name .. '.bin'),
             v6 = read_all(RULE_DIR .. name .. '.bin6') }
end

function _M.load()
    local cfg = parse_kv(RULE_DIR .. 'config.txt')
    local region, region_by_site = parse_region(RULE_DIR .. 'region.txt')
    local traffic, traffic_by_site = parse_traffic(RULE_DIR .. 'traffic.txt')
    local custom, custom_by_site = parse_custom(RULE_DIR .. 'custom.txt')
    local dom_exact, dom_wild = parse_domains(RULE_DIR .. 'domains.txt')
    state = {
        version = tonumber(read_all(RULE_DIR .. 'version') or '') or 0,
        cfg = cfg,
        sites = parse_sites(RULE_DIR .. 'sites.txt'),
        dom_exact = dom_exact,
        dom_wild = dom_wild,
        region = region,
        region_by_site = region_by_site,
        traffic = traffic,
        traffic_by_site = traffic_by_site,
        custom = custom,
        custom_by_site = custom_by_site,
        lan = ipset('lan'),
        -- this server's own addresses: SSR apps (Nuxt/Next) call their own
        -- public hostname from here, and banning that is what took dynamic
        -- pages down with 503s
        self_ip = ipset('self'),
        ip_white = ipset('ip_white'),
        ip_black = ipset('ip_black'),
        r_get = read_lines(RULE_DIR .. 'r_get.txt'),
        r_post = read_lines(RULE_DIR .. 'r_post.txt'),
        r_cookie = read_lines(RULE_DIR .. 'r_cookie.txt'),
        r_ua = read_lines(RULE_DIR .. 'r_ua.txt'),
        r_scan = read_lines(RULE_DIR .. 'r_scan.txt'),
        r_nday = read_lines(RULE_DIR .. 'r_nday.txt'),
        url_white = read_lines(RULE_DIR .. 'url_white.txt'),
        url_black = read_lines(RULE_DIR .. 'url_black.txt'),
        url_keyword = read_lines(RULE_DIR .. 'url_keyword.txt'),
        site_rules = parse_site_rules(RULE_DIR .. 'site_rules.txt'),
        site_domains = parse_site_domains(RULE_DIR .. 'domains.txt'),
        secret = (read_lines(RULE_DIR .. 'secret.txt'))[1] or 'wafpro',
        block_html = read_all(RULE_DIR .. 'block.html'),
        challenge_html = read_all(RULE_DIR .. 'challenge.html'),
        ua_white = read_lines(RULE_DIR .. 'ua_white.txt'),
        ua_black = read_lines(RULE_DIR .. 'ua_black.txt'),
        sensitive = read_lines(RULE_DIR .. 'sensitive.txt'),
        methods = parse_set(cfg.methods),
        hdr_limits = parse_hdr_limits(RULE_DIR .. 'hdr_limits.txt'),
        spider = ipset('spider'),
        spider_ua = (read_lines(RULE_DIR .. 'spider_ua.txt'))[1],
        mal = ipset('malicious'),
        idc = ipset('idc'),
        crawl_ua = (read_lines(RULE_DIR .. 'crawl_ua.txt'))[1],
        wait_html = read_all(RULE_DIR .. 'waiting.html'),
        unban = parse_unban(RULE_DIR .. 'unban.txt'),
        test_token = (read_lines(RULE_DIR .. 'test_token.txt'))[1],
    }
end

-- Workers report what they actually run, so the panel can tell "saved" from
-- "enforced". rule/ is root-owned (workers run as www), so this goes to the
-- log dir. Written on every resync that changes something, plus a heartbeat.
local last_beat = 0
local function heartbeat(force)
    local now = ngx.time()
    if not force and now - last_beat < 30 then return end
    last_beat = now
    local f = io.open(LOG_DIR .. 'engine.status', 'w')
    if f then
        f:write(fmt('%d|%d|%s\n', state.version or -1, now, _M._VERSION))
        f:close()
    end
end

-- The panel bumps rule/version on every change; workers poll it. This is why
-- saving a setting here does not need an nginx reload.
function _M.refresh()
    local ver = tonumber(read_all(RULE_DIR .. 'version') or '')
    if not ver or ver == state.version then
        heartbeat(false)
        return
    end
    _M.load()
    -- A ban lives in the shared dict, which the panel cannot touch. So "unban"
    -- is a list the panel writes; each worker drops those keys from its dict
    -- on the next resync. Runs in the worker timer only — ngx.shared is not
    -- usable from every phase load() may be called in.
    local blocked = ngx.shared.wafpro_block
    if blocked then
        for _, u in ipairs(state.unban) do
            local started = blocked:get(u.ip)
            if started and (tonumber(started) or 0) <= u.ts then blocked:delete(u.ip) end
        end
    end
    heartbeat(true)
end

-- ---------------- logging ----------------

local function esc(s)
    if not s then return '' end
    return tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('[%c]', ' ')
end

-- A banned client keeps hammering; logging every one of those requests turns
-- a flood into a disk-write storm. Repeat hits of these rules are logged at
-- most once per IP per window.
local QUIET_RULES = { ['banned'] = true, ['cc-blocked'] = true, ['ip-black'] = true,
                      ['malicious-ip'] = true, ['challenge'] = true }

local function log_block(ip, site, rule, payload, status)
    if state.cfg and state.cfg.log == false then return end
    if QUIET_RULES[rule] then
        local dict = ngx.shared.wafpro_cc
        if dict then
            local ok = dict:add('q:' .. rule .. ':' .. ip, 1, 10)
            if not ok then return end
        end
    end
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

-- Put an IP in the ban dict. The value is the moment the ban started (so a
-- later unban can tell old bans from new ones); the TTL is its length.
-- Every ban is mirrored to drop_ip.log purely so the Blockade tab can show
-- and lift it — the panel cannot read a shared dict. LOG_DIR, not RULE_DIR:
-- rule/ is root-owned and the workers run as www.
local function ban(ip, secs, site, rule, hits)
    local blocked = ngx.shared.wafpro_block
    if not blocked then return end
    local now = ngx.time()
    -- repeat offenders: every ban within a day multiplies the next one,
    -- capped at a day (a one-off trip stays short, a persistent bot does not)
    if (state.cfg or {}).ban_escalate ~= false then
        local n = blocked:incr('n:' .. ip, 1)
        if not n then blocked:set('n:' .. ip, 1, 86400); n = 1 end
        secs = secs * n
        if secs > 86400 then secs = 86400 end
    end
    blocked:set(ip, now, secs)
    local f = io.open(LOG_DIR .. 'drop_ip.log', 'a')
    if f then
        f:write(fmt('%s|%d|%d|%s|%s|%d\n', ip, now + secs, hits or 0, esc(site), esc(rule), now))
        f:close()
    end
end

-- Auto-ban bookkeeping: too many blocks inside retry_cycle -> banned.
local function auto_ban(ip, site, rule)
    local cfg = state.cfg or {}
    local retry = tonumber(cfg.retry) or 0
    if retry <= 0 then return end                 -- feature off
    local dict = ngx.shared.wafpro_cc
    if not dict then return end

    local cycle = tonumber(cfg.retry_cycle) or 60
    local key = 'b:' .. ip
    local n = dict:incr(key, 1)
    if not n then
        dict:set(key, 1, cycle)
        n = 1
    end
    if n < retry then return end
    dict:delete(key)
    ban(ip, tonumber(cfg.retry_time) or 600, site, rule, n)
end

-- ip is the resolved client address (honours cdn/X-Forwarded-For), not
-- necessarily remote_addr — logging the proxy's IP would make the Blockade
-- and top-attacker views useless behind a CDN.
local FRIENDLY = {
    get = 'Malicious request parameters', post = 'Malicious request body',
    cookie = 'Malicious cookie', scan = 'Scanner probe', ['user-agent'] = 'Blocked client',
    php2shell = 'Unsafe upload request', ['form-data'] = 'Malformed upload request',
}

-- 444 closes the connection, so a page only makes sense for real statuses.
-- The page is the panel's template with a few {placeholders}; values are
-- escaped since the rule payload is attacker text.
local function html_esc(s)
    return (tostring(s or ''):gsub('[&<>"\']', { ['&'] = '&amp;', ['<'] = '&lt;', ['>'] = '&gt;',
                                                ['"'] = '&quot;', ["'"] = '&#39;' }))
end
local function block_page(ip, rule, status)
    local tpl = state.block_html
    if not tpl or tpl == '' or status == 444 or (state.cfg or {}).block_page == false then
        return ngx.exit(status)
    end
    local key = rule:match('^[^:]+') or rule
    local body = tpl:gsub('{(%w+)}', {
        ip = html_esc(ip), status = tostring(status),
        rule = html_esc(FRIENDLY[key] or 'Request blocked by the firewall'),
        time = os.date('%Y-%m-%d %H:%M:%S'),
        id = ngx.var.request_id or fmt('%x', ngx.time()),
    })
    ngx.status = status
    ngx.header['Content-Type'] = 'text/html; charset=utf-8'
    ngx.header['Cache-Control'] = 'no-store'
    ngx.print(body)
    return ngx.exit(status)
end

local function deny(ip, site, rule, payload, status)
    log_block(ip, site, rule, payload, status)
    -- a banned IP's own ban hit must not feed the counter again, and the
    -- panel's self-test must not get the server's own address banned
    if rule ~= 'banned' and rule ~= 'cc-blocked' and not ngx.ctx.wafpro_testing then
        pcall(auto_ban, ip, site, rule)
    end
    if status >= 400 and status < 500 and status ~= 444 then
        return block_page(ip, rule, status)
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

-- Which managed site is this request for? Host header first (it carries
-- the real name for wildcard/alias domains), then the server block's own
-- server_name — that one cannot be spoofed and always maps for a request
-- that landed in a site's vhost.
local function resolve_site(host)
    local ex = state.dom_exact
    local s = ex[host]
    if s then return s end
    for i = 1, #state.dom_wild do
        local w = state.dom_wild[i]
        if #host > #w.suffix and host:sub(-#w.suffix) == w.suffix then return w.site end
    end
    local sn = ngx.var.server_name
    if sn and sn ~= '' and sn ~= '_' then
        sn = sn:lower()
        s = ex[sn]
        if s then return s end
        if state.sites[sn] then return sn end
    end
    if state.sites[host] then return host end
    return nil
end

-- sc is the site's config: CDN is per site, since one box can host a site
-- behind Cloudflare next to one served directly. Trusting XFF on a site that
-- is NOT behind a proxy would let anyone spoof their IP.
--
-- Behind a proxy the trustworthy entry is the one the proxy itself appended:
-- the right-most address that is not private/our own. The left-most one is
-- whatever the client chose to send.
local function client_addr(sc)
    if (sc and sc.cdn) or (state.cfg or {}).cdn then
        local cf = ngx.var.http_cf_connecting_ip
        if cf and parse_ip(cf) then return cf end
        local xff = ngx.var.http_x_forwarded_for
        if xff then
            local parts = split(xff, ',')
            for i = #parts, 1, -1 do
                local p = parts[i]:gsub('^%s+', ''):gsub('%s+$', '')
                local kind, key = parse_ip(p)
                if kind then
                    local c = { kind = kind, key = key }
                    if not in_set(state.lan, c) and not in_set(state.self_ip, c) then
                        return p
                    end
                end
            end
        end
        local xr = ngx.var.http_x_real_ip
        if xr and parse_ip(xr) then return xr end
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
    local key = ip .. '|' .. site
    local n = dict:incr(key, 1)
    if not n then
        dict:set(key, 1, sc.cc_cycle)
        return
    end
    local limit, smart = effective_cc_limit(sc, rate)
    if n > limit then
        dict:delete(key)
        ban(ip, sc.cc_block, site, smart and 'smart-cc' or 'cc', n)
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
        local hit = in_set(c.set, ctx.client)
        if c.op == 'notmatch' then return not hit end
        return hit
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
local function traffic_check(site, ips, uri, ua)
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
                local key = 't:' .. r.id .. ':' .. ips
                if r.dim == 'ipua' then key = key .. ':' .. (ua and #ua > 0 and ua or '-') end
                key = key .. ':' .. now
                local n = dict:incr(key, 1)
                if not n then dict:set(key, 1, 2); n = 1 end
                if n > r.rate then
                    if r.action == 'block' then
                        ban(ips, 600, site, 'traffic-block', n)
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

-- The request body, whether nginx kept it in memory or spilled it to a temp
-- file (anything past client_body_buffer_size). A spilled body used to skip
-- inspection entirely; now its first body_scan_kb are read.
local function raw_body()
    ngx.req.read_body()
    local b = ngx.req.get_body_data()
    if b then return b end
    local fp = ngx.req.get_body_file()
    if not fp then return nil end
    local f = io.open(fp, 'rb')
    if not f then return nil end
    b = f:read((tonumber((state.cfg or {}).body_scan_kb) or 1024) * 1024)
    f:close()
    return b
end

-- A JSON request body, with \uXXXX escapes for ASCII decoded.
local function json_body(ctx)
    if ctx.json_read then return ctx.json end
    ctx.json_read = true
    local ct = ngx.var.content_type or ''
    if not ct:lower():find('json', 1, true) then return nil end
    local b = raw_body()
    if not b then return nil end
    b = b:gsub('\\u00(%x%x)', function(h) return char(tonumber(h, 16)) end)
         :gsub('\\/', '/')
    ctx.json = b
    return b
end

-- Read an urlencoded POST body once per request, however many checks want it.
local function form_body(ctx)
    if ctx.body_read then return ctx.body end
    ctx.body_read = true
    if ctx.method ~= 'POST' and ctx.method ~= 'PUT' and ctx.method ~= 'PATCH' then return nil end
    local ct = ngx.var.content_type or ''
    if not ct:find('application/x%-www%-form%-urlencoded') then return nil end
    local b = raw_body()
    -- count fields on the raw body: a decoded value may contain '&'
    if b then local _, n = b:gsub('&', ''); ctx.body_fields = n + 1 end
    ctx.body = b and ngx.unescape_uri(b) or nil
    return ctx.body
end

-- ---------------- browser verification ----------------
--
-- A scripted client (curl, python-requests, most scrapers) does not run
-- JavaScript. The challenge page computes the verification cookie in JS and
-- reloads; a browser never notices beyond one quick reload. The cookie is an
-- HMAC over ip + user-agent + day, so it cannot be replayed from elsewhere.

local function verify_token(ips, ua)
    local raw = ngx.hmac_sha1(state.secret, ips .. '|' .. (ua or '') .. '|' .. os.date('%Y%m%d'))
    return (ngx.encode_base64(raw):gsub('[^%w]', ''):sub(1, 22))
end

local function verified(ips, ua)
    local c = ngx.var.cookie_wafpro_v
    return c ~= nil and c == verify_token(ips, ua)
end

-- Only top-level page loads get the challenge. XHR/fetch/API calls and
-- assets would just break — they are judged by the cookie a page load set.
local function wants_html()
    local m = ngx.var.request_method
    if m ~= 'GET' and m ~= 'HEAD' then return false end
    if ngx.var.http_x_requested_with then return false end
    local accept = ngx.var.http_accept or ''
    return accept:find('text/html', 1, true) ~= nil
end

local function challenge(ips, site, ua, reason)
    log_block(ips, site, 'challenge', reason, 200)
    -- the token travels reversed + base64'd; the page undoes that in JS
    local tok = ngx.encode_base64(verify_token(ips, ua):reverse())
    local tpl = state.challenge_html or
        '<!doctype html><meta charset="utf-8"><title>Checking your browser</title>' ..
        '<p>Checking your browser&hellip;</p><script>{script}</script>'
    local script = fmt("(function(){var t=atob('%s').split('').reverse().join('');" ..
        "document.cookie='wafpro_v='+t+'; path=/; max-age=86400; SameSite=Lax';" ..
        "setTimeout(function(){location.reload()},600)})();", tok)
    ngx.status = 200
    ngx.header['Content-Type'] = 'text/html; charset=utf-8'
    ngx.header['Cache-Control'] = 'no-store'
    ngx.print((tpl:gsub('{script}', function() return script end)))
    return ngx.exit(200)
end

-- ---------------- multipart / PHP2Shell guard ----------------
--
-- CVE-2026-109618 / CVE-2026-109619 ("PHP2Shell") are reached through PHP's
-- own multipart parser before any application code runs. PHP's advisories
-- list what a frontend can bound: bodies without a declared length, the
-- number of parts and of headers per part, field-name nesting, empty file
-- controls, and the session upload-progress field. This does NOT fix PHP —
-- updating PHP is the only complete remedy — it removes the known triggers.
--
-- The body is streamed line by line (memory or temp file), so a large
-- upload never sits in lua memory in one piece.

local function each_body_chunk(fn)
    local data = ngx.req.get_body_data()
    if data then return fn(data) end
    local fp = ngx.req.get_body_file()
    if not fp then return end
    local f = io.open(fp, 'rb')
    if not f then return end
    local limit = (tonumber(state.cfg.mp_scan_mb) or 64) * 1048576
    local seen = 0
    while seen < limit do
        local chunk = f:read(262144)
        if not chunk then break end
        seen = seen + #chunk
        local stop = fn(chunk)
        if stop then f:close(); return stop end
    end
    f:close()
end

-- returns (rule, reason) for the first violation, or nil
local function inspect_multipart(sc, ct)
    local cfg = state.cfg
    local boundary = ct:match('boundary="([^"]+)"') or ct:match('boundary=([^;%s]+)')
    if not boundary or #boundary > 200 then
        return 'form-data', 'multipart without a usable boundary'
    end
    local cl = ngx.var.content_length
    if sc.php_guard and (not cl or cl == '') then
        return 'php2shell', 'multipart body without Content-Length'
    end

    local max_parts = tonumber(cfg.mp_max_parts) or 500
    local max_hdrs = tonumber(cfg.mp_max_headers) or 16
    local max_depth = tonumber(cfg.mp_max_depth) or 10
    local max_empty = tonumber(cfg.mp_max_empty) or 50
    local progress = (cfg.mp_progress_name or 'PHP_SESSION_UPLOAD_PROGRESS'):lower()
    local delim, close = '--' .. boundary, '--' .. boundary .. '--'

    ngx.req.read_body()
    local st = { mode = 'pre', parts = 0, hdrs = 0, empty = 0, carry = '', first = true }
    local verdict, why

    local function line(l)
        if l:sub(-1) == '\r' then l = l:sub(1, -2) end
        if st.first then
            st.first = false
            -- RFC 7578: the body opens with the delimiter (an empty preamble
            -- is what every real client sends)
            if l ~= delim and l ~= '' then
                verdict, why = 'form-data', 'body does not start with the boundary'
                return true
            end
        end
        if l == delim or l == close then
            st.mode = 'hdr'; st.hdrs = 0; st.disp = false
            st.parts = st.parts + 1
            if sc.php_guard and st.parts > max_parts then
                verdict, why = 'php2shell', fmt('%d+ multipart parts', st.parts)
                return true
            end
            return
        end
        if st.mode ~= 'hdr' then return end
        if l == '' then
            if not st.disp then
                verdict, why = 'form-data', 'part without Content-Disposition'
                return true
            end
            st.mode = 'body'
            return
        end
        st.hdrs = st.hdrs + 1
        if sc.php_guard and st.hdrs > max_hdrs then
            verdict, why = 'php2shell', fmt('%d+ headers in one part', st.hdrs)
            return true
        end
        local low = l:lower()
        if low:sub(1, 20) == 'content-disposition:' then
            st.disp = true
            -- two filename= in one part: parsers disagree on which wins, the
            -- classic way to sneak shell.php past an extension check
            local _, nfn = low:gsub('filename%*?=', '')
            if nfn > 1 then
                verdict, why = 'form-data', 'several filename= in one part'
                return true
            end
            if sc.php_guard then
                local name = low:match('[;%s]name="([^"]*)"') or low:match('[;%s]name=([^;%s]+)') or ''
                if name:find(progress, 1, true) then
                    verdict, why = 'php2shell', 'session upload progress field'
                    return true
                end
                local _, depth = name:gsub('%[', '')
                if depth > max_depth then
                    verdict, why = 'php2shell', fmt('field nesting depth %d', depth)
                    return true
                end
                if low:find('filename=""', 1, true) then
                    st.empty = st.empty + 1
                    if st.empty > max_empty then
                        verdict, why = 'php2shell', fmt('%d+ empty file fields', st.empty)
                        return true
                    end
                end
            end
        end
    end

    each_body_chunk(function(chunk)
        local buf = st.carry .. chunk
        local pos = 1
        while true do
            local nl = buf:find('\n', pos, true)
            if not nl then break end
            if line(buf:sub(pos, nl - 1)) then return true end
            pos = nl + 1
        end
        st.carry = buf:sub(pos)
        -- binary file content can run for megabytes without a newline;
        -- no header line is that long, so drop it instead of buffering it
        if #st.carry > 8192 then st.carry = '' end
    end)
    if verdict then return verdict, why end
    if st.parts == 0 then return 'form-data', 'multipart body with no parts' end
    return nil
end

-- ---------------- per-site rule lists ----------------

local function referer_host()
    local r = ngx.var.http_referer
    if not r or r == '' then return nil end
    return (r:match('^%a[%w+.-]*://([^/:?#]+)') or ''):lower()
end

local function host_in(h, list)
    for i = 1, #list do
        local d = list[i]
        if h == d or (d:sub(1, 2) == '*.' and #h > #d - 1 and h:sub(-(#d - 1)) == d:sub(2)) then
            return true
        end
        -- a listed domain also covers its subdomains
        if d:sub(1, 2) ~= '*.' and #h > #d and h:sub(-(#d + 1)) == '.' .. d then return true end
    end
    return false
end

local function site_rules_check(site, sr, ctx, ips, cfg)
    local path = ctx.uri

    for i = 1, #sr.dpath do
        if match_any({ sr.dpath[i] }, path) then
            return deny(ips, site, 'deny-path', path, tonumber(cfg.black_status) or 444)
        end
    end

    if #sr.leech > 0 then
        local ext = path:lower():match('%.([%w]+)$')
        if ext then
            for i = 1, #sr.leech do
                local L = sr.leech[i]
                if L.exts[ext] then
                    local rh = referer_host()
                    if not rh then
                        if not L.allow_empty then
                            return deny(ips, site, 'hotlink', 'no referer', 403)
                        end
                    elseif not host_in(rh, state.site_domains[site] or {}) and not host_in(rh, L.domains) then
                        return deny(ips, site, 'hotlink', rh, 403)
                    end
                end
            end
        end
    end

    for i = 1, #sr.purl do
        local P = sr.purl[i]
        if match_any({ P.path }, path) then
            local v = ngx.req.get_uri_args()[P.param]
            if type(v) == 'table' then v = v[1] end
            if v ~= P.value then
                return deny(ips, site, 'protected-url', path, 403)
            end
        end
    end

    for i = 1, #sr.api do
        local A = sr.api[i]
        if match_any({ A.path }, path) then
            if next(A.methods) and not A.methods[(ctx.method or ''):lower()] then
                return deny(ips, site, 'api', 'method ' .. tostring(ctx.method), 405)
            end
            if A.per_min > 0 then
                local dict = ngx.shared.wafpro_cc
                if dict then
                    local key = 'a:' .. site .. ':' .. A.id .. ':' .. ips
                    local n = dict:incr(key, 1)
                    if not n then dict:set(key, 1, 60); n = 1 end
                    if n > A.per_min then
                        return deny(ips, site, 'api', fmt('%d req/min > %d', n, A.per_min), 429)
                    end
                end
            end
        end
    end

    -- content replace happens in the body filter; remember it for this request
    if #sr.repl > 0 then ngx.ctx.wafpro_repl = sr.repl end
end

function _M.access()
    local cfg = state.cfg
    if not cfg or cfg.open == false then return end

    local host = ngx.var.host
    if not host then return end
    host = host:lower():gsub(':%d+$', ''):gsub('%.$', '')

    local site = resolve_site(host)
    if not site then return end        -- site not managed by us
    local sc = state.sites[site]
    if not sc or not sc.open then return end

    local ips = client_addr(sc)
    local kind, key, canon = parse_ip(ips)
    -- unparseable address (unix socket peer etc): nothing to decide on
    if not kind then return end
    ips = canon
    local client = { kind = kind, key = key }

    -- The self-test sends a secret header so it can be judged like a stranger
    -- even though it comes from this very server.
    local testing = state.test_token and state.test_token ~= '' and
                    ngx.var.http_x_wafpro_test == state.test_token

    -- loopback, LAN and this server itself always reachable, before any rule
    if testing then
        ngx.ctx.wafpro_testing = true
    else
        if in_set(state.lan, client) then return end
        if in_set(state.self_ip, client) then return end
    end
    if in_set(state.ip_white, client) then return end
    if in_set(state.ip_black, client) then
        return deny(ips, site, 'ip-black', ips, tonumber(cfg.black_status) or 444)
    end

    -- banned (auto-ban, CC, traffic block)
    local blocked = ngx.shared.wafpro_block
    if blocked and blocked:get(ips) then
        return deny(ips, site, 'banned', ips, tonumber(cfg.black_status) or 444)
    end

    -- known-malicious IP feed
    if cfg.mal_open and in_set(state.mal, client) then
        return deny(ips, site, 'malicious-ip', ips, tonumber(cfg.black_status) or 444)
    end

    -- datacenter (IDC) addresses: real visitors browse from home and mobile
    -- networks; cloud servers are where bots and scanners run. Verified
    -- search crawlers live in cloud ranges too, so they are let through.
    if sc.idc and in_set(state.idc, client) and not in_set(state.spider, client) then
        return deny(ips, site, 'idc', ips, tonumber(cfg.black_status) or 444)
    end

    local ua = ngx.var.http_user_agent
    -- UA whitelist (monitoring, payment callbacks...) skips everything below
    if ua and match_any(state.ua_white, ua) then return end
    if ua and match_any(state.ua_black, ua) then
        return deny(ips, site, 'ua-black', ua, tonumber(cfg.ua_status) or 403)
    end

    local uri = ngx.var.request_uri or ngx.var.uri or ''

    -- explicit allow: skip every check below for this path
    if match_any(state.url_white, uri) then return end

    local ctx = {
        client = client, ips = ips,
        method = ngx.var.request_method,
        uri = ngx.var.uri or '',
        request_uri = uri,
        args = ngx.var.args,
        ua = ua,
    }

    -- custom rules: user-defined, evaluated before the built-in filters so a
    -- custom allow can whitelist and a custom block can pre-empt them.
    if state.custom_by_site[site] or state.custom_by_site['*'] then
        if custom_check(site, ctx) then
            return                                -- allow matched; deny already exited
        end
    end

    -- request method
    if next(state.methods) and not state.methods[(ctx.method or ''):lower()] then
        return deny(ips, site, 'method', ctx.method, tonumber(cfg.method_status) or 405)
    end

    -- header floods: real clients send a few dozen
    local max_h = tonumber(cfg.max_headers) or 800
    local _, herr = ngx.req.get_headers(max_h)
    if herr == 'truncated' then
        return deny(ips, site, 'header', fmt('more than %d headers', max_h), tonumber(cfg.header_status) or 403)
    end
    local qs = ngx.var.args
    if qs then
        local _, n = qs:gsub('&', '')
        if n + 1 > (tonumber(cfg.max_params) or 8000) then
            return deny(ips, site, 'get', fmt('%d query parameters', n + 1), tonumber(cfg.get_status) or 403)
        end
    end

    -- oversized headers (buffer-overflow probes, cache poisoning)
    for i = 1, #state.hdr_limits do
        local L = state.hdr_limits[i]
        local v = ngx.var['http_' .. L.h:gsub('-', '_')]
        if v and #v > L.max then
            return deny(ips, site, 'header', L.h .. ' (' .. #v .. 'B)',
                        tonumber(cfg.header_status) or 403)
        end
    end

    -- url blacklist
    if match_any(state.url_black, uri) then
        return deny(ips, site, 'url-black', uri, tonumber(cfg.black_status) or 444)
    end

    -- URL keywords: forbidden words anywhere in the decoded request line
    if #state.url_keyword > 0 then
        local hit = match_any(state.url_keyword, ngx.unescape_uri(uri))
        if hit then return deny(ips, site, 'url-keyword', hit, tonumber(cfg.black_status) or 444) end
    end

    -- oversized bodies (uploads are exempt: those have their own limits)
    if sc.body_max > 0 then
        local cl = tonumber(ngx.var.content_length or '')
        local ct = ngx.var.content_type or ''
        if cl and cl > sc.body_max * 1024 and not ct:find('multipart/form%-data') then
            return deny(ips, site, 'http-package', fmt('%d bytes > %d KB', cl, sc.body_max), 413)
        end
    end

    local sr = state.site_rules[site]
    if sr then site_rules_check(site, sr, ctx, ips, cfg) end

    -- extensions the site must never serve directly
    if next(sc.deny_ext) then
        local ext = ctx.uri:lower():match('%.([%w]+)$')
        if ext and sc.deny_ext[ext] then
            return deny(ips, site, 'deny-ext', ext, tonumber(cfg.black_status) or 444)
        end
    end

    -- no PHP execution under these paths (upload dirs etc)
    if #sc.php_path > 0 then
        local path = ctx.uri:lower()
        if path:find('.php', 1, true) then
            for i = 1, #sc.php_path do
                if path:find(sc.php_path[i], 1, true) == 1 then
                    return deny(ips, site, 'php-path', path, tonumber(cfg.black_status) or 444)
                end
            end
        end
    end

    -- region (the country database is IPv4 only)
    if kind == 4 then
        local function region_apply(rs)
            if not rs then return end
            for i = 1, #rs do
                local r = rs[i]
                local hit = in_ranges(r.ranges, key)
                -- intercept: listed areas blocked. pass: only listed get through.
                if (r.typ == 'intercept' and hit) or (r.typ == 'pass' and not hit) then
                    return deny(ips, site, 'region:' .. r.typ, ips, r.status)
                end
            end
        end
        region_apply(state.region_by_site[site])
        region_apply(state.region_by_site['*'])
    end

    -- fake spider: claims to be a search engine but is not crawling from the
    -- IPs that engine publishes. Real crawlers are let through untouched.
    if sc.fake_spider and state.spider_ua and (state.spider.v4 or state.spider.v6) then
        if ua and match_any({ state.spider_ua }, ua) then
            if in_set(state.spider, client) then
                return                       -- verified crawler: skip the rest
            end
            return deny(ips, site, 'fake-spider', ua, tonumber(cfg.ua_status) or 403)
        end
    end

    -- user-agent
    if sc.ua then
        if match_any(state.r_ua, ua or '') then
            return deny(ips, site, 'user-agent', ua, tonumber(cfg.ua_status) or 403)
        end
    end

    -- scanner paths: matched on the path alone. Matching the raw request_uri
    -- let "/.env?x" slip past a "/\.env(/|$)" rule.
    if sc.scan then
        if match_any(state.r_scan, ngx.unescape_uri(ctx.uri)) then
            return deny(ips, site, 'scan', uri, tonumber(cfg.scan_status) or 444)
        end
    end

    -- known exploits (virtual patches): decoded request line + form body
    if sc.nday and #state.r_nday > 0 then
        local line = ngx.unescape_uri(uri):lower()
        local hit = match_any(state.r_nday, line)
        if not hit then
            local b = form_body(ctx)
            if b then hit = match_any(state.r_nday, b) end
        end
        if hit then return deny(ips, site, 'nday', hit, tonumber(cfg.get_status) or 403) end
    end

    -- query string
    if sc.get then
        local args = ngx.var.args
        if args then
            local dec = ngx.unescape_uri(args)
            if match_any(state.r_get, dec) then
                return deny(ips, site, 'get', dec, tonumber(cfg.get_status) or 403)
            end
        end
    end

    -- cookie
    if sc.cookie then
        local ck = ngx.var.http_cookie
        if match_any(state.r_cookie, ck) then
            return deny(ips, site, 'cookie', ck, tonumber(cfg.cookie_status) or 403)
        end
    end

    -- body
    if ctx.method == 'POST' or ctx.method == 'PUT' or ctx.method == 'PATCH' then
        if sc.post then
            local body = form_body(ctx)
            if body then
                if match_any(state.r_post, body) then
                    return deny(ips, site, 'post', body, tonumber(cfg.post_status) or 403)
                end
                -- a PHP/JSP file smuggled in as a base64 data: URI field
                if body:find('data:', 1, true) and
                   ngx.re.find(body, [[data:[^;,]{0,80}(php|jsp|x-httpd)[^;,]{0,40};base64,]], 'joi') then
                    return deny(ips, site, 'upload-ext', 'base64 data URI script', tonumber(cfg.post_status) or 403)
                end
                if (ctx.body_fields or 0) > (tonumber(cfg.max_params) or 8000) then
                    return deny(ips, site, 'post', fmt('%d form parameters', ctx.body_fields), tonumber(cfg.post_status) or 403)
                end
            end
            -- JSON APIs carry the same payloads; JSON escapes (\u0027 for
            -- a quote) are decoded first so they cannot hide them
            local jb = json_body(ctx)
            if jb and match_any(state.r_post, jb) then
                return deny(ips, site, 'post', jb, tonumber(cfg.post_status) or 403)
            end
        end

        -- upload extension filter
        --
        -- Only the filename= parts of a multipart header are inspected, never
        -- the file bodies: reading those would mean buffering every upload
        -- through lua. ngx.req.get_body_data() returns nil once nginx spills a
        -- large body to disk, which is exactly when we still want to catch a
        -- webshell — so the raw body is read from the temp file in that case.
        local ct = ngx.var.content_type or ''
        if (sc.php_guard or sc.form_strict) and ct:lower():find('multipart/form%-data') then
            local rule, why = inspect_multipart(sc, ct)
            if rule then
                return deny(ips, site, rule, why, tonumber(cfg.php2shell_status) or 403)
            end
        end
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
                        return deny(ips, site, 'upload-ext', name,
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
        local b = form_body(ctx)
        if b then hay = hay .. ' ' .. b end
        local hit = match_any(state.sensitive, hay)
        if hit then return deny(ips, site, 'sensitive', hit, tonumber(cfg.black_status) or 444) end
    end

    -- WebSocket upgrades are long-lived and reconnect in bursts after a deploy;
    -- they went through every filter above, but must not eat the CC budget.
    local up = ngx.var.http_upgrade
    if up and up ~= '' then return end

    local static = is_static(ctx.uri)

    -- non-browser: page loads must prove they run JavaScript. Verified search
    -- crawlers returned earlier; assets and API calls are not challenged.
    if sc.browser and not static and wants_html() and not verified(ips, ua) then
        return challenge(ips, site, ua, 'browser verification')
    end

    -- rate-driven checks last: only clean requests count toward them.
    -- static assets are exempt from CC (config switch) — a page loads many.
    local skip_cc = cfg.static_protect ~= true and static
    local rate = (sc.cc_open or sc.wait or sc.smart_cc) and site_rate(site) or 0
    if sc.wait then wait_check(site, sc, ips, rate) end
    if sc.crawl then crawl_check(site, sc, ips, ua) end
    if sc.cc_open and not skip_cc then
        -- challenge mode: a visitor that proved it is a browser gets 4x the
        -- budget, and one over the limit is asked to verify instead of banned
        if sc.cc_mode == 'challenge' then
            if verified(ips, ua) then
                local saved = sc.cc_limit
                sc = setmetatable({ cc_limit = saved * 4 }, { __index = sc })
            elseif wants_html() then
                local dict = ngx.shared.wafpro_cc
                local n = dict and dict:get(ips .. '|' .. site) or 0
                if n >= sc.cc_limit then
                    return challenge(ips, site, ua, 'cc challenge')
                end
            end
        end
        cc_check(site, sc, ips, rate)
    end

    -- traffic limit last of all — lowest priority, per the UI note
    traffic_check(site, ips, uri, ua)
end

-- ---------------- content replace (response body) ----------------
--
-- Only runs for a request whose site has replace rules (set in access), and
-- only on uncompressed HTML: everything else streams through untouched, so
-- SSE / SSR streaming / downloads are never buffered.

function _M.header_filter()
    local repl = ngx.ctx.wafpro_repl
    if not repl then return end
    local ct = ngx.header['Content-Type'] or ''
    if type(ct) == 'table' then ct = ct[1] or '' end
    local enc = ngx.header['Content-Encoding']
    if not ct:lower():find('text/html', 1, true) or (enc and enc ~= '' and enc ~= 'identity') then
        ngx.ctx.wafpro_repl = nil
        return
    end
    -- the body length changes, so the upstream's length no longer applies
    ngx.header['Content-Length'] = nil
    ngx.ctx.wafpro_buf = {}
end

local MAX_BUFFER = 4 * 1048576

function _M.body_filter()
    local buf = ngx.ctx.wafpro_buf
    if not buf then return end
    local chunk, eof = ngx.arg[1], ngx.arg[2]
    if chunk and chunk ~= '' then
        buf[#buf + 1] = chunk
        ngx.ctx.wafpro_size = (ngx.ctx.wafpro_size or 0) + #chunk
    end
    -- a page past the cap is passed on as-is rather than held in memory
    if (ngx.ctx.wafpro_size or 0) > MAX_BUFFER then
        ngx.arg[1] = concat(buf)
        ngx.ctx.wafpro_buf = nil
        return
    end
    if not eof then
        ngx.arg[1] = nil
        return
    end
    local body = concat(buf)
    for _, r in ipairs(ngx.ctx.wafpro_repl) do
        local from, to, out, pos = r.from, r.to, {}, 1
        while true do
            local s, e = body:find(from, pos, true)
            if not s then break end
            out[#out + 1] = body:sub(pos, s - 1)
            out[#out + 1] = to
            pos = e + 1
        end
        out[#out + 1] = body:sub(pos)
        body = concat(out)
    end
    ngx.arg[1] = body
    ngx.ctx.wafpro_buf = nil
end

return _M

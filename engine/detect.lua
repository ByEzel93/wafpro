-- +-------------------------------------------------------------------
-- | WAF Pro — semantic detectors
-- +-------------------------------------------------------------------
-- | Regex rules see characters; these see structure. Each detector looks
-- | at ONE parameter value (never a whole query string, which mixes
-- | unrelated fields) and asks whether it forms a working attack in the
-- | language it targets:
-- |
-- |   sqli(v)  tokenises v as SQL three times — as-is, and as if it began
-- |            inside a '...' or "..." literal (the usual injection point)
-- |            — then looks for the shapes an injection needs: breaking out
-- |            of the literal/number and continuing with logic, a comment,
-- |            UNION SELECT, a stacked statement, an ORDER BY probe.
-- |   xss(v)   finds tags/attributes that execute script, and breakouts
-- |            from an HTML attribute or a JS string.
-- |   cmdi(v)  a shell separator or substitution followed by a command.
-- |   lfi(v)   directory climbing, sensitive absolute paths, stream wrappers.
-- |
-- | Plain Lua patterns only (no ngx.re), so it is unit-testable outside
-- | nginx and has no compile cache to warm. Every detector returns the
-- | matched reason, or nil.
-- +-------------------------------------------------------------------
local _M = {}

local sub, lower, find, byte = string.sub, string.lower, string.find, string.byte
local MAX_LEN = 8192

-- ================================================================ SQL

local function set(list)
    local t = {}
    for w in list:gmatch('%S+') do t[w] = true end
    return t
end

-- statements that start a query of their own (stacked / sub-select)
local STMT = set('select insert update delete drop exec execute declare create alter truncate shutdown waitfor')
local LOGIC = set('and or xor')
local OPWORD = set('like rlike regexp is in between div mod sounds collate escape not glob')
-- structural keywords
local KEYWORD = set([[from where order group having limit offset into outfile dumpfile procedure by
    case when then else end null true false all distinct as join inner outer left right on set values
    table tables column columns database schema union asc desc]])
-- functions an attacker reaches for (time, file, error-based, fingerprinting)
local SQLFUNC = set([[sleep benchmark pg_sleep extractvalue updatexml load_file group_concat concat_ws
    char chr unhex hex ascii ord substring substr mid version database user current_user system_user
    schema_name table_name column_name dbms_pipe randomblob convert cast if ifnull nullif
    exp floor rand count md5 sha1 pg_read_file xp_cmdshell]])

local function is_space(c)
    return c == 32 or (c >= 9 and c <= 13) or c == 160
end
local function is_word(c)
    return (c >= 97 and c <= 122) or (c >= 65 and c <= 90) or (c >= 48 and c <= 57) or c == 95 or c == 36
end
local function is_digit(c) return c >= 48 and c <= 57 end

-- Tokenise s. Types:
--   s string   n number   b bareword   f function   k keyword   E statement
--   U union    & logic    o operator   v @variable  c comment
--   ( ) , ; .  punctuation
-- A string token carries .open = true when its closing quote is missing.
local function tokenize(s)
    local toks, i, n = {}, 1, #s
    local function push(t, v, extra)
        local tk = { t = t, v = v }
        if extra then tk.open = extra end
        toks[#toks + 1] = tk
    end
    while i <= n do
        local c = byte(s, i)
        if is_space(c) then
            i = i + 1
        elseif c == 39 or c == 34 or c == 96 then          -- ' " `
            local q, j, closed = c, i + 1, false
            while j <= n do
                local d = byte(s, j)
                if d == 92 then
                    j = j + 2                                -- backslash escape
                elseif d == q then
                    if byte(s, j + 1) == q then j = j + 2    -- doubled quote
                    else closed = true; break end
                else
                    j = j + 1
                end
            end
            push(q == 96 and 'b' or 's', sub(s, i + 1, j - 1), not closed)
            i = j + 1
        elseif c == 35 then                                   -- # comment
            push('c', '#'); break
        elseif c == 45 and byte(s, i + 1) == 45 then          -- -- comment
            push('c', '--'); break
        elseif c == 47 and byte(s, i + 1) == 42 then          -- /* */
            if byte(s, i + 2) == 33 then                      -- /*! code */
                i = i + 3
                while i <= n and is_digit(byte(s, i)) do i = i + 1 end
            else
                local e = find(s, '*/', i + 2, true)
                push('c', '/*')
                if not e then break end
                i = e + 2
            end
        elseif c == 42 and byte(s, i + 1) == 47 then          -- stray */
            i = i + 2
        elseif is_digit(c) or (c == 46 and is_digit(byte(s, i + 1) or 0)) then
            local j = i
            if c == 48 and (byte(s, i + 1) == 120 or byte(s, i + 1) == 88) then
                j = i + 2
                while j <= n and find(sub(s, j, j), '%x') do j = j + 1 end
            else
                while j <= n and (is_digit(byte(s, j)) or byte(s, j) == 46) do j = j + 1 end
                -- 1e5, but "1abc" is a bareword, not a number
                if j <= n and is_word(byte(s, j)) then
                    while j <= n and is_word(byte(s, j)) do j = j + 1 end
                    push('b', sub(s, i, j - 1)); i = j
                    goto continue
                end
            end
            push('n', sub(s, i, j - 1)); i = j
        elseif c == 64 then                                   -- @var / @@var
            local j = i + 1
            if byte(s, j) == 64 then j = j + 1 end
            while j <= n and (is_word(byte(s, j)) or byte(s, j) == 46) do j = j + 1 end
            push('v', sub(s, i, j - 1)); i = j
        elseif is_word(c) then
            local j = i
            while j <= n and is_word(byte(s, j)) do j = j + 1 end
            local w = lower(sub(s, i, j - 1))
            -- look past spaces/comments for "(" to spot a function call
            local k = j
            while k <= n and is_space(byte(s, k)) do k = k + 1 end
            local call = byte(s, k) == 40
            if w == 'union' then push('U', w)
            elseif LOGIC[w] then push('&', w)
            elseif OPWORD[w] then push('o', w)
            elseif call and not STMT[w] then push('f', w)
            elseif STMT[w] then push('E', w)
            elseif KEYWORD[w] then push('k', w)
            else push('b', w) end
            i = j
        else
            local two = sub(s, i, i + 1)
            if two == '||' or two == '&&' then push('&', two); i = i + 2
            elseif two == '<=' or two == '>=' or two == '<>' or two == '!=' or two == ':=' then
                if sub(s, i, i + 2) == '<=>' then push('o', '<=>'); i = i + 3
                else push('o', two); i = i + 2 end
            elseif c == 40 then push('(', '('); i = i + 1
            elseif c == 41 then push(')', ')'); i = i + 1
            elseif c == 44 then push(',', ','); i = i + 1
            elseif c == 59 then push(';', ';'); i = i + 1
            elseif c == 46 then push('.', '.'); i = i + 1
            elseif find('=<>!+-*/%^|&~', string.char(c), 1, true) then push('o', string.char(c)); i = i + 1
            else i = i + 1 end                                -- anything else: noise
        end
        ::continue::
    end
    return toks
end
_M.tokenize = tokenize

local OPERAND = { s = true, n = true, b = true, v = true, f = true, ['('] = true }

-- does the token stream from position i on look like "<operand> <op> <operand>"
-- or a function call (the right-hand side of an injected AND/OR)
local function expr_at(toks, i)
    local a = toks[i]
    if not a then return false end
    if a.t == 'f' and SQLFUNC[a.v] then return true end
    if a.t == '(' then
        local b = toks[i + 1]
        return b ~= nil and (b.t == 'E' or (OPERAND[b.t] and toks[i + 2] ~= nil and toks[i + 2].t == 'o'))
    end
    if not OPERAND[a.t] then return false end
    local o = toks[i + 1]
    if o and o.t == 'o' then
        local b = toks[i + 2]
        return b ~= nil and (OPERAND[b.t] or b.t == 'k')
    end
    -- "x' or 1 --": operand straight into a comment / end of a quoted break
    return o ~= nil and o.t == 'c'
end

-- context: 'raw' (value is the start of a SQL fragment), or "'" / '"'
-- (value was placed inside a quoted literal by the application)
local function analyze(toks, ctx)
    local nt = #toks
    if nt < 2 then return nil end
    -- anywhere: UNION [ALL|DISTINCT] SELECT
    for i = 1, nt - 1 do
        if toks[i].t == 'U' then
            for j = i + 1, math.min(i + 3, nt) do
                local t = toks[j]
                if t.t == 'E' and t.v == 'select' then return 'union select' end
                if t.t ~= 'k' and t.t ~= '(' and t.t ~= 'c' then break end
            end
        end
        -- stacked statement: "; DROP ..." / "; SELECT ..."
        if toks[i].t == ';' and toks[i + 1].t == 'E' then return 'stacked query' end
    end

    -- the value must break out of its context: a closed quoted literal (in a
    -- quoted context the first token is the tail of the app's own literal),
    -- or a number / closing parenthesis for unquoted contexts
    local first = toks[1]
    local start
    if ctx == 'raw' then
        if first.t == 'n' or first.t == ')' then start = 2
        elseif first.t == 's' and not first.open then start = 2 end
    else
        if first.t == 's' and not first.open then start = 2 end
    end
    if not start then return nil end
    local i = start
    while toks[i] and toks[i].t == ')' do i = i + 1 end      -- 1')) or ...
    local t = toks[i]
    if not t then return nil end

    if t.t == '&' then
        if expr_at(toks, i + 1) then return 'boolean injection' end
        -- "x' or 'a" with the app's own quote closing the last literal
        local a, b = toks[i + 1], toks[i + 2]
        if ctx ~= 'raw' and a and a.t == 's' and a.open and not b then return 'boolean injection' end
        if a and a.t == 'o' and a.v == 'not' and expr_at(toks, i + 2) then return 'boolean injection' end
    elseif t.t == 'c' then
        -- admin'--   : close the literal, comment out the rest of the query
        if ctx ~= 'raw' then return 'comment truncation' end
    elseif t.t == 'o' and t.v ~= '-' and t.v ~= '+' then
        -- x'='x      : the app's closing quote completes the comparison
        local a, b = toks[i + 1], toks[i + 2]
        if ctx ~= 'raw' and a and a.t == 's' and a.open and not b then return 'tautology' end
        if a and OPERAND[a.t] and b and (b.t == '&' or b.t == 'c') then return 'tautology' end
    elseif t.t == 'k' and (t.v == 'order' or t.v == 'group' or t.v == 'having' or t.v == 'procedure'
                           or t.v == 'into' or t.v == 'limit') then
        local a = toks[i + 1]
        if a and (a.t == 'k' or a.t == 'n' or a.t == 'b' or a.t == 'f' or a.t == 'o') then
            local rest = toks[i + 2]
            if ctx ~= 'raw' or (rest and rest.t == 'c') or t.v == 'into' or t.v == 'procedure' then
                return t.v .. ' injection'
            end
        end
    elseif t.t == 'f' and SQLFUNC[t.v] and ctx ~= 'raw' then
        return 'function injection'
    end
    return nil
end

-- cheap gate: no SQL syntax at all -> nothing to tokenise
local function sql_candidate(v)
    return find(v, "['\"();=#*@<>|&`]") or find(v, '%-%-') or
           find(lower(v), '%f[%w]union%f[^%w]') or find(lower(v), '%f[%w]order%s+by%f[^%w]')
end

function _M.sqli(v)
    if not v or #v < 2 then return nil end
    if #v > MAX_LEN then v = sub(v, 1, MAX_LEN) end
    if not sql_candidate(v) then return nil end
    local r = analyze(tokenize(v), 'raw')
    if r then return r end
    if find(v, "'", 1, true) then
        r = analyze(tokenize("'" .. v), "'")
        if r then return r end
    end
    if find(v, '"', 1, true) then
        r = analyze(tokenize('"' .. v), '"')
        if r then return r end
    end
    return nil
end

-- ================================================================ XSS

local EXEC_TAGS = set('script iframe frame frameset object embed applet base import vmlframe xss')
local URL_ATTRS = set('href src action formaction data xlink:href background lowsrc dynsrc poster code codebase')

local function decode_entities(s)
    s = s:gsub('&#[xX](%x+);?', function(h)
        local n = tonumber(h, 16); return (n and n < 256) and string.char(n) or ''
    end)
    s = s:gsub('&#(%d+);?', function(d)
        local n = tonumber(d); return (n and n < 256) and string.char(n) or ''
    end)
    return (s:gsub('&colon;', ':'):gsub('&tab;', '\t'):gsub('&newline;', '\n')
             :gsub('&lt;', '<'):gsub('&gt;', '>'):gsub('&quot;', '"'):gsub('&apos;', "'"))
end

-- javascript:, vbscript:, data:text/html — browsers ignore spaces and
-- control characters inside the scheme, so strip them before comparing
local function script_url(v)
    local u = lower(v):gsub('[%c%s]', '')
    return u:find('^javascript:') or u:find('^vbscript:') or u:find('^data:text/html') or
           u:find('^data:image/svg') or u:find('^livescript:')
end

local function check_attrs(tag, attrs)
    -- event handler attribute: <x onload=...>
    for name in attrs:gmatch('[%s/"\']([%a][%w_:-]*)%s*=') do
        local ln = lower(name)
        if ln:sub(1, 2) == 'on' and #ln > 3 then return 'event handler ' .. ln end
    end
    for name, val in attrs:gmatch('([%a][%w_:-]*)%s*=%s*["\']?([^%s"\'>]*)') do
        local ln = lower(name)
        if URL_ATTRS[ln] and script_url(val) then return 'script URL in ' .. ln end
        if ln == 'style' and (lower(val):find('expression', 1, true) or lower(val):find('javascript:', 1, true)) then
            return 'script in style'
        end
    end
    if tag == 'meta' and lower(attrs):find('refresh', 1, true) and lower(attrs):find('url', 1, true) then
        return 'meta refresh'
    end
    return nil
end

local function xss_candidate(v)
    return find(v, '[<>"\'`]') or find(lower(v), 'script:', 1, true) or find(v, '&#', 1, true)
end

function _M.xss(v)
    if not v or #v < 3 then return nil end
    if #v > MAX_LEN then v = sub(v, 1, MAX_LEN) end
    if not xss_candidate(v) then return nil end
    local s = decode_entities(v:gsub('%z', ''))
    local ls = lower(s)

    -- a URL parameter that is itself a script URL (href=?url=javascript:...)
    if script_url(s) then return 'script URL' end

    -- tags, including one left open at the end of the value
    for tag, attrs in s:gmatch('<%s*/?%s*([%a][%w:-]*)([^<>]*)') do
        local lt = lower(tag)
        if EXEC_TAGS[lt] then return '<' .. lt .. '>' end
        if lt == 'svg' or lt == 'math' or lt == 'style' then
            if ls:find('on%a+%s*=') or ls:find('<%s*script') or ls:find('<%s*set') or ls:find('<%s*animate')
               or ls:find('@import', 1, true) or ls:find('expression%s*%(') then
                return '<' .. lt .. '> payload'
            end
        end
        local r = check_attrs(lt, attrs)
        if r then return r end
    end

    -- breaking out of a quoted HTML attribute: " onmouseover=alert(1)
    if ls:find('["\'`][^"\'`<>]-[%s/]on%a+%s*=') then return 'attribute breakout' end
    -- breaking out of a JS string: ';alert(1);//  "-alert(1)-"
    if ls:find("[\"'`]%s*[;+%-*|&,)]+%s*[%w_.%[%]'\"]-%s*[%(=`]") then
        local tail = ls:match("[\"'`]%s*[;+%-*|&,)]+%s*(.*)$") or ''
        if tail:find('^alert') or tail:find('^prompt') or tail:find('^confirm') or tail:find('^eval') or
           tail:find('^fetch') or tail:find('^import%s*%(') or tail:find('^document[.%[]') or
           tail:find('^window[.%[]') or tail:find('^top[.%[]') or tail:find('^self[.%[]') or
           tail:find('^location') or tail:find('^settimeout') or tail:find('^function') or
           tail:find('^new%s+function') or tail:find('^constructor') then
            return 'script string breakout'
        end
    end
    return nil
end

-- ================================================================ shell

local CMDS = set([[id whoami uname cat ls wget curl nc ncat netcat bash sh zsh ksh dash python python2
    python3 perl php ruby node ping nslookup dig chmod chown rm sleep telnet ftp tftp powershell
    cmd certutil bitsadmin base64 xterm busybox socat awk sed tail head more less passwd ifconfig
    netstat ps kill crontab useradd]])

function _M.cmdi(v)
    if not v or #v < 2 then return nil end
    if #v > MAX_LEN then v = sub(v, 1, MAX_LEN) end
    if not find(v, '[;|&`$\n]') then return nil end
    local s = lower(v)
    if s:find('%${ifs}', 1) or s:find('$ifs', 1, true) then return 'IFS substitution' end
    -- $(cmd ...) and `cmd ...`
    for w in s:gmatch('%$%(%s*([%w_./-]+)') do
        if CMDS[w:match('[^/]+$')] then return 'command substitution' end
    end
    for w in s:gmatch('`%s*([%w_./-]+)[^`]*`') do
        if CMDS[w:match('[^/]+$')] then return 'command substitution' end
    end
    -- separator then a command: ;id   | cat /etc/passwd   && wget ...
    for w, after in s:gmatch('[;|&\n]+%s*([%w_./-]+)(.?)') do
        local base = w:match('[^/]+$') or w
        if CMDS[base] and (after == '' or after:find('[%s;|&<>]')) then
            return 'command after separator'
        end
    end
    return nil
end

-- ================================================================ files

local SENSITIVE = { '/etc/passwd', '/etc/shadow', '/etc/hosts', '/proc/self/', '/proc/version',
    '/var/log/', 'c:\\windows\\', 'c:/windows/', 'boot.ini', 'win.ini', 'web.config', '/.ssh/',
    'wp-config.php', '/.env', '/etc/nginx/', '/www/server/panel/' }
local WRAPPERS = { 'php://', 'file://', 'phar://', 'zip://', 'expect://', 'glob://', 'data://', 'ogg://', 'rar://', 'zlib://' }

function _M.lfi(v)
    if not v or #v < 4 then return nil end
    if #v > MAX_LEN then v = sub(v, 1, MAX_LEN) end
    if not find(v, '[./\\:]') then return nil end
    local s = lower(v):gsub('\\', '/'):gsub('%z', '')
    for _, w in ipairs(WRAPPERS) do
        if s:find(w, 1, true) then return 'stream wrapper ' .. w end
    end
    local _, ups = s:gsub('%.%.+/', '')
    if ups >= 2 then return 'directory climbing' end
    for _, p in ipairs(SENSITIVE) do
        local q = p:gsub('\\', '/')
        if s:find(q, 1, true) and (ups >= 1 or s:sub(1, 1) == '/' or s:find('^%a:/')) then
            return 'sensitive path ' .. p
        end
    end
    return nil
end

-- Run every detector over one value; first hit wins.
-- kinds: table of enabled detector names, e.g. { sqli=true, xss=true }
function _M.check(v, kinds)
    if type(v) ~= 'string' or v == '' then return nil end
    -- the common case: plain words, numbers, slugs, emails — nothing to parse
    if not find(v, '[^%w%s%.,_:@/%-]') and not find(lower(v), '%f[%w]union%f[^%w]')
       and not find(lower(v), '%f[%w]order%s+by%f[^%w]') and not find(v, '%.%./') then
        return nil
    end
    local r
    if kinds.sqli then r = _M.sqli(v); if r then return 'sqli', r end end
    if kinds.xss then r = _M.xss(v); if r then return 'xss', r end end
    if kinds.cmdi then r = _M.cmdi(v); if r then return 'cmdi', r end end
    if kinds.lfi then r = _M.lfi(v); if r then return 'lfi', r end end
    return nil
end

return _M

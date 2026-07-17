-- init_by_lua_file: runs once in the master on start/reload. Load the engine
-- ONCE here and stash it in a VM global, exactly like the stock WAF caches its
-- run function. The access phase then just calls a cached function — no dofile,
-- no per-request disk I/O, which is what was breaking WebSocket/SSR streaming.
local DIR = '/www/server/wafpro/'
-- lua_package_path cannot be declared in our conf (the panel already sets one
-- in nginx.conf's http block; a second is a duplicate directive). So extend it
-- here, once, instead.
if not package.path:find(DIR, 1, true) then
    package.path = DIR .. '?.lua;' .. package.path
end

local ok, w = pcall(require, 'wafpro')
if not ok then
    ngx.log(ngx.ERR, 'wafpro: engine not loadable: ', tostring(w))
    return
end
-- VM global: forked into every worker, read from the access/timer phases.
_G.WAFPRO = w
local ok2, err = pcall(w.load)
if not ok2 then ngx.log(ngx.ERR, 'wafpro: initial load failed: ', tostring(err)) end

-- access_by_lua_file: the request hot path. Kept as light as possible — just a
-- cached function call, no dofile / no disk I/O per request (that latency was
-- breaking Nuxt's WebSocket upgrade + SSR streaming and returning 503).
local w = _G.WAFPRO
if not w then return end          -- engine not loaded; fail open

-- Never touch WebSocket / upgrade handshakes: sitting in their access phase and
-- adding any work corrupts the upgrade. Reverse-proxied apps (Nuxt/Node/etc.)
-- rely on this, so we bail before doing anything.
local up = ngx.var.http_upgrade
if up and up ~= '' then return end

local ok, err = pcall(w.access)
if not ok and err ~= nil then
    -- ngx.exit unwinds via error(); that is not a failure worth logging
    local s = tostring(err)
    if not s:find('exit') then ngx.log(ngx.ERR, 'wafpro: access failed: ', s) end
end

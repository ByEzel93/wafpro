-- access_by_lua_file: the request hot path. Kept as light as possible — just a
-- cached function call, no dofile / no disk I/O per request.
--
-- WebSocket/Upgrade requests are NOT skipped here any more: bailing on the
-- mere presence of an Upgrade header let any request bypass the whole WAF by
-- adding one. The engine instead runs every filter on them and only keeps
-- them out of the rate counters.
local w = _G.WAFPRO
if not w then return end          -- engine not loaded; fail open

local ok, err = pcall(w.access)
if not ok and err ~= nil then
    -- ngx.exit unwinds via error(); that is not a failure worth logging
    local s = tostring(err)
    if not s:find('exit') then ngx.log(ngx.ERR, 'wafpro: access failed: ', s) end
end

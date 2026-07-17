-- access_by_lua_file: the request hot path. Always under pcall — if the engine
-- breaks, traffic passes rather than 500s.
local ok, w = pcall(dofile, '/www/server/wafpro/loader.lua')
if not ok then return end
local ok2, err = pcall(w.access)
if not ok2 and err ~= nil then
    -- ngx.exit unwinds via error(); that is not a failure worth logging
    local s = tostring(err)
    if not s:find('exit') then ngx.log(ngx.ERR, 'wafpro: access failed: ', s) end
end

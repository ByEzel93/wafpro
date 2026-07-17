-- init_worker_by_lua_file: timers only exist in workers. This poll is what
-- removes the reload requirement the stock engines have.
local RESYNC = 2
local ok, w = pcall(dofile, '/www/server/wafpro/loader.lua')
if not ok then return end
pcall(w.load)
local ok2, err = ngx.timer.every(RESYNC, function(premature)
    if premature then return end
    local ok3, e = pcall(w.refresh)
    if not ok3 then ngx.log(ngx.ERR, 'wafpro: refresh failed: ', tostring(e)) end
end)
if not ok2 then ngx.log(ngx.ERR, 'wafpro: cannot start refresh timer: ', tostring(err)) end

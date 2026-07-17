-- init_worker_by_lua_file: timers only exist in workers. This poll is what
-- removes the reload requirement the stock engines have. Uses the cached engine
-- global from init.lua — no dofile, no per-request cost (timer only).
local RESYNC = 2
local w = _G.WAFPRO
if not w then return end

local ok, err = ngx.timer.every(RESYNC, function(premature)
    if premature then return end
    local ok2, e = pcall(w.refresh)
    if not ok2 then ngx.log(ngx.ERR, 'wafpro: refresh failed: ', tostring(e)) end
end)
if not ok then ngx.log(ngx.ERR, 'wafpro: cannot start refresh timer: ', tostring(err)) end

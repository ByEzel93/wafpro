-- init_by_lua_file: master, on start/reload. Must never abort nginx startup.
local ok, w = pcall(dofile, '/www/server/wafpro/loader.lua')
if not ok then
    ngx.log(ngx.ERR, 'wafpro: engine not loadable: ', tostring(w))
    return
end
local ok2, err = pcall(w.load)
if not ok2 then ngx.log(ngx.ERR, 'wafpro: initial load failed: ', tostring(err)) end

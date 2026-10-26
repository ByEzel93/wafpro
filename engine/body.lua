-- body_filter_by_lua_file: same gate as header.lua — responses of sites
-- without content-replace rules stream through untouched.
local w = _G.WAFPRO
if not w or not ngx.ctx.wafpro_buf then return end
local ok, err = pcall(w.body_filter)
if not ok then ngx.log(ngx.ERR, 'wafpro: body filter failed: ', tostring(err)) end

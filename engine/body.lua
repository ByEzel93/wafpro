-- body_filter_by_lua_file: runs only for a response header.lua chose to
-- buffer (content replace / error-leak masking); all others stream through.
local w = _G.WAFPRO
if not w or not ngx.ctx.wafpro_buf then return end
local ok, err = pcall(w.body_filter)
if not ok then ngx.log(ngx.ERR, 'wafpro: body filter failed: ', tostring(err)) end

-- header_filter_by_lua_file: only does work for a request whose site has
-- content-replace rules (flagged in the access phase); otherwise one table
-- lookup and out.
local w = _G.WAFPRO
if not w or not ngx.ctx.wafpro_repl then return end
local ok, err = pcall(w.header_filter)
if not ok then ngx.log(ngx.ERR, 'wafpro: header filter failed: ', tostring(err)) end

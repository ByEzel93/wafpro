-- header_filter_by_lua_file: only does work for a request the access phase
-- flagged (content replace, error-leak masking, directory-scan counting);
-- otherwise a few table lookups and out.
local w = _G.WAFPRO
local c = ngx.ctx
if not w or not (c.wafpro_repl or c.wafpro_leak or c.wafpro_ip) then return end
local ok, err = pcall(w.header_filter)
if not ok then ngx.log(ngx.ERR, 'wafpro: header filter failed: ', tostring(err)) end

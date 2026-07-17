-- Our lua dir cannot be added via lua_package_path: the panel already declares
-- that directive in nginx.conf's http block (line ~32), and ours would land in
-- the same block via the vhost include -> "directive is duplicate" -> nginx
-- refuses to start. So we extend package.path from inside lua instead.
local DIR = '/www/server/wafpro/'
if not package.path:find(DIR, 1, true) then
    package.path = DIR .. '?.lua;' .. package.path
end
return require('wafpro')

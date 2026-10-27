# WAF Pro

Web application firewall plugin for aaPanel (nginx). It runs its own Lua
engine inside nginx, so you don't need aaPanel's free WAF or the paid btwaf.

The interface follows aaPanel 8's built-in WAF closely. If you've used that
one, the tabs and dialogs will look familiar.

> This is a personal project. I run it on my own servers, but it hasn't been
> tested against a wide range of sites and traffic. Read the
> [disclaimer](#disclaimer) before putting it in front of anything important.

## Features

**Overview** – requests and blocks for the day, a live 5-minute view (QPS,
bandwidth, origin response time), trends, an access/attack map, and top lists
for clients, status codes, referrers, IPs and pages.

**WebSite** – protection on/off per site, plus CC defense, fake spider
detection, CDN mode, smart CC, anti-crawl and a waiting room. The site
settings dialog covers request filters, uploads, blocked URLs and extensions,
hotlink protection, protected URLs, API rate limits, content replacement and
allowed request methods.

**Blockade** – every blocked request with the rule and the value that
triggered it, IP ban history (with unban), and a hit log for custom rules.

**Black/White list** – IPv4 and IPv6 addresses, ranges and CIDRs, User-Agents
and URLs. Import and export supported.

**Region** – block or allow countries per site or for all sites, with an
optional custom response page per rule. Works for IPv4 and IPv6.

**Traffic Limit** – rate limits for a URL or a whole site, counted per IP, per
IP + User-Agent or across all visitors. Supports per-second limits and "N
requests in T seconds" windows.

**Custom rules** – conditions on IP, country, method, URI, parameters,
headers, User-Agent, referer and cookies, combined with AND/OR. Actions:
block (page or status code), allow, or browser verification.

**Exclusive Rules** – virtual patches for widely exploited CVEs (PHP-CGI,
ThinkPHP, Laravel Ignition, Spring4Shell, Confluence OGNL and others). Each
one can be switched off.

**Webshell** – background scan of site files with quarantine and restore.

**Attack Map / Report** – where attacks come from, broken down by IP and URI.

**Global** – engine install and health check, module switches, CC defaults,
auto-ban, malicious IP and datacenter lists, response codes, rule set editor,
block pages, config export/import, and a simulated attack test that sends
attack-like requests to your sites and shows which rule caught each one.

## How detection works

A request first goes through the IP lists, User-Agent/URL lists, custom
rules, region rules and CC limits. After that come the content checks:

- **Keyword rules** (regex, editable in Global) are matched against each
  decoded parameter name and value separately, not against the raw query
  string. In POST forms, free-text fields such as `content`, `body`,
  `message` and `comment` are skipped, since blog posts and support tickets
  often contain code.
- **SQL injection and XSS** are checked per parameter with
  [libinjection](https://github.com/libinjection/libinjection). The installer
  compiles it with gcc and the engine calls it through LuaJIT's FFI. Without
  gcc a simpler built-in Lua checker is used instead; the Global tab shows
  which one is active.
- **Command execution and file access** checks are heuristic and off by
  default.

On libinjection's own test data nearly all SQLi and XSS samples were caught.
I also ran about 42,000 unique parameter values from my servers' access logs
through it, and the only values it flagged came from vulnerability scanners.
The Lua fallback is noticeably weaker, which is why gcc is recommended.

A few details:

- Visitor IPs: on sites behind Cloudflare the real visitor address is read
  from `CF-Connecting-IP`, but only when the connection actually comes from
  Cloudflare's network. For other proxies, turn on CDN mode for the site.
- Search engine crawlers are verified against the IP lists Google, Bing and
  Apple publish. A request claiming to be Googlebot from anywhere else is
  blocked as a fake spider.
- Settings are compiled by the panel into plain text and binary files the
  engine reads directly. The engine notices changes on its own, so saving a
  setting doesn't reload nginx.
- If the engine hits an error on a request, the request is let through rather
  than failing.
- The server's own addresses and private networks are never blocked. Node /
  Nuxt SSR apps request their own pages a lot, and blocking that used to cause
  503s.

## Requirements

- aaPanel with nginx built with `lua_nginx_module` (aaPanel's default nginx
  build has it).
- gcc for building libinjection. Optional, but recommended.
- Outbound HTTPS from the server during install, to download the country
  database and the crawler IP lists.

## Install

1. Download `wafpro-x.x.x.zip` from the
   [releases page](https://github.com/ByEzel93/wafpro/releases). Use the zip
   attached to the release, not "Source code (zip)". Only the attached one
   has the `wafpro/` folder at the top that aaPanel expects.
2. In aaPanel's App Store, import it as a third-party plugin (or extract it
   so you end up with `/www/server/panel/plugin/wafpro/`).
3. Open the plugin, go to **Global** and enable the engine. It writes the
   nginx include, runs `nginx -t` and rolls back if the test fails.
4. Turn protection on for your sites in the **WebSite** tab.

To update, upload the new zip the same way. The rule files and libinjection
are rebuilt, and nginx is reloaded only if `nginx -t` passes.

## Removing the engine by hand

If something goes wrong and you can't reach the panel:

```bash
rm -f /www/server/panel/vhost/nginx/wafpro.conf
nginx -t && nginx -s reload
```

Your sites keep working; only the WAF is taken out of nginx.

## Limitations

- Only one Lua WAF can run in nginx's access phase. WAF Pro won't enable
  itself while btwaf or aaPanel's free WAF is active.
- aaPanel's **Security** page will still say the Nginx WAF isn't installed.
  That page only knows about aaPanel's own WAF and can't be changed from a
  plugin.
- Country data is DB-IP's free monthly list. You can refresh it from the
  Region tab. If it couldn't be downloaded, the panel's older GeoLite2 copy
  is used, which is IPv4 only, so IPv6 visitors aren't checked by region
  rules in that case.
- PHP2Shell (CVE-2026-109618 / 109619): the guard blocks the known ways to
  trigger it, but the actual fix is updating PHP to 8.2.35, 8.3.36, 8.4.27,
  8.5.12 or newer.
- libinjection, like any SQLi detector, sometimes flags quoted search
  phrases. If a search page is affected, whitelist that URL or turn off SQL
  injection protection for the site.

## Disclaimer

I wrote this for my own servers and I'm sharing it as is. Features were
tested on an isolated nginx and against real logs, but the plugin hasn't run
in front of many sites for long. A WAF sits in front of every request, so a
bug can block real visitors. Try it on a test server first, keep the commands
above handy, and give it some time before trusting it with anything critical.

No warranty. This is not an official aaPanel plugin and has no affiliation
with aaPanel.

## Bugs and contributions

Please open an [issue](https://github.com/ByEzel93/wafpro/issues) and include:

- aaPanel and nginx version (`nginx -V`)
- what you did, what you expected and what happened instead
- related lines from `/www/wwwlogs/wafpro/` and `/www/wwwlogs/nginx_error.log`
- whether the engine is enabled and `nginx -t` passes

Pull requests are welcome. Please mention how you tested the change.

## License

Free to use, modify and share, with no warranty.

`engine/libinjection/` is libinjection by Nick Galbreath and contributors,
BSD 3-Clause license (see `engine/libinjection/COPYING`), included unchanged.

Country data: [IP Geolocation by DB-IP](https://db-ip.com), CC BY 4.0. It's
downloaded on your server and isn't part of this repository.

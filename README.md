# WAF Pro

A web application firewall plugin for aaPanel (nginx). It has its own Lua
engine, so it doesn't need aaPanel's free WAF or the paid btwaf. You install the
plugin, wire the engine into nginx from the Global tab, and turn protection on
per site.

The UI follows the layout of aaPanel 8's own WAF on purpose, so anyone who has
used that one will find things where they expect them.

Please read the [disclaimer](#disclaimer) first. This is a side project, not a
product, and it has seen far less real traffic than a WAF normally should.

## What's in it

- **Overview**: today's requests and blocks, a 5-minute real-time view (QPS,
  bandwidth, origin latency), request/traffic trends, access and block map with
  source ranking, client / status code / referrer / traffic / page top lists,
  block types and the latest block events.
- **WebSite**: per-site switches (CC, fake spider, CDN, smart CC, crawl
  protection, waiting room...) and a Modify dialog with everything else for that
  site: filters, uploads, forbidden URLs and extensions, anti-leech, protected
  URLs, API defense, content replace, URL CC, request methods.
- **Blockade**: interception records with details (the rule that matched and
  the value that triggered it), IP ban history with unblock, and a rule hit log
  for custom rules.
- **Black/White list**: IP (v4 ranges, v6, CIDR), User-Agent and URL lists, with
  import/export.
- **Region**: country rules per site or for all sites, with an optional custom
  response page per rule.
- **Traffic Limit**: rate limits per URL or for the whole site, per IP, IP+UA or
  all clients together; per-second and "N requests in T seconds" limits.
- **Custom rules**: AND/OR conditions on IP, country, method, URI, parameters,
  headers, UA, referer and cookies. Actions are block (page or status code),
  allow, or browser verification.
- **Exclusive Rules**: virtual patches for widely exploited CVEs (PHP-CGI,
  ThinkPHP, Laravel Ignition, Spring4Shell, Confluence OGNL and others), each
  one switchable.
- **Webshell**: background scan of site files, with quarantine and restore.
- **Attack Map** and **Report**: where attacks come from, by IP and by URI.
- **Global**: engine wiring and health, module switches, CC defaults, auto-ban,
  malicious IP / datacenter lists, response codes, PHP2Shell limits, rule set
  editor, block pages, config export/import.

There is also a **Simulated attack** button that sends attack-shaped requests to
your sites through nginx and shows which rule stopped each one.

## How detection works

Requests go through IP lists, UA/URL lists, custom rules, region and CC first,
then the content checks:

- **Keyword rules** (regex, editable in Global) run on each decoded parameter
  name and value separately, not on the whole query string. In form posts the
  values of free-text fields (`content`, `body`, `message`, `comment` and
  similar) are skipped by these rules, because blog posts and tickets
  legitimately contain code.
- **SQL injection and XSS** are checked per parameter by
  [libinjection](https://github.com/libinjection/libinjection). The installer
  compiles it with gcc and the engine calls it through LuaJIT's FFI. If there is
  no compiler, a smaller analyser written in Lua takes over (Global shows which
  one is active).
- **Command execution and file access** use their own heuristics and are off by
  default.

Some numbers from testing. On libinjection's own test sets, about 100% of the
SQLi and XSS samples were caught. I also ran 42k distinct parameter values from
my server's access logs through it. The only values it flagged were scanner
probes. The Lua fallback is weaker: it flagged 4.5% of libinjection's
false-positive samples, which is why the C library is the default.

Other bits that may be useful if you read the code:

- Rule files are compiled by the panel into simple text and packed binary files
  (sorted IP ranges, binary-searched by the engine). The engine polls a version
  file and reloads them, so saving a setting doesn't need an nginx reload.
- The access handler runs under `pcall`. If the engine errors, the request goes
  through instead of failing.
- The server's own addresses and LAN ranges are never blocked. Node/Nuxt SSR
  apps call themselves a lot, and older versions of this plugin returned 503s
  for that reason.

## Requirements

- aaPanel with nginx built with `lua_nginx_module` (the default aaPanel nginx is).
- gcc, to build libinjection. It's optional, but strongly recommended.
- The panel's country database
  (`/www/server/panel/data/firewall/GeoLite2-Country.json`). The installer
  downloads it if it's missing.

## Install

1. Download `wafpro-x.x.zip` from the
   [releases page](https://github.com/ByEzel93/wafpro/releases). Use the zip
   attached to the release, not GitHub's "Source code" zip. Only the attached
   one unpacks into the `wafpro/` folder aaPanel expects.
2. In aaPanel open App Store, upload it as a third-party plugin (or unzip it so
   you end up with `/www/server/panel/plugin/wafpro/`).
3. Open the plugin, go to Global and switch on the engine. It writes the nginx
   include, runs `nginx -t`, and rolls back if the test fails.
4. Turn protection on for your sites on the WebSite tab.

Updating works the same way: upload the new zip. The updater rebuilds the rule
files and libinjection, and reloads nginx only if `nginx -t` passes.

## Limitations

- Only one Lua WAF can own the access phase. WAF Pro won't wire itself in while
  btwaf or the free WAF is active.
- The country database is IPv4 only, so region rules don't apply to IPv6
  visitors. Everything else does.
- PHP2Shell (CVE-2026-109618 / 109619): the guard blocks the known triggers, but
  the real fix is updating PHP (8.2.35, 8.3.36, 8.4.27, 8.5.12 or newer).
- Like any SQLi detector, libinjection has false positives on some quoted search
  strings. If a search box on your site is affected, whitelist that URL or turn
  SQL injection defense off for the site.

To take the engine out of nginx by hand:

```bash
rm -f /www/server/panel/vhost/nginx/wafpro.conf
nginx -t && nginx -s reload
```

Your sites keep running; only the WAF is removed.

## Changes in 2.2

- Every tab rebuilt to match aaPanel 8's WAF; new Exclusive Rules tab.
- libinjection for SQLi/XSS, on by default. Keyword rules match per parameter
  and skip free-text fields.
- Ban history, rule hit log, matched-rule details in Blockade.
- Region: multiple sites per rule, custom response page.
- Traffic Limit: whole-site and all-client limits, time windows, HTML/JSON
  limit page.
- Custom rules: OR groups, release and verification actions.
- Overview: client, status code, referrer and per-IP/per-page traffic stats.
- The plugin window opens at its final size instead of resizing several times.

## Disclaimer

I built this for my own servers and I'm sharing it as is. Features were tested
while developing them, on an isolated nginx and against real logs, but it hasn't
run in front of many sites for a long time. A WAF sits in the request path, so a
bug can block real users. Try it on a staging box first, keep the recovery
commands above handy, and don't put it in front of anything critical until
you're comfortable with it.

There is no warranty. This is not an official aaPanel plugin and isn't
affiliated with aaPanel.

## Issues and contributions

Bugs and requests go to the
[issue tracker](https://github.com/ByEzel93/wafpro/issues). It helps if you
include:

- aaPanel and nginx versions (`nginx -V`)
- what you did, what you expected and what happened
- related lines from `/www/wwwlogs/wafpro/` and `/www/wwwlogs/nginx_error.log`
- whether the engine is wired in and whether `nginx -t` passes

Pull requests are welcome; please say how you tested the change.

## License

Free to use, modify and share, with no warranty.

`engine/libinjection/` is libinjection, copyright Nick Galbreath and the
libinjection contributors, under the BSD 3-Clause license (see
`engine/libinjection/COPYING`). It's included unmodified.

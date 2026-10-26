# WAF Pro — Standalone Nginx WAF for aaPanel

A self-contained Web Application Firewall plugin for **aaPanel**, with a modern
dashboard and a full protection engine that runs directly in nginx. It does
**not** depend on aaPanel's free WAF or the paid btwaf — install it and it
works on its own.

> ⚠️ **Please read the [Disclaimer](#disclaimer) before installing.** This is a
> community project shared as-is. It has **not** been through rigorous,
> long-term production testing.

---

## What it does

WAF Pro ships its own lua engine (`/www/server/wafpro/`) wired into nginx, plus
a Python + HTML management UI as an aaPanel plugin. Everything is driven from
one dashboard:

| Tab | What it covers |
|-----|----------------|
| **Overview** | Traffic / attack charts by day, real-time QPS and origin response, access & block map, attacked domains / traffic / visited pages TOP10, intercept types |
| **WebSite** | Per-site switches (domains detected automatically, incl. Node projects and wildcards): GET/POST/Cookie/UA filters, scanner, N-day patches, PHP2Shell guard, form-data check, non-browser check, IDC interception, CC defense (block or browser-check), smart CC, crawl limit, waiting room, CDN, fake spider, file/upload/PHP-path rules — plus per-site **Rules**: forbidden URL, anti-leech, protected URL, API defense, content replace |
| **Blockade** | Interception records, banned IPs (auto-ban, CC, traffic; escalating) with unban, rule-hit stats |
| **Black/White List** | IP white/black (IPv4 + IPv6, ranges, CIDR), UA white/black, URL white/black, URL keywords |
| **Region** | Per-rule country blocking (allow-list / block-list), per site |
| **Traffic Limit** | Per-URL rate limiting (per IP or IP+UA), 503/502/block actions |
| **Custom rules** | Multi-condition rules (IP, country, method, URI, header, UA, …) with allow/block/status actions |
| **Webshell** | Background scan of site files for webshell signatures; view, quarantine/restore, mark safe |
| **Attack Map** | World map of attackers with animated lines to the server |
| **Report** | Attack analytics by IP / URI, protection-type donut, country leaderboard, date range + search |
| **Global** | Master switch, engine wiring + health/update, auto-ban, escalating bans, malicious-IP / datacenter / verified-crawler lists, HTTP methods, header and parameter limits, response codes, PHP2Shell limits, filter rule-set editor, block & check pages, sensitive words, config export/import/restore |

**Simulated attack** (top right) sends real attack-shaped requests to each site
through nginx and shows which rule stopped each one — and flags any PHP build on
the server that lacks the PHP2Shell fix.

### Design notes (how it's built)

- **Dependency-free lua engine.** No cjson, no ffi, no external resty modules.
  Plain Lua 5.1 so it runs on a stock nginx + `lua_nginx_module` build.
- **Binary-search IP matching.** The panel compiles country/IP ranges into a
  packed, sorted binary blob (`8 bytes/range`) that the engine binary-searches —
  ~17 comparisons instead of a linear scan over 100k+ ranges.
- **No nginx reload on config change.** The engine polls a `version` file every
  couple of seconds and hot-reloads its rule files. Saving a setting in the UI
  takes effect within seconds, without restarting nginx.
- **Panel-native data.** Country database and GeoIP come from aaPanel's own
  data files, so no other WAF plugin is required.
- **Fails open.** The request hot path runs under `pcall`; if the engine ever
  errors, traffic passes rather than 500-ing.

---

## Requirements

- aaPanel with **nginx + `lua_nginx_module`** (LuaJIT).
- aaPanel's GeoIP country database
  (`/www/server/panel/data/firewall/GeoLite2-Country.json`) — normally already
  present.

## Limitations — please read

- **One lua WAF per nginx.** WAF Pro refuses to wire itself in while aaPanel's
  btwaf or free_waf is hooked into nginx (two `access_by_lua_file` in one
  `http` block is a fatal config error).
- **Reverse-proxied apps (Node.js, Nuxt, Next.js…).** Versions before 2.1
  broke these with 503s. 2.1 removes the known causes (the server's own SSR
  requests are never rate-limited or banned, WebSocket connections are kept out
  of the rate counters, and Node project domains are now actually matched).
  It has been tested on an isolated nginx with the same build, **not yet under
  real production traffic** — enable it on a proxied site and watch it before
  relying on it.
- **PHP2Shell (CVE-2026-109618 / 109619).** The guard removes the known
  triggers, but PHP's own advisory is clear that updating PHP (8.2.35, 8.3.36,
  8.4.27, 8.5.12 or newer) is the only complete fix.
- The country database is IPv4-only, so Region rules do not apply to IPv6
  visitors (every other rule does).

If a site misbehaves after you enable the engine, disable it immediately:

```bash
rm -f /www/server/panel/vhost/nginx/wafpro.conf
nginx -t && nginx -s reload
```

That fully removes the engine from nginx; your sites keep running.

## Install

1. Download the latest **`wafpro-x.x.zip`** from the
   [Releases page](https://github.com/ByEzel93/wafpro/releases).
   > Use the `wafpro-x.x.zip` attached to the release, **not** GitHub's
   > auto-generated "Source code" zip — only the attached one unpacks to the
   > `wafpro/` folder aaPanel expects.
2. In aaPanel, go to **App Store → find a plugin / third-party** and upload the
   zip as a custom plugin. (Or unzip it straight into
   `/www/server/panel/plugin/` so you get `/www/server/panel/plugin/wafpro/`.)
3. Open the plugin and, on the **Global** tab, turn on **Engine wired into
   nginx**. This installs the lua config into nginx after testing it with
   `nginx -t` (it rolls back automatically if the test fails).
4. Enable protection per site on the **Website** tab.

The installer never edits a running nginx config without a successful `nginx -t`
first, and backs up before changing anything.

**Updating from 2.0:** upload the new zip the same way. The updater re-renders
all rule files (2.1 uses a new site format) and, if the engine is wired, reloads
nginx after a passing `nginx -t`. Global › Engine status shows when the workers
run the latest settings.

---

## Disclaimer

**Read this carefully.**

- This plugin was built quickly and **has not been through thorough,
  long-running production testing.** Individual features were verified during
  development, but there is no guarantee it behaves correctly under every
  real-world traffic pattern, nginx build, or aaPanel version.
- A WAF sits directly in your request path. A bug could, in the worst case,
  **block legitimate traffic or affect site availability.** Test it on a
  staging server before putting it in front of anything important.
- It is provided **as-is, with no warranty of any kind.** You run it at your own
  risk. The author is not responsible for downtime, blocked users, data loss, or
  any other damage resulting from its use.
- It is **not** an official aaPanel product and is not affiliated with or
  endorsed by aaPanel.

If you are not comfortable reading the code and recovering nginx by hand if
something goes wrong, please wait for a more mature release.

---

## Found a bug? Have a request?

Please **open an issue on GitHub** rather than only reporting it on the forum —
that way it's tracked and others can see it:

**➡️ https://github.com/ByEzel93/wafpro/issues**

When opening an issue, include:

- aaPanel version and nginx version (`nginx -V`)
- What you did and what you expected vs. what happened
- Any relevant lines from the WAF log (`/www/wwwlogs/wafpro/`) and the nginx
  error log (`/www/wwwlogs/nginx_error.log`)
- Whether the engine is wired in (Global tab) and whether `nginx -t` passes

Pull requests are welcome. If you improve a rule, fix a bug, or add a feature,
please describe how you tested it.

---

## Uninstall / recovery

- The plugin's uninstaller removes the nginx wiring and the plugin files.
- If nginx ever fails to start because of the WAF config, remove
  `/www/server/panel/vhost/nginx/wafpro.conf` and reload nginx — that fully
  disables the engine.

---

## License

Released as a free community plugin. Use, modify and share freely. No warranty.
See the [Disclaimer](#disclaimer).

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
| **Overview** | Live traffic/attack charts, top attackers, world map, attack-type breakdown |
| **Website** | Per-site switches: scan protection, GET/POST/Cookie/UA filtering, CC defense, fake-spider blocking, per-site CDN, upload/extension filters |
| **Blockade** | Interception records, auto-banned IP list (with unban), rule-hit stats |
| **Black/White List** | IP and URL allow/deny lists |
| **Region** | Per-rule country blocking (allow-list / block-list), per site |
| **Traffic** | Per-URL rate limiting (per IP or IP+UA), 503/502/block actions |
| **Custom Rules** | Multi-condition rules (IP, country, method, URI, header, UA, …) with allow/block/status actions |
| **Attack Map** | World map of attackers with animated lines to the server |
| **Report** | Attack analytics by IP / URI, protection-type donut, country leaderboard, date range + search |
| **Global** | Master switch, auto-ban, HTTP method allow-list, header size limits, sensitive-word filter, malicious-IP feed, verified-crawler list, config export/import/restore |

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

## Install

1. Copy the `wafpro` folder to `/www/server/panel/plugin/wafpro/`, **or** zip it
   and install via the aaPanel App Store (custom plugin).
2. Open the plugin and, on the **Global** tab, turn on **Engine wired into
   nginx**. This installs the lua config into nginx after testing it with
   `nginx -t` (it rolls back automatically if the test fails).
3. Enable protection per site on the **Website** tab.

The installer never edits a running nginx config without a successful `nginx -t`
first, and backs up before changing anything.

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

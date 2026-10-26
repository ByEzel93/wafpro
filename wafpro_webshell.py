#!/usr/bin/python
# coding: utf-8
# +-------------------------------------------------------------------
# | WAF Pro — webshell scanner
# +-------------------------------------------------------------------
# | Runs as its own background process (a full scan can take minutes,
# | far longer than a panel request may block):
# |
# |   python wafpro_webshell.py scan
# |
# | Reads webshell/targets.json ([{site, path}]) written by the panel,
# | writes webshell/status.json while it works and webshell/results.json
# | when done. Static signatures only: it never executes or includes the
# | files it reads.
# +-------------------------------------------------------------------
import os
import re
import sys
import json
import time
import hashlib

PLUGIN_PATH = '/www/server/panel/plugin/wafpro/'
WS_DIR = PLUGIN_PATH + 'webshell/'
TARGETS = WS_DIR + 'targets.json'
STATUS = WS_DIR + 'status.json'
RESULTS = WS_DIR + 'results.json'
IGNORE = WS_DIR + 'ignore.json'

SCAN_EXT = ('.php', '.phtml', '.php3', '.php4', '.php5', '.php7', '.phar', '.inc', '.pht')
MAX_SIZE = 3 * 1048576
# directories that hold no code of the site itself and are huge
SKIP_DIRS = {'.git', '.svn', 'node_modules', '.cache', '.well-known'}

# (id, level, description, regex). Level 3 = near-certain shell, 2 = strong
# indicator, 1 = worth a look. Patterns target the construct, not words:
# "eval" or "base64_decode" alone appear in plenty of legitimate code.
SIGNATURES = [
    ('eval-input', 3, 'eval/assert of request input',
     r'\b(eval|assert)\s*\(\s*(stripslashes\s*\(\s*)?\$_(POST|GET|REQUEST|COOKIE|SERVER)\b'),
    ('exec-input', 3, 'shell command from request input',
     r'\b(system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\b'),
    ('eval-decode', 3, 'eval of decoded/obfuscated payload',
     r'\beval\s*\(\s*(gzinflate|gzuncompress|gzdecode|str_rot13|base64_decode|rawurldecode|hex2bin)\s*\('),
    ('dynamic-call', 3, 'function name taken from request input',
     r'\$_(POST|GET|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)'),
    # the pattern string itself: quote, delimiter, body on one line, the same
    # delimiter, then a modifier list containing e
    ('preg-e', 3, 'preg_replace /e code execution',
     r'preg_replace\s*\(\s*([\'"])([^\w\s\\])[^\n]{0,300}?\2[imsxuADSUXJ]*e[imsxuADSUXJ]*\1\s*,'),
    ('create-func', 2, 'create_function with request input',
     r'create_function\s*\([^)]{0,200}\$_(POST|GET|REQUEST|COOKIE)'),
    ('known-shell', 3, 'known webshell family marker',
     r'(c99shell|r57shell|\bFilesMan\b|b374k|weevely|IndoXploit|AnonymousFox|WSO\s+\d|'
     r'Mini\s*Shell|Alfa\s*Shell|p0wny)'),
    ('upload-anything', 2, 'uploads any file to any path from input',
     r'move_uploaded_file\s*\(\s*\$_FILES\s*\[[^\]]+\]\s*\[\s*[\'"]tmp_name[\'"]\s*\]\s*,\s*\$_(POST|GET|REQUEST)'),
    ('long-b64-eval', 2, 'long encoded blob next to eval',
     r'\beval\s*\(.{0,60}[A-Za-z0-9+/]{2000,}'),
    ('var-func-chain', 2, 'string-built function call (obfuscation)',
     r'\$\w+\s*=\s*[\'"](as|ba|ev|sy|sh|cr)[\'"]\s*\.\s*[\'"][a-z_]{2,}[\'"]\s*;.{0,200}\$\w+\s*\('),
]
# re.S only where a construct may legitimately span lines; preg-e must not
COMPILED = [(i, lv, d, re.compile(p, re.I if i == 'preg-e' else re.I | re.S))
            for i, lv, d, p in SIGNATURES]

# PHP inside an uploads directory is a shell more often than not. Case
# sensitive and upload-specific on purpose: "Image/" or "Images/" in vendor
# code are class namespaces, not upload targets.
UPLOAD_DIR_RE = re.compile(r'/(wp-content/uploads|uploads?|upfiles?|attachments)/')


def _write(path, data):
    tmp = path + '.tmp'
    with open(tmp, 'w') as fh:
        json.dump(data, fh)
    os.replace(tmp, path)


def _read(path, default):
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return default


def file_hash(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def scan_file(path):
    '''-> list of (sig id, level, desc, line no, snippet)'''
    try:
        with open(path, 'rb') as fh:
            raw = fh.read(MAX_SIZE)
    except Exception:
        return []
    text = raw.decode('utf-8', 'ignore')
    hits = []
    for sid, lv, desc, rx in COMPILED:
        m = rx.search(text)
        if m:
            line = text.count('\n', 0, m.start()) + 1
            snip = text[max(m.start() - 60, 0):m.end() + 60].replace('\r', '')
            hits.append((sid, lv, desc, line, snip[:300]))
    if UPLOAD_DIR_RE.search(path.replace('\\', '/')) and '<?' in text[:4096]:
        hits.append(('php-in-uploads', 1, 'PHP file inside an uploads directory', 1, text[:200]))
    return hits


def scan():
    targets = _read(TARGETS, [])
    ignore = set(_read(IGNORE, []))
    status = {'running': True, 'pid': os.getpid(), 'started': int(time.time()),
              'scanned': 0, 'found': 0, 'current': '', 'sites': len(targets)}
    _write(STATUS, status)
    found = []
    seen = set()          # two sites can share one directory
    last = 0
    for t in targets:
        root = t.get('path') or ''
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                if not fn.lower().endswith(SCAN_EXT):
                    continue
                full = os.path.join(dirpath, fn)
                if full in seen:
                    continue
                seen.add(full)
                try:
                    st = os.stat(full)
                except Exception:
                    continue
                if st.st_size > MAX_SIZE:
                    continue
                status['scanned'] += 1
                hits = scan_file(full)
                if hits:
                    try:
                        digest = file_hash(full)
                    except Exception:
                        digest = ''
                    if digest in ignore:
                        continue
                    found.append({'site': t.get('site', ''), 'file': full, 'hash': digest,
                                  'size': st.st_size, 'mtime': int(st.st_mtime),
                                  'level': max(h[1] for h in hits),
                                  'hits': [{'id': h[0], 'level': h[1], 'desc': h[2],
                                            'line': h[3], 'snippet': h[4]} for h in hits]})
                    status['found'] = len(found)
                now = time.time()
                if now - last > 1:
                    last = now
                    status['current'] = full
                    _write(STATUS, status)
    found.sort(key=lambda x: (-x['level'], -x['mtime']))
    _write(RESULTS, {'time': int(time.time()), 'scanned': status['scanned'], 'files': found})
    status.update({'running': False, 'finished': int(time.time()), 'current': ''})
    _write(STATUS, status)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'scan':
        if not os.path.isdir(WS_DIR):
            os.makedirs(WS_DIR, 0o700)
        try:
            scan()
        except Exception as e:
            st = _read(STATUS, {})
            st.update({'running': False, 'error': str(e)})
            _write(STATUS, st)

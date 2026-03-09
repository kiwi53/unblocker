const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');
const zlib = require('zlib');

const PORT = 3000;

// Keep-alive agents for connection reuse
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 64 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 64, rejectUnauthorized: false });

// Works on Node 16+ using built-in http/https (no fetch needed)
function fetchUrl(urlStr, redirectCount, method, body, extraHeaders) {
    redirectCount = redirectCount || 0;
    if (redirectCount > 10) return Promise.reject(new Error('Too many redirects'));
    method = method || 'GET';

    return new Promise((resolve, reject) => {
        let parsed;
        try { parsed = new URL(urlStr); } catch (e) { return reject(e); }

        const isHttps = parsed.protocol === 'https:';
        const lib = isHttps ? https : http;
        const options = {
            hostname: parsed.hostname,
            port: parsed.port || (isHttps ? 443 : 80),
            path: parsed.pathname + parsed.search,
            method: method,
            agent: isHttps ? httpsAgent : httpAgent,
            headers: Object.assign({
                'Host': parsed.host,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Upgrade-Insecure-Requests': '1',
            }, extraHeaders || {}),
        };
        if (body && body.length) options.headers['Content-Length'] = body.length;

        const req = lib.request(options, (res) => {
            if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
                const next = new URL(res.headers.location, urlStr).toString();
                // POST -> GET on 301/302/303
                const nextMethod = [301, 302, 303].includes(res.statusCode) ? 'GET' : method;
                const nextBody = nextMethod === 'GET' ? null : body;
                return fetchUrl(next, redirectCount + 1, nextMethod, nextBody, extraHeaders).then(resolve).catch(reject);
            }
            // Decompress gzip/deflate/br responses
            let stream = res;
            const encoding = (res.headers['content-encoding'] || '').toLowerCase();
            if (encoding === 'gzip') {
                stream = res.pipe(zlib.createGunzip());
            } else if (encoding === 'deflate') {
                stream = res.pipe(zlib.createInflate());
            } else if (encoding === 'br') {
                stream = res.pipe(zlib.createBrotliDecompress());
            }
            const chunks = [];
            stream.on('data', chunk => chunks.push(chunk));
            stream.on('end', () => {
                const headers = Object.assign({}, res.headers);
                delete headers['content-encoding'];
                delete headers['transfer-encoding'];
                resolve({
                    status: res.statusCode,
                    headers: headers,
                    body: Buffer.concat(chunks),
                });
            });
            stream.on('error', reject);
            res.on('error', reject);
        });

        req.on('error', reject);
        req.setTimeout(30000, () => { req.destroy(new Error('Request timed out')); });
        if (body && body.length) req.write(body);
        req.end();
    });
}

function readBody(req) {
    return new Promise((resolve) => {
        const chunks = [];
        req.on('data', chunk => chunks.push(chunk));
        req.on('end', () => resolve(Buffer.concat(chunks)));
        req.on('error', () => resolve(Buffer.alloc(0)));
    });
}

// Headers that must be stripped from proxied responses to prevent blocking
const BLOCKED_HEADERS = [
    'x-frame-options',
    'content-security-policy',
    'content-security-policy-report-only',
    'cross-origin-opener-policy',
    'cross-origin-embedder-policy',
    'cross-origin-resource-policy',
    'x-content-type-options',
    'permissions-policy',
    'strict-transport-security',
];

function rewriteSetCookie(cookieHeader) {
    if (!cookieHeader) return null;
    const cookies = Array.isArray(cookieHeader) ? cookieHeader : [cookieHeader];
    return cookies.map(c => {
        // Strip Domain, Secure, SameSite, and __Host-/__Secure- prefixes so cookies work on our proxy
        return c
            .replace(/;\s*domain=[^;]*/gi, '')
            .replace(/;\s*secure/gi, '')
            .replace(/;\s*samesite=[^;]*/gi, '; SameSite=Lax')
            .replace(/\b__Host-/g, '__host-')
            .replace(/\b__Secure-/g, '__secure-');
    });
}

function buildSafeHeaders(originalHeaders, contentType) {
    const out = { 'Content-Type': contentType };
    // Copy safe headers through
    for (const [k, v] of Object.entries(originalHeaders)) {
        if (!BLOCKED_HEADERS.includes(k.toLowerCase()) && k.toLowerCase() !== 'set-cookie') {
            out[k] = v;
        }
    }
    // Rewrite set-cookie to work through proxy
    const rewritten = rewriteSetCookie(originalHeaders['set-cookie']);
    if (rewritten && rewritten.length) {
        out['Set-Cookie'] = rewritten;
    }
    // Explicitly allow cross-origin loading
    out['Cross-Origin-Resource-Policy'] = 'cross-origin';
    out['Access-Control-Allow-Origin'] = '*';
    out['Access-Control-Allow-Credentials'] = 'true';
    out['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Super-Properties, X-Discord-Locale, X-Discord-Timezone, X-Debug-Options, X-Fingerprint';
    out['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS';
    return out;
}

function proxyUrl(url, pageUrl) {
    url = url.trim();
    if (!url || url.startsWith('data:') || url.startsWith('#') ||
        url.startsWith('javascript:') || url.startsWith('mailto:') ||
        url.startsWith('blob:') || url.startsWith('about:')) return null;
    try {
        const abs = new URL(url, pageUrl).toString();
        if (!abs.startsWith('http://') && !abs.startsWith('https://')) return null;
        return '/proxy?url=' + encodeURIComponent(abs);
    } catch { return null; }
}

function rewriteHtml(html, pageUrl) {
    let pageOrigin;
    try { pageOrigin = new URL(pageUrl).origin; } catch { pageOrigin = ''; }

    // Remove existing base tags and CSP meta tags
    html = html.replace(/<base\b[^>]*>/gi, '');
    html = html.replace(/<meta[^>]+http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/gi, '');
    html = html.replace(/<meta[^>]+http-equiv\s*=\s*["']?x-frame-options["']?[^>]*>/gi, '');

    // Strip integrity and crossorigin attrs — our proxy modifies content so hashes will mismatch
    html = html.replace(/\s+integrity\s*=\s*(["'])[^"']*\1/gi, '');
    html = html.replace(/\s+crossorigin\s*=\s*(["'])[^"']*\1/gi, '');
    html = html.replace(/\s+crossorigin(?=[\s>])/gi, '');
    // Strip nonce attributes from scripts/styles (CSP nonces won't match)
    html = html.replace(/\s+nonce\s*=\s*(["'])[^"']*\1/gi, '');

    // Rewrite <style> block contents (handles @import and url() inside inline CSS)
    html = html.replace(/(<style\b[^>]*>)([\s\S]*?)(<\/style>)/gi, (match, open, content, close) => {
        return open + rewriteCss(content, pageUrl) + close;
    });

    // Rewrite src, href, action, srcset, poster, formaction attributes
    html = html.replace(/\b(src|href|action|data-src|data-href|poster|formaction)\s*=\s*(["'])([^"']*)\2/gi, (match, attr, quote, url) => {
        // Don't rewrite anchors (#...) or javascript: URLs
        if (url.startsWith('#') || url.startsWith('javascript:')) return match;
        const p = proxyUrl(url, pageUrl);
        return p ? `${attr}=${quote}${p}${quote}` : match;
    });

    // Rewrite srcset (comma-separated list of url [descriptor])
    html = html.replace(/\bsrcset\s*=\s*(["'])([^"']*)\1/gi, (match, quote, srcset) => {
        const rewritten = srcset.split(',').map(part => {
            const trimmed = part.trim();
            const spaceIdx = trimmed.search(/\s/);
            const url = spaceIdx === -1 ? trimmed : trimmed.slice(0, spaceIdx);
            const rest = spaceIdx === -1 ? '' : trimmed.slice(spaceIdx);
            const p = proxyUrl(url, pageUrl);
            return p ? p + rest : part;
        }).join(', ');
        return `srcset=${quote}${rewritten}${quote}`;
    });

    // Rewrite inline style url()
    html = html.replace(/style\s*=\s*(["'])([\s\S]*?)\1/gi, (match, quote, styleContent) => {
        const rewritten = rewriteCss(styleContent, pageUrl);
        return `style=${quote}${rewritten}${quote}`;
    });

    // Inject a script that intercepts fetch/XHR/navigation/WebSockets/dynamic elements to route through proxy
    const interceptScript = `<script data-proxy-injected="true">
(function(){
    var PROXY_ORIGIN = window.location.origin;
    var PAGE_URL = ${JSON.stringify(pageUrl)};
    var PAGE_ORIGIN = ${JSON.stringify(pageOrigin)};

    function resolveUrl(url) {
        if (!url || typeof url !== 'string') return url;
        // Already proxied
        if (url.indexOf('/proxy?url=') === 0 || url.indexOf(PROXY_ORIGIN + '/proxy?url=') === 0) return url;
        // Absolute external URL
        if (/^https?:\\/\\//i.test(url)) return '/proxy?url=' + encodeURIComponent(url);
        // Protocol-relative
        if (url.indexOf('//') === 0) return '/proxy?url=' + encodeURIComponent('https:' + url);
        // Data, blob, about, javascript, mailto, # — leave alone
        if (/^(data:|blob:|about:|javascript:|mailto:|#)/i.test(url)) return url;
        // Relative URL — resolve against original page URL
        try {
            var abs = new URL(url, PAGE_URL).href;
            if (/^https?:\\/\\//i.test(abs)) return '/proxy?url=' + encodeURIComponent(abs);
        } catch(e) {}
        return url;
    }
    function toWsProxy(url) {
        try {
            if (!url || typeof url !== 'string') return url;
            if (/^wss?:\\/\\//i.test(url)) {
                var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
                return proto + '//' + location.host + '/wsproxy?url=' + encodeURIComponent(url);
            }
        } catch(e) {}
        return url;
    }

    // --- Block service workers ---
    try {
        if (navigator.serviceWorker) {
            // Unregister existing service workers
            navigator.serviceWorker.getRegistrations && navigator.serviceWorker.getRegistrations().then(function(regs) {
                regs.forEach(function(r) { r.unregister(); });
            });
        }
        Object.defineProperty(navigator, 'serviceWorker', { get: function(){ return undefined; }, configurable: true });
    } catch(e) {}

    // --- XHR ---
    var _open = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
        try { url = resolveUrl(url); } catch(e) {}
        return _open.apply(this, [method, url].concat(Array.prototype.slice.call(arguments, 2)));
    };
    var _send = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function() {
        try { this.withCredentials = true; } catch(e) {}
        return _send.apply(this, arguments);
    };

    // --- fetch ---
    var _fetch = window.fetch;
    if (_fetch) {
        window.fetch = function(input, init) {
            try {
                init = init || {};
                if (!init.credentials) init.credentials = 'include';
                if (typeof input === 'string') {
                    input = resolveUrl(input);
                } else if (input && input.url) {
                    var newUrl = resolveUrl(input.url);
                    if (newUrl !== input.url) {
                        input = new Request(newUrl, input);
                    }
                }
            } catch(e) {}
            return _fetch.call(this, input, init);
        };
    }

    // --- WebSocket ---
    try {
        var _WS = window.WebSocket;
        window.WebSocket = function(url, protocols) {
            try { url = toWsProxy(url); } catch(e) {}
            return protocols ? new _WS(url, protocols) : new _WS(url);
        };
        window.WebSocket.prototype = _WS.prototype;
        window.WebSocket.CONNECTING = _WS.CONNECTING;
        window.WebSocket.OPEN = _WS.OPEN;
        window.WebSocket.CLOSING = _WS.CLOSING;
        window.WebSocket.CLOSED = _WS.CLOSED;
    } catch(e) {}

    // --- EventSource (SSE) ---
    try {
        var _ES = window.EventSource;
        if (_ES) {
            window.EventSource = function(url, config) {
                try { url = resolveUrl(url); } catch(e) {}
                return new _ES(url, config);
            };
            window.EventSource.prototype = _ES.prototype;
        }
    } catch(e) {}

    // --- location.assign / location.replace ---
    try {
        var _assign = window.location.assign.bind(window.location);
        window.location.assign = function(url) { _assign(resolveUrl(url)); };
    } catch(e) {}
    try {
        var _locReplace = window.location.replace.bind(window.location);
        window.location.replace = function(url) { _locReplace(resolveUrl(url)); };
    } catch(e) {}

    // --- Form submissions ---
    document.addEventListener('submit', function(e) {
        try {
            var form = e.target;
            var action = form.getAttribute('action') || '';
            var proxied = resolveUrl(action || PAGE_URL);
            if (proxied !== action) { form.action = proxied; }
        } catch(ex) {}
    }, true);

    // --- Notify parent frame before unload so it can re-proxy ---
    window.addEventListener('beforeunload', function() {
        try { window.top.postMessage({ type: 'proxyNav', href: window.location.href }, '*'); } catch(e) {}
    });

    // --- history.pushState / replaceState ---
    try {
        var _push = history.pushState.bind(history);
        var _replaceState = history.replaceState.bind(history);
        history.pushState = function(state, title, url) {
            if (url) url = resolveUrl(url);
            return _push(state, title, url);
        };
        history.replaceState = function(state, title, url) {
            if (url) url = resolveUrl(url);
            return _replaceState(state, title, url);
        };
    } catch(e) {}

    // --- intercept link clicks (catch dynamically added links) ---
    document.addEventListener('click', function(e) {
        try {
            var el = e.target;
            while (el && el.tagName !== 'A') el = el.parentElement;
            if (!el) return;
            var href = el.getAttribute('href');
            if (!href || href.startsWith('#') || href.startsWith('javascript:')) return;
            var proxied = resolveUrl(href);
            if (proxied !== href) {
                e.preventDefault();
                e.stopPropagation();
                // If target="_blank", open in same proxy context
                if (el.target === '_blank') {
                    el.target = '_self';
                }
                window.location.href = proxied;
            }
        } catch(ex) {}
    }, true);

    // --- open() ---
    try {
        var _winOpen = window.open;
        window.open = function(url, target, features) {
            try { url = resolveUrl(url) || url; } catch(e) {}
            return _winOpen.call(window, url, target, features);
        };
    } catch(e) {}

    // --- MutationObserver: rewrite dynamically added elements ---
    try {
        var _observer = new MutationObserver(function(mutations) {
            mutations.forEach(function(m) {
                m.addedNodes.forEach(function(node) {
                    if (node.nodeType !== 1) return;
                    rewriteNode(node);
                    if (node.querySelectorAll) {
                        node.querySelectorAll('[src],[href],[action],[poster],[srcset],[data-src],[data-href]').forEach(rewriteNode);
                    }
                });
            });
        });
        _observer.observe(document.documentElement || document, { childList: true, subtree: true });
    } catch(e) {}

    function rewriteNode(el) {
        try {
            ['src', 'href', 'action', 'poster', 'formaction', 'data-src', 'data-href'].forEach(function(attr) {
                var val = el.getAttribute && el.getAttribute(attr);
                if (val && !val.startsWith('#') && !val.startsWith('javascript:') && val.indexOf('/proxy?url=') !== 0) {
                    var p = resolveUrl(val);
                    if (p !== val) el.setAttribute(attr, p);
                }
            });
            // Rewrite srcset
            var srcset = el.getAttribute && el.getAttribute('srcset');
            if (srcset) {
                var rewritten = srcset.split(',').map(function(part) {
                    var trimmed = part.trim();
                    var sp = trimmed.search(/\\s/);
                    var url = sp === -1 ? trimmed : trimmed.slice(0, sp);
                    var rest = sp === -1 ? '' : trimmed.slice(sp);
                    var p = resolveUrl(url);
                    return (p !== url ? p : url) + rest;
                }).join(', ');
                if (rewritten !== srcset) el.setAttribute('srcset', rewritten);
            }
        } catch(e) {}
    }

    // --- Intercept createElement to catch dynamic script/img/link/iframe creation ---
    try {
        var _createElement = document.createElement.bind(document);
        document.createElement = function(tag) {
            var el = _createElement(tag);
            var tagLower = (tag || '').toLowerCase();
            if (tagLower === 'script' || tagLower === 'img' || tagLower === 'link' || tagLower === 'iframe' || tagLower === 'video' || tagLower === 'audio' || tagLower === 'source') {
                // Intercept .src setter
                var _srcDesc = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'src') ||
                               Object.getOwnPropertyDescriptor(el.__proto__, 'src') ||
                               Object.getOwnPropertyDescriptor(el.__proto__.__proto__, 'src');
                if (_srcDesc && _srcDesc.set) {
                    Object.defineProperty(el, 'src', {
                        get: _srcDesc.get,
                        set: function(v) { _srcDesc.set.call(this, resolveUrl(v)); },
                        configurable: true
                    });
                }
            }
            return el;
        };
    } catch(e) {}

    // --- Intercept image constructor ---
    try {
        var _Image = window.Image;
        window.Image = function(w, h) {
            var img = new _Image(w, h);
            var _srcDesc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src');
            if (_srcDesc && _srcDesc.set) {
                Object.defineProperty(img, 'src', {
                    get: _srcDesc.get,
                    set: function(v) { _srcDesc.set.call(this, resolveUrl(v)); },
                    configurable: true
                });
            }
            return img;
        };
        window.Image.prototype = _Image.prototype;
    } catch(e) {}

    // --- Rewrite all existing elements on DOMContentLoaded ---
    function rewriteAll() {
        try {
            document.querySelectorAll('[src],[href],[action],[poster],[srcset],[data-src],[data-href]').forEach(rewriteNode);
        } catch(e) {}
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', rewriteAll);
    } else {
        rewriteAll();
    }
})();
<` + `/script>`;

    if (/<head\b/i.test(html)) {
        html = html.replace(/<head\b[^>]*>/i, '$&' + interceptScript);
    } else if (/<html\b/i.test(html)) {
        html = html.replace(/<html\b[^>]*>/i, '$&<head>' + interceptScript + '</head>');
    } else {
        html = interceptScript + html;
    }

    return html;
}

function rewriteCss(css, pageUrl) {
    // Rewrite url(...)
    css = css.replace(/url\(\s*(["']?)([^)"']+)\1\s*\)/gi, (match, quote, url) => {
        const p = proxyUrl(url, pageUrl);
        return p ? `url(${quote}${p}${quote})` : match;
    });
    // Rewrite @import "url" and @import 'url'
    css = css.replace(/@import\s+(["'])([^"']+)\1/gi, (match, quote, url) => {
        const p = proxyUrl(url, pageUrl);
        return p ? `@import ${quote}${p}${quote}` : match;
    });
    // Rewrite @import url(...)
    css = css.replace(/@import\s+url\(\s*(["']?)([^)"']+)\1\s*\)/gi, (match, quote, url) => {
        const p = proxyUrl(url, pageUrl);
        return p ? `@import url(${quote}${p}${quote})` : match;
    });
    return css;
}

function rewriteJs(js, pageUrl) {
    // Rewrite absolute URL strings in JS (handles "https://..." and 'https://...')
    // Only rewrite URLs that point to the same origin as the page being proxied
    try {
        const pageOrigin = new URL(pageUrl).origin;
        // Rewrite quoted strings that start with the page's origin
        js = js.replace(/(["'])(https?:\/\/[^"']+)\1/g, (match, quote, url) => {
            try {
                const urlOrigin = new URL(url).origin;
                if (urlOrigin === pageOrigin) {
                    const p = proxyUrl(url, pageUrl);
                    return p ? `${quote}${p}${quote}` : match;
                }
            } catch {}
            return match;
        });
    } catch {}
    return js;
}

// Streaming fetch for binary resources — pipes directly to client without buffering
function streamUrl(urlStr, res, redirectCount) {
    redirectCount = redirectCount || 0;
    if (redirectCount > 10) { res.writeHead(502); res.end('Too many redirects'); return; }

    let parsed;
    try { parsed = new URL(urlStr); } catch (e) { res.writeHead(400); res.end('Bad URL'); return; }

    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;
    const options = {
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: 'GET',
        agent: isHttps ? httpsAgent : httpAgent,
        headers: {
            'Host': parsed.host,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
        },
    };

    const proxyReq = lib.request(options, (proxyRes) => {
        if ([301, 302, 303, 307, 308].includes(proxyRes.statusCode) && proxyRes.headers.location) {
            proxyRes.resume(); // drain
            const next = new URL(proxyRes.headers.location, urlStr).toString();
            return streamUrl(next, res, redirectCount + 1);
        }
        const contentType = proxyRes.headers['content-type'] || 'application/octet-stream';
        const safeHeaders = buildSafeHeaders(proxyRes.headers, contentType);
        delete safeHeaders['content-encoding'];
        delete safeHeaders['transfer-encoding'];
        res.writeHead(proxyRes.statusCode, safeHeaders);

        // Decompress if needed, then pipe
        const encoding = (proxyRes.headers['content-encoding'] || '').toLowerCase();
        let stream = proxyRes;
        if (encoding === 'gzip') stream = proxyRes.pipe(zlib.createGunzip());
        else if (encoding === 'deflate') stream = proxyRes.pipe(zlib.createInflate());
        else if (encoding === 'br') stream = proxyRes.pipe(zlib.createBrotliDecompress());

        stream.pipe(res);
        stream.on('error', () => res.end());
    });

    proxyReq.on('error', () => { try { res.writeHead(502); res.end('Fetch error'); } catch {} });
    proxyReq.setTimeout(30000, () => { proxyReq.destroy(); });
    proxyReq.end();
}

// Smart proxy: streams binary responses directly, buffers text (HTML/CSS/JS) for rewriting
function smartProxy(urlStr, clientRes, clientReq, redirectCount) {
    redirectCount = redirectCount || 0;
    if (redirectCount > 10) { clientRes.writeHead(502); clientRes.end('Too many redirects'); return; }

    let parsed;
    try { parsed = new URL(urlStr); } catch (e) { clientRes.writeHead(400); clientRes.end('Bad URL'); return; }

    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;
    const method = (clientReq && clientReq.method) || 'GET';
    const headers = {
        'Host': parsed.host,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Origin': parsed.origin,
        'Referer': parsed.origin + '/',
    };
    // Forward cookies from client
    if (clientReq && clientReq.headers) {
        if (clientReq.headers['cookie']) headers['Cookie'] = clientReq.headers['cookie'];
        if (clientReq.headers['content-type']) headers['Content-Type'] = clientReq.headers['content-type'];
        if (clientReq.headers['authorization']) headers['Authorization'] = clientReq.headers['authorization'];
        if (clientReq.headers['range']) headers['Range'] = clientReq.headers['range'];
        if (clientReq.headers['accept']) headers['Accept'] = clientReq.headers['accept'];
        if (clientReq.headers['if-none-match']) headers['If-None-Match'] = clientReq.headers['if-none-match'];
        if (clientReq.headers['if-modified-since']) headers['If-Modified-Since'] = clientReq.headers['if-modified-since'];
        // Forward Discord-specific headers
        for (const h of ['x-super-properties', 'x-discord-locale', 'x-discord-timezone', 'x-debug-options', 'x-fingerprint', 'x-context-properties', 'x-requested-with']) {
            if (clientReq.headers[h]) headers[h] = clientReq.headers[h];
        }
    }
    const options = {
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: method,
        agent: isHttps ? httpsAgent : httpAgent,
        headers: headers,
    };

    // For methods with a body, pipe the client request body to the proxy request
    const proxyReq = lib.request(options, (proxyRes) => {
        if ([301, 302, 303, 307, 308].includes(proxyRes.statusCode) && proxyRes.headers.location) {
            proxyRes.resume();
            const next = new URL(proxyRes.headers.location, urlStr).toString();
            return smartProxy(next, clientRes, clientReq, redirectCount + 1);
        }

        const contentType = proxyRes.headers['content-type'] || 'application/octet-stream';
        const safeHeaders = buildSafeHeaders(proxyRes.headers, contentType);
        delete safeHeaders['content-encoding'];
        delete safeHeaders['transfer-encoding'];
        delete safeHeaders['content-length'];

        const encoding = (proxyRes.headers['content-encoding'] || '').toLowerCase();
        let decompressed = proxyRes;
        if (encoding === 'gzip') decompressed = proxyRes.pipe(zlib.createGunzip());
        else if (encoding === 'deflate') decompressed = proxyRes.pipe(zlib.createInflate());
        else if (encoding === 'br') decompressed = proxyRes.pipe(zlib.createBrotliDecompress());

        const needsRewrite = contentType.includes('text/html') ||
                             contentType.includes('text/css') ||
                             contentType.includes('javascript') ||
                             contentType.includes('text/js') ||
                             contentType.includes('application/json');

        if (needsRewrite) {
            // Buffer text content for rewriting
            const chunks = [];
            decompressed.on('data', chunk => chunks.push(chunk));
            decompressed.on('end', () => {
                let text = Buffer.concat(chunks).toString('utf8');
                if (contentType.includes('text/html')) text = rewriteHtml(text, urlStr);
                else if (contentType.includes('text/css')) text = rewriteCss(text, urlStr);
                else if (contentType.includes('javascript') || contentType.includes('text/js')) text = rewriteJs(text, urlStr);
                // JSON passes through without rewriting (but we still strip blocked headers)
                clientRes.writeHead(proxyRes.statusCode, safeHeaders);
                clientRes.end(text);
            });
            decompressed.on('error', () => { try { clientRes.writeHead(502); clientRes.end('Decode error'); } catch {} });
        } else {
            // Stream binary content directly — no buffering
            clientRes.writeHead(proxyRes.statusCode, safeHeaders);
            decompressed.pipe(clientRes);
            decompressed.on('error', () => clientRes.end());
        }
    });

    proxyReq.on('error', () => { try { clientRes.writeHead(502); clientRes.end('Fetch error'); } catch {} });
    proxyReq.setTimeout(30000, () => { proxyReq.destroy(); });
    // For POST/PUT/PATCH, pipe the client request body
    if (clientReq && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
        clientReq.pipe(proxyReq);
    } else {
        proxyReq.end();
    }
}

const server = http.createServer((req, res) => {
    if (req.url === '/' || req.url === '/index.html') {
        const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(html);
        return;
    }

    // Serve favicon to prevent unnecessary fallback proxy attempts
    if (req.url === '/favicon.ico') {
        res.writeHead(204);
        res.end();
        return;
    }

    if (req.url.startsWith('/proxy?')) {
        let targetUrl;
        try {
            const reqParsed = new URL(req.url, 'http://localhost');
            targetUrl = reqParsed.searchParams.get('url');
            if (!targetUrl) throw new Error('missing url param');
            const parsed = new URL(targetUrl);
            if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                res.end('Only http/https URLs are allowed');
                return;
            }
        } catch {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            res.end('Invalid URL');
            return;
        }

        // Handle CORS preflight
        if (req.method === 'OPTIONS') {
            res.writeHead(204, {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD',
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Allow-Credentials': 'true',
                'Access-Control-Max-Age': '86400',
            });
            res.end();
            return;
        }

        // Use smartProxy for ALL methods — it now supports POST/PUT/PATCH/DELETE with body piping
        return smartProxy(targetUrl, res, req);
    }

    // Handle CORS preflight for any path (fallback routes)
    if (req.method === 'OPTIONS') {
        res.writeHead(204, {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD',
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Max-Age': '86400',
        });
        res.end();
        return;
    }

    // Fallback: if the request has a Referer pointing to a proxied page,
    // auto-proxy the request against the original site's origin.
    // This handles relative URLs that the browser resolves against localhost.
    const referer = req.headers['referer'] || '';
    let fallbackOrigin = null;
    try {
        const refParsed = new URL(referer);
        // Check if referer points to our proxy — extract the real origin from ?url= param
        const refTargetUrl = refParsed.searchParams.get('url');
        if (refTargetUrl) {
            fallbackOrigin = new URL(refTargetUrl).origin;
        }
        // Also check if the referer path starts with /proxy?url= (for nested cases)
        if (!fallbackOrigin && refParsed.pathname === '/proxy') {
            const urlParam = refParsed.searchParams.get('url');
            if (urlParam) fallbackOrigin = new URL(urlParam).origin;
        }
    } catch {}

    // Secondary check: look at the Origin header
    if (!fallbackOrigin) {
        try {
            const originHeader = req.headers['origin'] || '';
            if (originHeader) {
                const originParsed = new URL(originHeader);
                // Our own origin — not useful for determining the target
            }
        } catch {}
    }

    if (fallbackOrigin) {
        const proxiedTarget = fallbackOrigin + req.url;
        // Use smart streaming proxy for fallback requests too
        return smartProxy(proxiedTarget, res, req);
    }

    res.writeHead(404);
    res.end('Not found');
});

// --- WebSocket tunnel ---
server.on('upgrade', (req, socket, head) => {
    let targetUrl;
    try {
        const parsed = new URL(req.url, 'http://localhost');
        if (!parsed.pathname.startsWith('/wsproxy')) { socket.destroy(); return; }
        targetUrl = parsed.searchParams.get('url');
        if (!targetUrl) throw new Error('no url');
    } catch { socket.destroy(); return; }

    let target;
    try { target = new URL(targetUrl); } catch { socket.destroy(); return; }

    const isSecure = target.protocol === 'wss:';
    const port = parseInt(target.port) || (isSecure ? 443 : 80);
    const lib = isSecure ? tls : net;
    const connectOpts = isSecure
        ? { host: target.hostname, port, servername: target.hostname }
        : { host: target.hostname, port };

    const targetSocket = lib.connect(connectOpts, () => {
        // Forward the WebSocket upgrade request to the real server
        const headers = [
            `GET ${target.pathname}${target.search || ''} HTTP/1.1`,
            `Host: ${target.host}`,
            'Upgrade: websocket',
            'Connection: Upgrade',
            `Sec-WebSocket-Key: ${req.headers['sec-websocket-key'] || ''}`,
            `Sec-WebSocket-Version: ${req.headers['sec-websocket-version'] || '13'}`,
        ];
        if (req.headers['sec-websocket-extensions'])
            headers.push(`Sec-WebSocket-Extensions: ${req.headers['sec-websocket-extensions']}`);
        if (req.headers['sec-websocket-protocol'])
            headers.push(`Sec-WebSocket-Protocol: ${req.headers['sec-websocket-protocol']}`);
        headers.push('', '');
        targetSocket.write(headers.join('\r\n'));
        if (head && head.length) targetSocket.write(head);
    });

    targetSocket.on('data', d => { try { socket.write(d); } catch(e) {} });
    socket.on('data', d => { try { targetSocket.write(d); } catch(e) {} });
    targetSocket.on('end', () => socket.end());
    socket.on('end', () => targetSocket.end());
    targetSocket.on('error', () => socket.destroy());
    socket.on('error', () => targetSocket.destroy());
});

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`Port ${PORT} is already in use. Run this to free it:\n  Stop-Process -Id (Get-NetTCPConnection -LocalPort ${PORT}).OwningProcess -Force`);
    } else {
        console.error(err);
    }
    process.exit(1);
});

server.listen(PORT, () => {
    console.log(`Web Viewer running at http://localhost:${PORT}`);
});

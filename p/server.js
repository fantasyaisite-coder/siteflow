const express = require('express');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const { createProxyMiddleware } = require('http-proxy-middleware');
const http = require('http');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = 'admin123';
const PROFILES_FILE = path.join(__dirname, 'profiles.json');

// ---------- Middleware ----------
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ---------- Session (simple memory store) ----------
const sessions = {};

function requireAdmin(req, res, next) {
    const token = req.query.token || req.body.token;
    if (token && sessions[token]) return next();
    if (req.headers.cookie && req.headers.cookie.includes('admin_token=')) {
        const match = req.headers.cookie.match(/admin_token=([^;]+)/);
        if (match && sessions[match[1]]) return next();
    }
    res.redirect('/login');
}

// ---------- Data helpers ----------
function loadProfiles() {
    try {
        const data = fs.readFileSync(PROFILES_FILE, 'utf-8');
        return JSON.parse(data);
    } catch { return []; }
}

function saveProfiles(profiles) {
    fs.writeFileSync(PROFILES_FILE, JSON.stringify(profiles, null, 2), 'utf-8');
}

// ---------- Auth Routes ----------
app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', (req, res) => {
    const { password } = req.body;
    if (password === ADMIN_PASSWORD) {
        const token = uuidv4();
        sessions[token] = { createdAt: Date.now() };
        res.cookie('admin_token', token, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 });
        return res.redirect(`/admin?token=${token}`);
    }
    res.render('login', { error: 'Invalid password!' });
});

app.get('/logout', (req, res) => {
    const token = req.query.token || req.body.token;
    if (token) delete sessions[token];
    res.clearCookie('admin_token');
    res.redirect('/login');
});

// ---------- Admin Routes ----------
app.get('/admin', requireAdmin, (req, res) => {
    const token = req.query.token || '';
    const profiles = loadProfiles();
    const isRender = process.env.RENDER === 'true';
    const baseUrl = isRender
        ? `https://${req.hostname}`
        : `${req.protocol}://${req.hostname}${process.env.PORT && process.env.PORT !== '80' && process.env.PORT !== '443' ? ':' + process.env.PORT : ''}`;
    res.render('dashboard', { profiles, token, message: req.query.msg || null, baseUrl });
});

app.get('/admin/create', requireAdmin, (req, res) => {
    const token = req.query.token || '';
    res.render('create', { token, error: null, profile: null });
});

app.post('/admin/create', requireAdmin, (req, res) => {
    const token = req.query.token || req.body.token || '';
    const { name, targetUrl, cookieInput, cookieFormat } = req.body;

    if (!name || !targetUrl) {
        return res.render('create', { token, error: 'Name and Target URL are required!', profile: null });
    }

    let cookies = [];
    try {
        if (cookieFormat === 'json' && cookieInput) {
            cookies = JSON.parse(cookieInput);
            if (!Array.isArray(cookies)) cookies = [cookies];
        } else if (cookieFormat === 'raw' && cookieInput) {
            cookies = parseRawCookies(cookieInput);
        }
    } catch (e) {
        return res.render('create', { token, error: 'Invalid cookie format: ' + e.message, profile: null });
    }

    const profile = {
        id: uuidv4().replace(/-/g, '').substring(0, 12),
        name,
        targetUrl,
        cookies,
        createdAt: new Date().toISOString()
    };

    const profiles = loadProfiles();
    profiles.push(profile);
    saveProfiles(profiles);

    res.redirect(`/admin?token=${token}&msg=Profile created successfully!`);
});

app.get('/admin/edit/:id', requireAdmin, (req, res) => {
    const token = req.query.token || '';
    const profiles = loadProfiles();
    const profile = profiles.find(p => p.id === req.params.id);
    if (!profile) return res.redirect(`/admin?token=${token}&msg=Profile not found`);
    res.render('create', { token, error: null, profile });
});

app.post('/admin/edit/:id', requireAdmin, (req, res) => {
    const token = req.query.token || req.body.token || '';
    const { name, targetUrl, cookieInput, cookieFormat } = req.body;
    const profiles = loadProfiles();
    const idx = profiles.findIndex(p => p.id === req.params.id);
    if (idx === -1) return res.redirect(`/admin?token=${token}&msg=Profile not found`);

    let cookies = profiles[idx].cookies;
    try {
        if (cookieInput) {
            if (cookieFormat === 'json') {
                cookies = JSON.parse(cookieInput);
                if (!Array.isArray(cookies)) cookies = [cookies];
            } else if (cookieFormat === 'raw') {
                cookies = parseRawCookies(cookieInput);
            }
        }
    } catch (e) {
        return res.render('create', { token, error: 'Invalid cookie format: ' + e.message, profile: profiles[idx] });
    }

    profiles[idx] = { ...profiles[idx], name, targetUrl, cookies };
    saveProfiles(profiles);
    res.redirect(`/admin?token=${token}&msg=Profile updated!`);
});

app.post('/admin/delete/:id', requireAdmin, (req, res) => {
    const token = req.query.token || req.body.token || '';
    let profiles = loadProfiles();
    profiles = profiles.filter(p => p.id !== req.params.id);
    saveProfiles(profiles);
    res.redirect(`/admin?token=${token}&msg=Profile deleted!`);
});

app.post('/admin/test/:id', requireAdmin, (req, res) => {
    const token = req.query.token || req.body.token || '';
    const profiles = loadProfiles();
    const profile = profiles.find(p => p.id === req.params.id);
    if (!profile) return res.json({ ok: false, error: 'Profile not found' });

    const urlObj = new URL(profile.targetUrl);
    const testPath = urlObj.pathname === '' ? '/' : urlObj.pathname;
    const options = {
        hostname: urlObj.hostname,
        port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
        path: testPath,
        method: 'HEAD',
        timeout: 10000,
        rejectUnauthorized: false
    };

    const lib = urlObj.protocol === 'https:' ? https : http;
    const reqHttp = lib.request(options, (resp) => {
        res.json({ ok: true, statusCode: resp.statusCode, message: 'Target is reachable' });
    });
    reqHttp.on('error', (e) => {
        res.json({ ok: false, error: e.message });
    });
    reqHttp.end();
});

// ---------- Proxy Route ----------
app.all('/go/:id*', (req, res, next) => {
    const profiles = loadProfiles();
    const profile = profiles.find(p => p.id === req.params.id);

    if (!profile) {
        return res.status(404).send(`
            <html><body style="font-family:sans-serif;text-align:center;padding:60px">
                <h1>404 - Profile Not Found</h1>
                <p>The injection link is invalid or the profile has been deleted.</p>
                <a href="/login">Go to Admin</a>
            </body></html>
        `);
    }

    const targetUrl = profile.targetUrl.replace(/\/+$/, '');
    const targetObj = new URL(targetUrl);
    const basePath = `/go/${profile.id}`;

    // Build proxy options
    const proxyOptions = {
        target: targetUrl,
        changeOrigin: true,
        selfHandleResponse: true,
        ws: true,
        pathRewrite: {
            [`^${basePath}`]: ''
        },
        onProxyReq: (proxyReq, req, res) => {
            // Build cookie string from profile cookies
            const cookieParts = profile.cookies.map(c => {
                let cookieStr = `${encodeURIComponent(c.name)}=${encodeURIComponent(c.value || '')}`;
                if (c.domain) cookieStr += `; Domain=${c.domain}`;
                if (c.path) cookieStr += `; Path=${c.path}`;
                if (c.secure || c.name.startsWith('__Secure-') || c.name.startsWith('__Host-')) cookieStr += '; Secure';
                if (c.httpOnly) cookieStr += '; HttpOnly';
                if (c.sameSite) cookieStr += `; SameSite=${c.sameSite}`;
                if (c.maxAge) cookieStr += `; Max-Age=${c.maxAge}`;
                if (c.name.startsWith('__Host-') && !c.path) cookieStr += '; Path=/';
                return cookieStr;
            });

            // Append to existing cookies
            const existingCookie = proxyReq.getHeader('cookie') || '';
            if (existingCookie) {
                proxyReq.setHeader('cookie', existingCookie + '; ' + cookieParts.join('; '));
            } else {
                proxyReq.setHeader('cookie', cookieParts.join('; '));
            }
        },
        onProxyRes: (proxyRes, req, res) => {
            // Inject Set-Cookie headers from profile
            profile.cookies.forEach(c => {
                let setCookieStr = `${encodeURIComponent(c.name)}=${encodeURIComponent(c.value || '')}`;
                if (c.domain) setCookieStr += `; Domain=${c.domain}`;
                if (c.path) setCookieStr += `; Path=${c.path}`;
                if (c.secure || c.name.startsWith('__Secure-') || c.name.startsWith('__Host-')) setCookieStr += '; Secure';
                if (c.httpOnly) setCookieStr += '; HttpOnly';
                if (c.sameSite) setCookieStr += `; SameSite=${c.sameSite}`;
                if (c.maxAge) setCookieStr += `; Max-Age=${c.maxAge}`;
                if (c.name.startsWith('__Host-')) setCookieStr += '; Path=/';
                if (c.expires) setCookieStr += `; Expires=${c.expires}`;

                proxyRes.headers['set-cookie'] = proxyRes.headers['set-cookie'] || [];
                if (Array.isArray(proxyRes.headers['set-cookie'])) {
                    proxyRes.headers['set-cookie'].push(setCookieStr);
                } else {
                    proxyRes.headers['set-cookie'] = [proxyRes.headers['set-cookie'], setCookieStr];
                }
            });

            // Rewrite redirects and links
            let body = '';
            const originalWrite = res.write;
            const originalEnd = res.end;
            const chunks = [];

            res.write = function (chunk) {
                chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
                return true;
            };
            res.end = function (chunk) {
                if (chunk) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
                body = Buffer.concat(chunks).toString('utf-8');

                // Rewrite absolute URLs in content
                const escapedTarget = targetUrl.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                const baseUrl = `${req.protocol}://${req.hostname}${basePath}`;

                body = body.replace(
                    new RegExp(`(href|src|action)=["']${escapedTarget}`, 'gi'),
                    `$1="${baseUrl}`
                );
                body = body.replace(
                    /(href|src|action)=["'](\/[^"']*)/gi,
                    (match, attr, uri) => {
                        if (uri.startsWith(basePath)) return match;
                        return `${attr}=${basePath}${uri}`;
                    }
                );
                body = body.replace(
                    /(href|src|action)=["'](https?:\/\/[^"']+)["']/gi,
                    (match, attr, uri) => {
                        if (uri.startsWith(targetUrl.replace(/\/+$/, ''))) {
                            return `${attr}="${baseUrl}${uri.substring(targetUrl.replace(/\/+$/, '').length)}"`;
                        }
                        return match;
                    }
                );

                // Inject status bar
                if (res.statusCode === 200 && body.includes('</body>')) {
                    const statusHtml = `
                        <div id="cip-status" style="position:fixed;bottom:0;left:0;right:0;z-index:99999;background:linear-gradient(135deg,#1e293b,#334155);color:#fff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:13px;padding:10px 20px;display:flex;align-items:center;justify-content:center;gap:12px;border-top:2px solid #6366f1;box-shadow:0 -4px 20px rgba(0,0,0,0.3);">
                            <span style="width:10px;height:10px;background:#22c55e;border-radius:50%;display:inline-block;animation:pulse 2s infinite;"></span>
                            <strong style="color:#a5b4fc;">Cookies Injected</strong>
                            <span style="color:#94a3b8;">|</span>
                            <span style="color:#cbd5e1;">Profile: <span style="color:#f472b6;">${profile.name}</span></span>
                            <span style="color:#94a3b8;">|</span>
                            <span style="color:#cbd5e1;">${profile.cookies.length} cookie(s) injected</span>
                            <style>@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}</style>
                        </div>
                    `;
                    body = body.replace('</body>', statusHtml + '\n</body>');
                }

                // Fix content-length
                const newBuffer = Buffer.from(body, 'utf-8');
                if (proxyRes.headers['content-length']) {
                    res.setHeader('content-length', newBuffer.length);
                }

                res.writeHead(res.statusCode, proxyRes.headers);
                originalEnd.call(res, newBuffer);
            };
        },
        onError: (err, req, res) => {
            res.status(502).send(`
                <html><body style="font-family:sans-serif;text-align:center;padding:60px">
                    <h1>502 - Bad Gateway</h1>
                    <p>Could not reach the target: ${err.message}</p>
                    <a href="/login">Go to Admin</a>
                </body></html>
            `);
        }
    };

    // Handle WebSocket upgrade
    app.on('upgrade', (req, socket, head) => {
        if (req.url.startsWith(basePath)) {
            proxy.ws(req, socket, head);
        }
    });

    const proxy = createProxyMiddleware(proxyOptions);
    return proxy(req, res, next);
});

// ---------- Utility: Parse raw cookie strings ----------
function parseRawCookies(input) {
    const lines = input.split('\n').filter(l => l.trim());
    const cookies = [];

    for (const line of lines) {
        const parts = line.split(';').map(p => p.trim());
        const firstEq = parts[0].indexOf('=');
        if (firstEq === -1) continue;

        const name = decodeURIComponent(parts[0].substring(0, firstEq).trim());
        const value = decodeURIComponent(parts[0].substring(firstEq + 1).trim());
        const cookie = { name, value };

        for (let i = 1; i < parts.length; i++) {
            const eqIdx = parts[i].indexOf('=');
            const key = eqIdx === -1 ? parts[i].toLowerCase() : parts[i].substring(0, eqIdx).toLowerCase();
            const val = eqIdx === -1 ? '' : parts[i].substring(eqIdx + 1);
            if (key === 'domain') cookie.domain = val;
            if (key === 'path') cookie.path = val;
            if (key === 'secure') cookie.secure = true;
            if (key === 'httponly') cookie.httpOnly = true;
            if (key === 'samesite') cookie.sameSite = val;
            if (key === 'max-age') cookie.maxAge = parseInt(val);
            if (key === 'expires') cookie.expires = val;
        }

        cookies.push(cookie);
    }
    return cookies;
}

// ---------- Home Route ----------
app.get('/', (req, res) => {
    res.redirect('/login');
});

// ---------- Start ----------
app.listen(PORT, () => {
    console.log(`\n  🍪 Cookie Injection Proxy Tool`);
    console.log(`  ─────────────────────────────`);
    console.log(`  Admin Panel : http://localhost:${PORT}/admin`);
    console.log(`  Login       : http://localhost:${PORT}/login`);
    console.log(`  Password    : admin123`);
    console.log(`\n  Server running on port ${PORT}\n`);
});

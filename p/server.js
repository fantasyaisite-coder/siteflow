const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cookieParser = require('cookie-parser');
const path = require('path');
const uuid = require('uuid');
const { URL } = require('url');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// --- SQLite Database Setup ---
const dbPath = process.env.RENDER ? '/opt/render/project/data/proxy_data.db' : path.join(__dirname, 'proxy_data.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    targetUrl TEXT NOT NULL,
    cookies TEXT NOT NULL
  )
`);

// --- Middleware ---
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// --- Helper Functions ---
function parseCookies(cookieString, format) {
    try {
        if (format === 'json') {
            const parsed = JSON.parse(cookieString);
            if (!Array.isArray(parsed)) throw new Error('JSON must be an array');
            return parsed.map(c => ({
                name: c.name, value: c.value,
                domain: c.domain || '', path: c.path || '/',
                secure: c.secure || false, httpOnly: c.httpOnly || false,
                sameSite: c.sameSite || 'Lax'
            }));
        } else {
            return cookieString.split(';').map(pair => {
                const [name, ...rest] = pair.trim().split('=');
                return {
                    name: name.trim(), value: rest.join('=').trim(),
                    domain: '', path: '/', secure: false, httpOnly: false, sameSite: 'Lax'
                };
            });
        }
    } catch (e) {
        console.error('Cookie parsing error:', e);
        return null;
    }
}

// --- Auth Middleware ---
function requireAuth(req, res, next) {
    if (req.cookies && req.cookies.admin_auth === ADMIN_PASSWORD) {
        return next();
    }
    res.redirect('/admin/login');
}

// --- Admin Routes ---
app.set('view engine', 'ejs');

app.get('/admin/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/admin/login', (req, res) => {
    if (req.body.password === ADMIN_PASSWORD) {
        res.cookie('admin_auth', ADMIN_PASSWORD, { httpOnly: true, maxAge: 86400000, secure: true, sameSite: 'strict' });
        res.redirect('/admin');
    } else {
        res.render('login', { error: 'Invalid password' });
    }
});

app.get('/admin/logout', (req, res) => {
    res.clearCookie('admin_auth');
    res.redirect('/admin/login');
});

app.get('/admin', requireAuth, (req, res) => {
    const profiles = db.prepare('SELECT * FROM profiles').all().map(p => ({
        ...p,
        cookies: JSON.parse(p.cookies)
    }));
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    res.render('dashboard', { profiles, baseUrl, msg: req.query.msg, error: req.query.error });
});

app.post('/admin/profile', requireAuth, (req, res) => {
    const { name, targetUrl, cookies, cookieFormat } = req.body;
    const parsedCookies = parseCookies(cookies, cookieFormat);
    
    if (!parsedCookies) return res.redirect('/admin?error=Invalid cookie format.');
    try {
        new URL(targetUrl);
    } catch (e) {
        return res.redirect('/admin?error=Invalid Target URL format.');
    }

    const id = uuid.v4().substring(0, 8);
    
    db.prepare('INSERT INTO profiles (id, name, targetUrl, cookies) VALUES (?, ?, ?, ?)')
      .run(id, name, targetUrl, JSON.stringify(parsedCookies));
      
    res.redirect('/admin?msg=Profile created successfully!');
});

app.post('/admin/profile/:id/delete', requireAuth, (req, res) => {
    db.prepare('DELETE FROM profiles WHERE id = ?').run(req.params.id);
    res.redirect('/admin?msg=Profile deleted successfully!');
});

// --- PROXY SYSTEM ---
app.use('/go/:id', (req, res, next) => {
    const profile = db.prepare('SELECT * FROM profiles WHERE id = ?').get(req.params.id);
    if (!profile) return res.status(404).send('Proxy profile not found.');
    
    req.targetProfile = {
        ...profile,
        cookies: JSON.parse(profile.cookies)
    };
    next();
}, createProxyMiddleware({
    target: 'http://dummy-required-host.com',
    router: (req) => {
        const url = new URL(req.targetProfile.targetUrl);
        return url.origin;
    },
    pathRewrite: (path, req) => {
        const url = new URL(req.targetProfile.targetUrl);
        const basePath = `/go/${req.targetProfile.id}`;
        const remainingPath = path.startsWith(basePath) ? path.slice(basePath.length) : path;
        return url.pathname === '/' ? remainingPath : url.pathname + remainingPath;
    },
    changeOrigin: true,
    secure: false,
    cookieDomainRewrite: { '*': '' },
    followRedirects: true,
    
    onProxyReq: (proxyReq, req, res) => {
        const profile = req.targetProfile;
        const cookieHeader = profile.cookies.map(c => `${c.name}=${c.value}`).join('; ');
        proxyReq.setHeader('Cookie', cookieHeader);
    },

    onProxyRes: (proxyRes, req, res) => {
        const profile = req.targetProfile;
        const existingCookies = proxyRes.headers['set-cookie'] || [];

        profile.cookies.forEach(c => {
            let cookieStr = `${c.name}=${c.value}; Path=${c.path || '/'}`;
            if (c.secure || c.name.startsWith('__Secure-')) cookieStr += '; Secure';
            if (c.httpOnly) cookieStr += '; HttpOnly';
            if (c.sameSite) cookieStr += `; SameSite=${c.sameSite}`;
            if (c.name.startsWith('__Host-')) cookieStr += '; Secure'; 
            existingCookies.push(cookieStr);
        });

        proxyRes.headers['set-cookie'] = existingCookies;
        proxyRes.headers['X-Cookie-Injection'] = 'Success'; 
    },

    onError: (err, req, res) => {
        console.error('Proxy Error:', err);
        res.status(500).send('Proxy Error: Could not connect to the target website.');
    }
}));

app.listen(PORT, () => {
    console.log(`🚀 Cookie Proxy Tool running on port ${PORT}`);
});

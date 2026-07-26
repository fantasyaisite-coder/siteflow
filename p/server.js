const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');
const uuid = require('uuid');
const { URL } = require('url');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// --- Safe JSON File Setup ---
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'profiles.json');

function ensureDataFileExists() {
    try {
        if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
        if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, '[]', 'utf8');
    } catch (err) {
        console.error("Failed to create data file:", err);
    }
}

function getProfiles() {
    try {
        ensureDataFileExists();
        const data = fs.readFileSync(DATA_FILE, 'utf8');
        const parsed = JSON.parse(data);
        return Array.isArray(parsed) ? parsed : [];
    } catch (e) {
        console.error("Error reading profiles:", e);
        return [];
    }
}

function saveProfiles(profiles) {
    try {
        ensureDataFileExists();
        fs.writeFileSync(DATA_FILE, JSON.stringify(profiles, null, 2));
    } catch (e) {
        console.error("Error saving profiles:", e);
    }
}

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

// ==========================================
// 1. ADMIN & CONTROL ROUTES (Never Proxied)
// ==========================================
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
    const profiles = getProfiles();
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    res.render('dashboard', { profiles, baseUrl, msg: req.query.msg, error: req.query.error });
});

app.post('/admin/profile', requireAuth, (req, res) => {
    const profiles = getProfiles();
    const { name, targetUrl, cookies, cookieFormat } = req.body;
    const parsedCookies = parseCookies(cookies, cookieFormat);
    
    if (!parsedCookies) return res.redirect('/admin?error=Invalid cookie format.');
    try {
        new URL(targetUrl);
    } catch (e) {
        return res.redirect('/admin?error=Invalid Target URL format.');
    }

    const id = uuid.v4().substring(0, 8);
    profiles.push({ id, name, targetUrl, cookies: parsedCookies });
    saveProfiles(profiles);
    res.redirect('/admin?msg=Profile created successfully!');
});

app.post('/admin/profile/:id/delete', requireAuth, (req, res) => {
    let profiles = getProfiles();
    profiles = profiles.filter(p => p.id !== req.params.id);
    saveProfiles(profiles);
    res.redirect('/admin?msg=Profile deleted successfully!');
});

// --- Proxy Init Route ---
// When user clicks share link, set session cookie and redirect to target path
app.get('/go/:id', (req, res) => {
    const profiles = getProfiles();
    const profile = profiles.find(p => p.id === req.params.id);
    
    if (!profile) return res.status(404).send('Proxy profile not found.');
    
    // Set cookie to remember this profile for all subsequent page navigation
    res.cookie('proxy_id', profile.id, { httpOnly: true, maxAge: 86400000 });
    
    // Redirect to the target URL's path on our own domain
    const targetUrl = new URL(profile.targetUrl);
    res.redirect(targetUrl.pathname + targetUrl.search);
});

// Route to stop the proxy session and return to admin
app.get('/proxy-stop', (req, res) => {
    res.clearCookie('proxy_id');
    res.redirect('/admin');
});


// ==========================================
// 2. DYNAMIC PROXY MIDDLEWARE
// ==========================================
const proxyMiddleware = createProxyMiddleware({
    target: 'http://dummy-required-host.com', // Fallback, overridden by router below
    router: (req) => {
        // Since our wrapper below guarantees req.targetProfile exists, this will NEVER fail!
        return new URL(req.targetProfile.targetUrl).origin;
    },
    changeOrigin: true,
    secure: false,
    cookieDomainRewrite: { '*': '' },
    followRedirects: true,
    selfHandleResponse: false,
    
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
});

// CONDITIONAL WRAPPER: This ensures the proxy ONLY runs if the user has a valid proxy session!
app.use((req, res, next) => {
    // 1. If no proxy cookie is present, skip the proxy completely
    if (!req.cookies || !req.cookies.proxy_id) {
        return next();
    }

    // 2. Find the profile associated with their cookie
    const profiles = getProfiles();
    const profile = profiles.find(p => p.id === req.cookies.proxy_id);

    // 3. If profile was deleted or invalid, clear cookie and skip proxy
    if (!profile) {
        res.clearCookie('proxy_id');
        return res.redirect('/admin');
    }

    // 4. Attach profile to req so the proxy can use it safely
    req.targetProfile = profile;

    // 5. Execute the proxy middleware!
    return proxyMiddleware(req, res, next);
});


// ==========================================
// 3. FALLBACK ROUTE (Not in Proxy Mode)
// ==========================================
// If a user gets here, it means they are NOT in proxy mode. Redirect to admin!
app.use((req, res) => {
    res.redirect('/admin');
});

// --- Global Error Handler ---
app.use((err, req, res, next) => {
    console.error('Unhandled Error:', err);
    res.status(500).send(`
        <h1>Internal Server Error</h1>
        <pre style="background: #f0f0f0; padding: 20px; border-radius: 5px; overflow-x: auto;">${err.stack}</pre>
    `);
});

app.listen(PORT, () => {
    console.log(`🚀 Cookie Proxy Tool running on port ${PORT}`);
});

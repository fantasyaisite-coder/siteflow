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
// 1. ADMIN & CONTROL ROUTES
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
    
    // Set a cookie to remember this profile for all subsequent page navigation
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
// 2. DYNAMIC PROXY MIDDLEWARE (STEALTH MODE + RESIDENTIAL PROXY)
// ==========================================
const proxyMiddleware = createProxyMiddleware({
    target: 'http://dummy-required-host.com', // Fallback target
    router: (req) => {
        try {
            return new URL(req.targetProfile.targetUrl).origin;
        } catch(e) {
            console.error("Router Error:", e);
            return 'http://localhost'; // Fallback to prevent crash
        }
    },
    changeOrigin: true,
    secure: false,
    cookieDomainRewrite: { '*': '' },
    followRedirects: true,
    selfHandleResponse: false,
    timeout: 30000, 
    proxyTimeout: 30000,
    
    // ==========================================
    // THE ULTIMATE WAF BYPASS: RESIDENTIAL PROXY
    // ==========================================
    // To bypass strict "Unusual Activity" Cloudflare blocks, add a Residential Proxy URL 
    // in your Render Environment Variables (Key: RESIDENTIAL_PROXY_URL).
    // Format: http://username:password@gate.smartproxy.com:7000
    // Leave it blank (false) if you don't have one.
    proxy: process.env.RESIDENTIAL_PROXY_URL || false,
    
    onProxyReq: (proxyReq, req, res) => {
        if (!req.targetProfile) return;
        try {
            const profile = req.targetProfile;
            const targetOrigin = new URL(profile.targetUrl).origin;

            // ==========================================
            // STEALTH INJECTION: Look exactly like a real browser
            // ==========================================

            // 1. REMOVE ALL PROXY HEADERS (WAFs check these to block bots instantly!)
            proxyReq.removeHeader('X-Forwarded-For');
            proxyReq.removeHeader('X-Forwarded-Host');
            proxyReq.removeHeader('X-Forwarded-Proto');
            proxyReq.removeHeader('X-Real-Ip');

            // 2. SPOOF ORIGIN & REFERER (Must match the target site perfectly)
            proxyReq.setHeader('Origin', targetOrigin);
            proxyReq.setHeader('Referer', targetOrigin + req.path);

            // 3. INJECT COOKIES
            const cookieHeader = profile.cookies.map(c => `${c.name}=${c.value}`).join('; ');
            proxyReq.setHeader('Cookie', cookieHeader);
            
            // 4. FORWARD MODERN BROWSER SEC- HEADERS (Crucial for Next.js/Cloudflare)
            const secHeaders = [
                'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 
                'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site'
            ];
            
            secHeaders.forEach(h => {
                if (req.headers[h]) {
                    proxyReq.setHeader(h, req.headers[h]);
                } else {
                    proxyReq.removeHeader(h); // Don't send empty sec headers
                }
            });

            // 5. FORWARD REAL BROWSER HEADERS + UPGRADE-INSECURE-REQUESTS
            if (req.headers['user-agent']) proxyReq.setHeader('User-Agent', req.headers['user-agent']);
            
            if (req.headers['accept']) {
                proxyReq.setHeader('Accept', req.headers['accept']);
            } else {
                // Fallback Accept header if browser doesn't provide one
                proxyReq.setHeader('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8');
            }
            
            // This header tells the site we are a real browser requesting a secure page
            proxyReq.setHeader('Upgrade-Insecure-Requests', '1');
            
            if (req.headers['accept-language']) proxyReq.setHeader('Accept-Language', req.headers['accept-language']);
            if (req.headers['accept-encoding']) proxyReq.setHeader('Accept-Encoding', req.headers['accept-encoding']);

        } catch(e) {
            console.error("Error in onProxyReq Stealth Setup:", e);
        }
    },

    onProxyRes: (proxyRes, req, res) => {
        if (!req.targetProfile) return;
        try {
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
        } catch(e) {
            console.error("Error in onProxyRes:", e);
        }
    },

    onError: (err, req, res) => {
        console.error('Proxy Network Error:', err.code, err.message);
        // If headers aren't sent, we can send a custom error page
        if (!res.headersSent) {
            res.status(502).send(`
                <h1>Proxy Connection Error (502)</h1>
                <p>Could not connect to the target website page.</p>
                <p><b>Error:</b> ${err.code || 'UNKNOWN'} - The target server might be blocking the request or is down.</p>
                <a href="/proxy-stop">Return to Admin Panel</a>
            `);
        }
    }
});

// ==========================================
// 3. CONDITIONAL PROXY WRAPPER
// ==========================================
// This ensures the proxy ONLY runs if the user has a valid proxy session cookie!
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
// 4. FALLBACK ROUTE (Not in Proxy Mode)
// ==========================================
// If a user visits a random URL without a proxy cookie, redirect to admin
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

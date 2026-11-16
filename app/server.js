require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fetch = require('node-fetch');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/public', express.static(path.join(__dirname, 'public')));

const {
    SHOPIFY_API_KEY,
    SHOPIFY_API_SECRET,
    SHOPIFY_SCOPES,
    SHOPIFY_APP_URL,
    TAGCONSENT_ENDPOINT = 'https://tagconsent.com',
    PORT = 3100
} = process.env;

const shops = new Map();

function verifyHmac(query) {
    const { hmac, ...params } = query;
    if (!hmac) return false;
    const sorted = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('&');
    const hash = crypto.createHmac('sha256', SHOPIFY_API_SECRET).update(sorted).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(hmac));
}

function verifyWebhookHmac(body, hmacHeader) {
    const hash = crypto.createHmac('sha256', SHOPIFY_API_SECRET).update(body, 'utf8').digest('base64');
    return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(hmacHeader));
}

// ── OAuth: Install ──
app.get('/auth', (req, res) => {
    const { shop } = req.query;
    if (!shop) return res.status(400).send('Missing shop parameter');
    const nonce = crypto.randomBytes(16).toString('hex');
    shops.set(shop, { nonce });
    const redirectUri = `${SHOPIFY_APP_URL}/auth/callback`;
    const installUrl = `https://${shop}/admin/oauth/authorize?client_id=${SHOPIFY_API_KEY}&scope=${SHOPIFY_SCOPES}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${nonce}`;
    res.redirect(installUrl);
});

// ── OAuth: Callback ──
app.get('/auth/callback', async (req, res) => {
    const { shop, code, state, hmac } = req.query;
    if (!shop || !code) return res.status(400).send('Missing parameters');

    if (!verifyHmac(req.query)) return res.status(401).send('HMAC validation failed');

    const stored = shops.get(shop);
    if (!stored || stored.nonce !== state) return res.status(401).send('Invalid state');

    try {
        const tokenRes = await fetch(`https://${shop}/admin/oauth/access_token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                client_id: SHOPIFY_API_KEY,
                client_secret: SHOPIFY_API_SECRET,
                code
            })
        });
        const { access_token, scope } = await tokenRes.json();

        shops.set(shop, { accessToken: access_token, scope, installedAt: new Date().toISOString() });
        await installScriptTag(shop, access_token);
        await syncWithTagConsent(shop, 'install');

        res.redirect(`https://${shop}/admin/apps/${SHOPIFY_API_KEY}`);
    } catch (err) {
        console.error('OAuth callback error:', err);
        res.status(500).send('Installation failed');
    }
});

async function installScriptTag(shop, token) {
    const scriptUrl = `${TAGCONSENT_ENDPOINT}/api/dpdp/cms/loader.js`;
    try {
        await fetch(`https://${shop}/admin/api/2024-01/script_tags.json`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Shopify-Access-Token': token
            },
            body: JSON.stringify({
                script_tag: {
                    event: 'onload',
                    src: scriptUrl,
                    display_scope: 'online_store'
                }
            })
        });
        console.log(`Script tag installed for ${shop}`);
    } catch (err) {
        console.error(`Failed to install script tag for ${shop}:`, err);
    }
}

async function syncWithTagConsent(shop, eventType) {
    const apiKey = process.env.TAGCONSENT_API_KEY;
    if (!apiKey) return;
    try {
        await fetch(`${TAGCONSENT_ENDPOINT}/api/dpdp/cms/sync`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-TC-API-Key': apiKey },
            body: JSON.stringify({
                plugin_version: '1.0.0',
                platform: 'shopify',
                cms_version: 'shopify',
                site_url: `https://${shop}`,
                event: eventType
            })
        });
    } catch (err) {
        console.error('TagConsent sync error:', err);
    }
}

// ── App UI (embedded in Shopify admin) ──
app.get('/', (req, res) => {
    const { shop, hmac } = req.query;
    if (shop && !shops.has(shop)) return res.redirect(`/auth?shop=${shop}`);
    res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

// ── API: Get config for this shop ──
app.get('/api/config', (req, res) => {
    const shop = req.query.shop;
    const data = shops.get(shop);
    if (!data || !data.accessToken) return res.status(401).json({ error: 'Not installed' });
    res.json({
        shop,
        endpoint: TAGCONSENT_ENDPOINT,
        installedAt: data.installedAt,
        scope: data.scope
    });
});

// ── API: Save TagConsent settings ──
app.post('/api/settings', (req, res) => {
    const { shop, apiKey, domainId, bannerPosition, bannerTheme, autoBlock, gcmEnabled } = req.body;
    const data = shops.get(shop);
    if (!data) return res.status(401).json({ error: 'Not installed' });
    data.tagconsentApiKey = apiKey;
    data.domainId = domainId;
    data.bannerPosition = bannerPosition || 'bottom';
    data.bannerTheme = bannerTheme || 'light';
    data.autoBlock = autoBlock !== false;
    data.gcmEnabled = gcmEnabled !== false;
    shops.set(shop, data);
    res.json({ success: true });
});

// ── API: Get settings ──
app.get('/api/settings', (req, res) => {
    const shop = req.query.shop;
    const data = shops.get(shop);
    if (!data) return res.status(401).json({ error: 'Not installed' });
    res.json({
        apiKey: data.tagconsentApiKey || '',
        domainId: data.domainId || '',
        bannerPosition: data.bannerPosition || 'bottom',
        bannerTheme: data.bannerTheme || 'light',
        autoBlock: data.autoBlock !== false,
        gcmEnabled: data.gcmEnabled !== false
    });
});

// ── API: Test connection ──
app.post('/api/test-connection', async (req, res) => {
    const { apiKey } = req.body;
    if (!apiKey) return res.json({ success: false, error: 'No API key' });
    try {
        const r = await fetch(`${TAGCONSENT_ENDPOINT}/api/dpdp/cms/sync`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-TC-API-Key': apiKey },
            body: JSON.stringify({ plugin_version: '1.0.0', platform: 'shopify' })
        });
        const body = await r.json();
        res.json({ success: r.ok && body.status === 'ok', error: body.error });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// ── Webhooks ──
app.post('/webhooks/app/uninstalled', express.raw({ type: 'application/json' }), (req, res) => {
    const hmacHeader = req.get('X-Shopify-Hmac-Sha256');
    if (!verifyWebhookHmac(req.body, hmacHeader)) return res.status(401).send('Invalid');
    const data = JSON.parse(req.body);
    const shop = data.myshopify_domain;
    if (shop) {
        shops.delete(shop);
        syncWithTagConsent(shop, 'uninstall').catch(() => {});
    }
    res.status(200).send('OK');
});

app.listen(PORT, () => {
    console.log(`TagConsent Shopify app running on port ${PORT}`);
});

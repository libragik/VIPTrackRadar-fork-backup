export const ALLOWED_TARGET_HOSTS = [
    'api.adsb.one',
    'api.adsb.lol',
    'api.airplanes.live',
    'opendata.adsb.fi',
    'api.adsbdb.com',
    'hexdb.io',
    'airport-data.com',
    'aviationweather.gov',
    'tfr.faa.gov',
    'en.wikipedia.org'
];

const MAX_TARGET_URL_LENGTH = 2048;

function isPrivateHost(hostname) {
    const host = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
    if (!host) return true;
    if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') ||
        host.endsWith('.internal') || host.endsWith('.home.arpa') || host.endsWith('.lan') ||
        host.endsWith('.test') || host.endsWith('.invalid') || host.endsWith('.example') ||
        host === 'metadata.google.internal') return true;
    if (host.startsWith('::ffff:')) return isPrivateHost(host.slice(7));
    const ipv4 = host.split('.').map(Number);
    if (ipv4.length === 4 && ipv4.every(Number.isInteger) && ipv4.every(value => value >= 0 && value <= 255)) {
        const [a, b] = ipv4;
        return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) ||
            (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
            (a === 198 && (b === 18 || b === 19)) || a >= 224;
    }
    return host === '::1' || host.startsWith('fc') || host.startsWith('fd') || host.startsWith('fe80:');
}

export function isAllowedTarget(value) {
    const raw = String(value || '').trim();
    if (!raw || raw.length > MAX_TARGET_URL_LENGTH) return false;
    let url;
    try { url = new URL(raw); } catch (e) { return false; }
    if (url.protocol !== 'https:') return false;
    if (url.username || url.password) return false;
    if (url.port && url.port !== '443') return false;
    if (isPrivateHost(url.hostname)) return false;
    return ALLOWED_TARGET_HOSTS.includes(url.hostname.toLowerCase());
}

function allowedOrigins(env) {
    return String(env?.ALLOWED_ORIGINS || '')
        .split(',')
        .map(entry => entry.trim())
        .filter(Boolean);
}

function corsHeaders(request, env) {
    const configured = allowedOrigins(env);
    const origin = request.headers.get('Origin') || '';
    const allow = configured.length === 0 ? '*' : (configured.includes(origin) ? origin : '');
    const headers = {
        'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
        'Access-Control-Max-Age': '86400',
        'Vary': 'Origin'
    };
    if (allow) headers['Access-Control-Allow-Origin'] = allow;
    return { headers, allowed: Boolean(allow) };
}

function deny(status, message, cors) {
    return new Response(JSON.stringify({ error: message }), {
        status,
        headers: { ...cors.headers, 'Content-Type': 'application/json' }
    });
}

export default {
    async fetch(request, env) {
        const cors = corsHeaders(request, env);

        if (request.method === 'OPTIONS') {
            return new Response(null, { status: cors.allowed ? 204 : 403, headers: cors.headers });
        }
        if (!cors.allowed) return deny(403, 'Origin is not permitted to use this relay', cors);
        if (request.method !== 'GET' && request.method !== 'HEAD') {
            return deny(405, 'Only GET and HEAD are relayed', cors);
        }

        const target = new URL(request.url).searchParams.get('url');
        if (!target) return deny(400, 'Missing url parameter', cors);
        if (!isAllowedTarget(target)) {
            return deny(403, 'Target host is not in this relay allowlist', cors);
        }

        let upstream;
        try {
            upstream = await fetch(target, {
                method: request.method,
                headers: {
                    'Accept': request.headers.get('Accept') || 'application/json, */*',
                    'User-Agent': 'VIPTrackRadar/0.8.2 (https://github.com/libragik/VIPTrackRadar; contact: kingpirpir@gmail.com)'
                },
                redirect: 'follow'
            });
        } catch (error) {
            return deny(502, 'Upstream fetch failed: ' + String(error?.message || error), cors);
        }

        if (upstream.status === 401 || upstream.status === 403) {
            return deny(502, 'Upstream target returned HTTP ' + upstream.status, cors);
        }

        const headers = new Headers(cors.headers);
        const contentType = upstream.headers.get('Content-Type');
        if (contentType) headers.set('Content-Type', contentType);
        headers.set('Cache-Control', 'no-store');
        return new Response(upstream.body, { status: upstream.status, headers });
    }
};

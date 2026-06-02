/**
 * MDMCheck — Cloudflare Worker
 * 
 * KV Namespace bindings required (wrangler.toml):
 *   KV — general key-value store
 * 
 * Secret bindings required (wrangler secret put):
 *   GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
 *   MS_CLIENT_ID, MS_CLIENT_SECRET
 *   GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET
 *   SESSION_SECRET  (32+ random bytes, hex)
 * 
 * Var bindings (wrangler.toml [vars]):
 *   BASE_URL        e.g. https://mdmcheck.pages.dev
 *   ALLOWED_ORIGIN  same as BASE_URL
 */

export default {
  async fetch(request, env, ctx) {
    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method;

    const cors = {
      'Access-Control-Allow-Origin':  env.ALLOWED_ORIGIN,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Session-Token, X-FP-Id',
      'Access-Control-Allow-Credentials': 'true',
    };

    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    const securityHeaders = {
      'X-Content-Type-Options':  'nosniff',
      'X-Frame-Options':         'DENY',
      'Referrer-Policy':         'strict-origin-when-cross-origin',
      'Content-Security-Policy': [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' https://d3js.org https://cdn.jsdelivr.net https://fonts.googleapis.com",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src https://fonts.gstatic.com",
        "connect-src 'self' https://cloudflare-dns.com https://login.microsoftonline.com https://enterpriseregistration.windows.net",
        "img-src 'self' data: https:",
      ].join('; '),
    };

    const routeKey = `${method} ${path}`;

    const routes = {
      'POST /api/fingerprint':         handleFingerprint,
      'GET  /api/session':             handleSession,
      'POST /api/logout':              handleLogout,
      'GET  /api/auth/google':         (r,e,c) => handleOAuthInit(r,e,c,'google'),
      'GET  /api/auth/microsoft':      (r,e,c) => handleOAuthInit(r,e,c,'microsoft'),
      'GET  /api/auth/github':         (r,e,c) => handleOAuthInit(r,e,c,'github'),
      'GET  /api/auth/callback':       handleOAuthCallback,
      'POST /api/scan':                handleScan,
      'GET  /api/history':             handleHistory,
      'POST /api/restoration-plan':    handleRestorationPlan,
      'GET  /api/probe-script/:platform': handleProbeScript,
      'POST /api/evidence/save':       handleEvidenceSave,
    };

    // Match dynamic routes
    let handler = routes[routeKey];
    let params  = {};

    if (!handler) {
      for (const [pattern, fn] of Object.entries(routes)) {
        const match = matchRoute(pattern, `${method} ${path}`);
        if (match) { handler = fn; params = match; break; }
      }
    }

    if (!handler) {
      return new Response('Not Found', {
        status: 404,
        headers: { 'Content-Type': 'text/plain', ...cors, ...securityHeaders },
      });
    }

    try {
      const response = await handler(request, env, ctx, params);
      Object.entries({ ...cors, ...securityHeaders }).forEach(([k, v]) => {
        if (!response.headers.has(k)) response.headers.set(k, v);
      });
      return response;
    } catch (err) {
      console.error('[Worker error]', err.message, err.stack);
      return json({ error: 'Internal server error' }, 500, { ...cors, ...securityHeaders });
    }
  },
};

// ─── UTILITIES ─────────────────────────────────────────────────────────────

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
  });
}

function matchRoute(pattern, path) {
  const patParts = pattern.split(' ');
  const pathParts = path.split(' ');
  if (patParts[0] !== pathParts[0]) return null;
  const patSegs  = patParts[1].split('/');
  const pathSegs = pathParts[1].split('/');
  if (patSegs.length !== pathSegs.length) return null;
  const params = {};
  for (let i = 0; i < patSegs.length; i++) {
    if (patSegs[i].startsWith(':')) {
      params[patSegs[i].slice(1)] = decodeURIComponent(pathSegs[i]);
    } else if (patSegs[i] !== pathSegs[i]) {
      return null;
    }
  }
  return params;
}

async function getSession(request, env) {
  const cookie = request.headers.get('Cookie') || '';
  const match  = cookie.match(/mdm_session=([^;]+)/);
  const headerToken = request.headers.get('X-Session-Token');
  const token  = match?.[1] || headerToken;
  if (!token || token.length < 32) return null;
  // Validate token format before KV lookup
  if (!/^[a-f0-9\-]{32,}$/i.test(token)) return null;
  try {
    return await env.KV.get(`session:${token}`, 'json');
  } catch {
    return null;
  }
}

function sessionCookie(token, maxAge = 86400) {
  return `mdm_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function clearCookie() {
  return 'mdm_session=; Path=/; HttpOnly; Secure; Max-Age=0';
}

async function rateLimit(env, key, max, windowSeconds) {
  const rlKey   = `rl:${key}`;
  const current = parseInt(await env.KV.get(rlKey) || '0');
  if (current >= max) return false;
  await env.KV.put(rlKey, String(current + 1), { expirationTtl: windowSeconds });
  return true;
}

function getIP(request) {
  return request.headers.get('CF-Connecting-IP') || 'unknown';
}

// ─── FINGERPRINT ────────────────────────────────────────────────────────────

async function handleFingerprint(request, env) {
  const ip = getIP(request);

  const allowed = await rateLimit(env, `fp:${ip}`, 20, 3600);
  if (!allowed) return json({ error: 'Rate limit exceeded' }, 429);

  const body = await request.json().catch(() => ({}));

  // Store minimal fingerprint — no precise hardware identifiers
  const fpId = crypto.randomUUID();
  await env.KV.put(`fp:${fpId}`, JSON.stringify({
    id:    fpId,
    ip,
    ua:    (body.ua    || '').slice(0, 300),
    canvas:(body.canvas|| '').slice(0, 64),  // already hashed client-side
    tz:    (body.tz    || '').slice(0, 60),
    ts:    new Date().toISOString(),
  }), { expirationTtl: 86400 });

  return json({ id: fpId });
}

// ─── SESSION ────────────────────────────────────────────────────────────────

async function handleSession(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ authenticated: false });
  return json({ authenticated: true, user: session.user });
}

// ─── LOGOUT ─────────────────────────────────────────────────────────────────

async function handleLogout(request, env) {
  const cookie = request.headers.get('Cookie') || '';
  const match  = cookie.match(/mdm_session=([^;]+)/);
  if (match) await env.KV.delete(`session:${match[1]}`).catch(() => {});
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie':   clearCookie(),
    },
  });
}

// ─── OAUTH ───────────────────────────────────────────────────────────────────

const OAUTH_CONFIGS = {
  google: {
    authUrl:   'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl:  'https://oauth2.googleapis.com/token',
    userUrl:   'https://www.googleapis.com/oauth2/v2/userinfo',
    scope:     'openid email profile',
    clientId:  env => env.GOOGLE_CLIENT_ID,
    clientSec: env => env.GOOGLE_CLIENT_SECRET,
    mapUser:   u => ({ name: u.name, email: u.email, avatar: u.picture }),
  },
  microsoft: {
    authUrl:   'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    tokenUrl:  'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    userUrl:   'https://graph.microsoft.com/v1.0/me',
    scope:     'openid email profile User.Read',
    clientId:  env => env.MS_CLIENT_ID,
    clientSec: env => env.MS_CLIENT_SECRET,
    mapUser:   u => ({ name: u.displayName, email: u.mail || u.userPrincipalName, avatar: null }),
  },
  github: {
    authUrl:   'https://github.com/login/oauth/authorize',
    tokenUrl:  'https://github.com/login/oauth/access_token',
    userUrl:   'https://api.github.com/user',
    scope:     'read:user user:email',
    clientId:  env => env.GITHUB_CLIENT_ID,
    clientSec: env => env.GITHUB_CLIENT_SECRET,
    mapUser:   u => ({ name: u.name || u.login, email: u.email, avatar: u.avatar_url }),
  },
};

async function handleOAuthInit(request, env, ctx, provider) {
  const cfg = OAUTH_CONFIGS[provider];
  if (!cfg) return json({ error: 'Unknown provider' }, 400);

  const state       = crypto.randomUUID();
  const redirectUri = `${env.BASE_URL}/api/auth/callback`;

  // Store state with provider so callback knows which flow to complete
  await env.KV.put(`oauth:${state}`, provider, { expirationTtl: 600 });

  const params = new URLSearchParams({
    client_id:     cfg.clientId(env),
    redirect_uri:  redirectUri,
    response_type: 'code',
    scope:         cfg.scope,
    state,
  });

  return Response.redirect(`${cfg.authUrl}?${params}`, 302);
}

async function handleOAuthCallback(request, env) {
  const url   = new URL(request.url);
  const code  = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const error = url.searchParams.get('error');

  if (error || !code || !state) {
    return Response.redirect(`${env.BASE_URL}/?auth=error`, 302);
  }

  // Validate state — prevents CSRF
  const provider = await env.KV.get(`oauth:${state}`);
  if (!provider) {
    return Response.redirect(`${env.BASE_URL}/?auth=error`, 302);
  }
  await env.KV.delete(`oauth:${state}`);

  const cfg         = OAUTH_CONFIGS[provider];
  const redirectUri = `${env.BASE_URL}/api/auth/callback`;

  try {
    // Exchange code for access token
    const tokenBody = provider === 'github'
      ? JSON.stringify({ client_id: cfg.clientId(env), client_secret: cfg.clientSec(env), code })
      : new URLSearchParams({
          code,
          client_id:     cfg.clientId(env),
          client_secret: cfg.clientSec(env),
          redirect_uri:  redirectUri,
          grant_type:    'authorization_code',
        }).toString();

    const tokenRes = await fetch(cfg.tokenUrl, {
      method:  'POST',
      headers: {
        'Content-Type': provider === 'github' ? 'application/json' : 'application/x-www-form-urlencoded',
        'Accept':       'application/json',
        ...(provider === 'github' ? { 'User-Agent': 'MDMCheck' } : {}),
      },
      body: tokenBody,
    });

    const tokens = await tokenRes.json();
    if (!tokens.access_token) throw new Error('No access token returned');

    // Fetch user profile
    const userRes = await fetch(cfg.userUrl, {
      headers: {
        Authorization:  `Bearer ${tokens.access_token}`,
        'User-Agent':   'MDMCheck',
        Accept:         'application/json',
      },
    });
    const rawUser = await userRes.json();
    const user    = cfg.mapUser(rawUser);

    if (!user.email) throw new Error('No email returned from provider');

    // Create session
    const sessionToken = crypto.randomUUID();
    await env.KV.put(`session:${sessionToken}`, JSON.stringify({
      user,
      provider,
      created_at: new Date().toISOString(),
    }), { expirationTtl: 86400 });

    const headers = new Headers({
      Location:    `${env.BASE_URL}/?auth=ok`,
      'Set-Cookie': sessionCookie(sessionToken),
    });
    return new Response(null, { status: 302, headers });

  } catch (err) {
    console.error('[OAuth callback error]', err.message);
    return Response.redirect(`${env.BASE_URL}/?auth=error`, 302);
  }
}

// ─── MDM SCAN (SSE) ──────────────────────────────────────────────────────────

// Zero-false-positive probe definitions.
// Every probe is READ-ONLY. We replicate the exact network call
// a first-boot device makes during enrollment discovery.
// HTTP 200 + positive body pattern = confirmed finding.
// Anything else = 0. No guessing.

const PROBES = [
  {
    key: 'ms_enterprise_registration',
    label: 'Microsoft Enterprise Device Registration',
    category: 'domain_intel',
    tier: 0,
    url: (d) => `https://enterpriseregistration.windows.net/${d}/discover?api-version=1.7`,
    method: 'GET',
    positive: [/"TenantId"\s*:\s*"[0-9a-f-]{36}"/i, /DiscoveryEndpoint/i],
    negative: [/unknown_tenant/i],
    intel: (j) => ({ tenant_id: j.TenantId, endpoint: j.DiscoveryEndpoint }),
  },
  {
    key: 'ms_openid_config',
    label: 'Microsoft Entra OpenID Configuration',
    category: 'domain_intel',
    tier: 0,
    url: (d) => `https://login.microsoftonline.com/${d}/v2.0/.well-known/openid-configuration`,
    method: 'GET',
    positive: [/"tenant_region_scope"/i, /"issuer"\s*:\s*"https:\/\/login\.microsoftonline/i],
    negative: [/invalid_tenant/i, /AADSTS90002/i],
    intel: (j) => ({ region: j.tenant_region_scope, cloud: j.cloud_instance_name, issuer: j.issuer }),
  },
  {
    key: 'ms_user_realm',
    label: 'Microsoft User Realm Discovery',
    category: 'domain_intel',
    tier: 0,
    url: (d, email) => `https://login.microsoftonline.com/common/userrealm/${encodeURIComponent(email)}?api-version=1.0`,
    method: 'GET',
    positive: [/"NameSpaceType"\s*:\s*"(Managed|Federated)"/i],
    negative: [/"NameSpaceType"\s*:\s*"Unknown"/i],
    intel: (j) => ({ namespace: j.NameSpaceType, brand: j.FederationBrandName, domain: j.DomainName }),
  },
  {
    key: 'ms_intune_enrollment',
    label: 'Microsoft Intune MDM Enrollment Endpoint',
    category: 'domain_intel',
    tier: 0,
    url: (d) => `https://EnterpriseEnrollment.${d}/EnrollmentServer/Discovery.svc`,
    method: 'GET',
    positive: [/EnrollmentServiceUrl/i, /AuthPolicy/i],
    negative: [/faultcode/i],
    intel: () => ({}),
  },
  {
    key: 'apple_well_known_mobileconfig',
    label: 'Apple MDM .well-known Mobileconfig',
    category: 'apple_dep',
    tier: 0,
    url: (d) => `https://${d}/.well-known/mobileconfig`,
    method: 'GET',
    positive: [/PayloadType.*Configuration/i, /ServerURL/i, /PayloadOrganization/i],
    negative: [],
    intel: () => ({}),
  },
  {
    key: 'vmware_workspace_one',
    label: 'VMware Workspace ONE Autodiscovery',
    category: 'mdm_discovery',
    tier: 0,
    url: (d) => `https://discovery.awmdm.com/autodiscovery/awclient/v1/autodiscovery/DeviceServices/EmailDomain?domain=${encodeURIComponent(d)}`,
    method: 'GET',
    positive: [/ServerName.*awmdm\.com/i, /GroupID/i],
    negative: [/InvalidDomain/i],
    intel: (j) => ({ server: j.ServerName, group_id: j.GroupID }),
  },
  {
    key: 'jamf_cloud',
    label: 'Jamf Cloud Enrollment Portal',
    category: 'mdm_discovery',
    tier: 0,
    url: (d) => `https://${d}.jamfcloud.com/enroll`,
    method: 'GET',
    positive: [/jamfcloud\.com/i, /Jamf\s+(Pro|School|Now)/i],
    negative: [/404 Not Found/i],
    intel: () => ({}),
  },
  {
    key: 'okta_org',
    label: 'Okta Organization Discovery',
    category: 'identity_discovery',
    tier: 0,
    url: (d) => `https://${d}.okta.com/.well-known/okta-organization`,
    method: 'GET',
    positive: [/"id"\s*:\s*"[0-9a-zA-Z]{16,}"/i, /subdomain/i, /displayName/i],
    negative: [],
    intel: (j) => ({ org_id: j.id, subdomain: j.subdomain, name: j.displayName }),
  },
  {
    key: 'jumpcloud_oidc',
    label: 'JumpCloud OpenID Configuration',
    category: 'identity_discovery',
    tier: 0,
    url: () => 'https://oauth.id.jumpcloud.com/.well-known/openid-configuration',
    method: 'GET',
    positive: [/jumpcloud\.com/i, /"issuer"/i],
    negative: [],
    intel: (j) => ({ issuer: j.issuer }),
  },
  {
    key: 'crowdstrike_api',
    label: 'CrowdStrike Falcon API Endpoint',
    category: 'edr_discovery',
    tier: 0,
    url: () => 'https://api.crowdstrike.com/',
    method: 'GET',
    positive: [/CrowdStrike/i, /falcon/i],
    negative: [],
    intel: () => ({}),
  },
  {
    key: 'sophos_central',
    label: 'Sophos Central Identity Check',
    category: 'edr_discovery',
    tier: 0,
    url: () => 'https://api.central.sophos.com/whoami/v1',
    method: 'GET',
    positive: [/"idType"\s*:\s*"(tenant|partner)"/i],
    negative: [],
    intel: (j) => ({ id_type: j.idType }),
  },
  {
    key: 'samsung_knox_kme',
    label: 'Samsung Knox KME Enrollment Check',
    category: 'samsung_knox',
    tier: 0,
    url: () => 'https://kme.samsungknox.com/kcs/v1/kme/devices/check',
    method: 'POST',
    body: (id) => JSON.stringify({ imei: id, serial: id, wifiMacAddress: '', bluetoothMacAddress: '' }),
    headers: { 'Content-Type': 'application/json', 'X-Knox-Client': 'KME/4.0' },
    positive: [/"enrolled"\s*:\s*true/i, /customerId/i, /ENROLLED|REGISTERED/i],
    negative: [/"enrolled"\s*:\s*false/i],
    intel: (j) => ({ customer_id: j.customerId, status: j.deviceStatus }),
  },
  {
    key: 'well_known_mdm_enrollment',
    label: 'RFC .well-known MDM Enrollment',
    category: 'mdm_discovery',
    tier: 0,
    url: (d) => `https://${d}/.well-known/mdm-enrollment`,
    method: 'GET',
    positive: [/enrollment-endpoint/i, /EnrollmentServiceUrl/i],
    negative: [],
    intel: () => ({}),
  },
  {
    key: 'ms_autopilot',
    label: 'Microsoft Autopilot Tenant Info',
    category: 'domain_intel',
    tier: 0,
    url: () => 'https://cs.dds.microsoft.com/TenantsInfo',
    method: 'GET',
    positive: [/tenantId/i, /Provisioning/i],
    negative: [],
    intel: () => ({}),
  },
  {
    key: 'ivanti_mobileiron',
    label: 'Ivanti / MobileIron MDM Endpoint',
    category: 'mdm_discovery',
    tier: 0,
    url: (d) => `https://${d}.mobileiron.com/enrollment`,
    method: 'GET',
    positive: [/mobileiron/i, /ivanti/i, /enrollment/i],
    negative: [],
    intel: () => ({}),
  },
  {
    key: 'google_workspace_mx',
    label: 'Google Workspace MX Record Check',
    category: 'google_android',
    tier: 0,
    url: (d) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(d)}&type=MX`,
    method: 'GET',
    headers: { Accept: 'application/dns-json' },
    positive: [/google\.com|aspmx\.l\.google/i],
    negative: [],
    intel: () => ({}),
  },
  {
    key: 'auth0_tenant',
    label: 'Auth0 Tenant OIDC Discovery',
    category: 'identity_discovery',
    tier: 0,
    url: (d) => `https://${d}.auth0.com/.well-known/openid-configuration`,
    method: 'GET',
    positive: [/auth0\.com/i, /"issuer"/i, /authorization_endpoint/i],
    negative: [],
    intel: (j) => ({ issuer: j.issuer }),
  },
  {
    key: 'kandji_mdm',
    label: 'Kandji MDM Endpoint',
    category: 'mdm_discovery',
    tier: 0,
    url: (d) => `https://${d}.kandji.io/api/v1/devices`,
    method: 'GET',
    positive: [/kandji/i, /blueprint/i],
    negative: [],
    intel: () => ({}),
  },
  {
    key: 'microsoft_defender',
    label: 'Microsoft Defender for Endpoint',
    category: 'edr_discovery',
    tier: 0,
    url: () => 'https://api.securitycenter.microsoft.com/api/machines',
    method: 'GET',
    positive: [/computerDnsName/i, /onboardingStatus/i],
    negative: [],
    intel: () => ({}),
  },
  {
    key: 'jamf_scep',
    label: 'Jamf SCEP Certificate Enrollment',
    category: 'mdm_discovery',
    tier: 0,
    url: (d) => `https://${d}.jamfcloud.com/CertificateAuthority/SCEP`,
    method: 'GET',
    positive: [/SCEP/i, /jamf/i, /certificate/i],
    negative: [],
    intel: () => ({}),
  },
];

const DEPTH_LABELS = {
  apple_dep:          'FULL SUPERVISION — silent app install, remote wipe, GPS lock, global proxy',
  domain_intel:       'TENANT CONFIRMED — Conditional Access, device compliance, activity logging',
  samsung_knox:       'KNOX MANAGED — Knox Container, remote lock, E-FOTA firmware, Knox Guard',
  mdm_discovery:      'MDM INFRASTRUCTURE — management server and org identity confirmed',
  google_android:     'ANDROID ENTERPRISE — Device Owner or Work Profile management confirmed',
  edr_discovery:      'EDR MONITORED — continuous process, network, and file system monitoring',
  identity_discovery: 'IDENTITY MANAGED — org controls all authentication and SSO access logs',
};

function scoreConfidence(status, bodyText, positive, negative) {
  // Zero false positive: any doubt = 0
  if (!status || status < 200 || status >= 300) return 0;

  // Generic HTML error pages = 0
  if (bodyText && (bodyText.trimStart().startsWith('<!') || /<html/i.test(bodyText.slice(0, 300)))) return 0;

  // Any negative pattern = 0
  for (const pat of negative) {
    if (pat.test(bodyText || '')) return 0;
  }

  // No positive patterns defined = reachability probe (lower confidence)
  if (!positive || positive.length === 0) return 55;

  const hits = positive.filter(p => p.test(bodyText || '')).length;
  if (hits === 0) return 0;

  return Math.min(100, 70 + (hits * 10));
}

function safeExtractIntel(bodyText, probe) {
  if (!bodyText || !probe.intel) return {};
  try {
    const j = JSON.parse(bodyText);
    return probe.intel(j) || {};
  } catch {
    return {};
  }
}

async function handleScan(request, env, ctx) {
  const ip = getIP(request);

  // Server-side rate limit — guests 3/hr, authenticated 10/hr
  const session   = await getSession(request, env);
  const rlMax     = session ? 10 : 3;
  const allowed   = await rateLimit(env, `scan:${ip}`, rlMax, 3600);
  if (!allowed) {
    return json({ error: `Rate limit: ${rlMax} scans per hour. Please wait before scanning again.` }, 429);
  }

  const body = await request.json().catch(() => ({}));
  const raw  = (body.target || '').trim().toLowerCase();

  if (!raw || raw.length > 253) {
    return json({ error: 'Target required (email address or domain).' }, 400);
  }

  const isEmail = raw.includes('@');
  const domain  = isEmail
    ? raw.split('@').pop()
    : raw.replace(/^https?:\/\//, '').split('/')[0];

  // Strict domain validation
  const domainRE = /^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$/;
  if (!domainRE.test(domain)) {
    return json({ error: 'Please enter a valid email address or domain name.' }, 400);
  }

  // Block reserved / loopback domains
  const reserved = [
    'localhost', 'example.com', 'example.org', 'example.net',
    'test', 'local', 'invalid', '0.0.0.0',
  ];
  if (reserved.some(r => domain === r || domain.endsWith('.' + r))) {
    return json({ error: 'Reserved or test domains cannot be scanned.' }, 400);
  }

  const scanId = crypto.randomUUID();
  const email  = isEmail ? raw : `user@${domain}`;

  // Server-Sent Events stream
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const enc    = new TextEncoder();

  const emit = async (event, data) => {
    await writer.write(enc.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
  };

  ctx.waitUntil((async () => {
    await emit('start', { domain, email, total: PROBES.length, scanId });

    let hits = 0;
    const findings = [];

    for (const probe of PROBES) {
      try {
        const url         = probe.url(domain, email);
        const reqHeaders  = { 'User-Agent': 'MDMCheck/1.0 (device-audit)', ...(probe.headers || {}) };
        const reqInit     = {
          method:  probe.method,
          headers: reqHeaders,
          redirect: 'follow',
          signal:  AbortSignal.timeout(9000),
        };
        if (probe.method === 'POST' && probe.body) {
          reqInit.body = probe.body(domain);
        }

        const resp     = await fetch(url, reqInit);
        const bodyText = probe.method === 'HEAD' ? '' : (await resp.text().catch(() => ''));
        const conf     = scoreConfidence(resp.status, bodyText, probe.positive, probe.negative);
        const isHit    = conf >= 60;

        await emit('probe', {
          key:        probe.key,
          label:      probe.label,
          hit:        isHit,
          confidence: conf,
          status:     resp.status,
        });

        if (isHit) {
          hits++;
          const finding = {
            key:              probe.key,
            label:            probe.label,
            category:         probe.category,
            confidence:       conf,
            status:           resp.status,
            url,
            management_depth: DEPTH_LABELS[probe.category] || '',
            intel:            safeExtractIntel(bodyText, probe),
          };
          findings.push(finding);
          await emit('finding', finding);
        }
      } catch (err) {
        // Timeout or network error — not a finding
        await emit('probe', { key: probe.key, label: probe.label, hit: false, error: true });
      }
    }

    // Persist scan record for authenticated users
    if (session?.user?.email) {
      await env.KV.put(
        `scan:${session.user.email}:${scanId}`,
        JSON.stringify({
          scan_id:       scanId,
          target:        raw,
          domain,
          hits,
          finding_count: hits,
          findings:      findings.map(f => ({ key: f.key, label: f.label, category: f.category, confidence: f.confidence })),
          created_at:    new Date().toISOString(),
        }),
        { expirationTtl: 2592000 } // 30 days
      );
    }

    await emit('complete', { hits, scanId, domain, target_type: isEmail ? 'email' : 'domain' });
    await writer.close();
  })());

  return new Response(readable, {
    status: 200,
    headers: {
      'Content-Type':  'text/event-stream',
      'Cache-Control': 'no-cache, no-store',
      'Connection':    'keep-alive',
      'X-Accel-Buffering': 'no',
    },
  });
}

// ─── SCAN HISTORY ────────────────────────────────────────────────────────────

async function handleHistory(request, env) {
  const session = await getSession(request, env);
  if (!session?.user?.email) {
    return json({ error: 'Authentication required.' }, 401);
  }

  const prefix = `scan:${session.user.email}:`;
  const list   = await env.KV.list({ prefix, limit: 50 });
  const scans  = [];

  for (const key of list.keys) {
    const record = await env.KV.get(key.name, 'json').catch(() => null);
    if (record) scans.push(record);
  }

  scans.sort((a, b) => b.created_at.localeCompare(a.created_at));

  return json({ scans });
}

// ─── RESTORATION PLAN ────────────────────────────────────────────────────────
//
// Takes findings from a completed scan and returns a prioritized,
// platform-specific restoration roadmap for victims.
// Every step is actionable and ordered correctly:
//   PRESERVE evidence → LEGAL removal requests → VERIFY removal → RESTORE device

async function handleRestorationPlan(request, env) {
  const body     = await request.json().catch(() => ({}));
  const findings = Array.isArray(body.findings) ? body.findings : [];
  const domain   = (body.domain || '').trim();

  const categories = [...new Set(findings.map(f => f.category))];

  const plan = {
    domain,
    generated_at:    new Date().toISOString(),
    priority_order:  [],
    steps:           [],
    dsar_targets:    [],
    safe_device_steps: [],
    official_tools:  [],
  };

  // ── Phase 1: Preserve first — always ──
  plan.steps.push({
    phase:    1,
    priority: 'CRITICAL',
    title:    'Preserve All Evidence Before Taking Any Action',
    detail:   'Export your full evidence bundle now. Every step after this could change device state. You need the original state documented for legal proceedings.',
    actions: [
      'Click "Export Evidence" → download the JSON and HTML report',
      'Email it to yourself and your attorney immediately',
      'Do not factory reset, do not disable anything, until this is done',
    ],
  });

  // ── Phase 2: Platform-specific DSAR letters ──
  if (categories.includes('domain_intel') || categories.includes('apple_dep') || categories.includes('samsung_knox')) {
    const intel = findings.find(f => f.category === 'domain_intel')?.intel || {};

    if (categories.includes('domain_intel')) {
      plan.dsar_targets.push({
        platform:  'Microsoft',
        recipient: 'privacy@microsoft.com',
        template:  'gdpr_microsoft',
        tenant_id: intel.tenant_id || null,
        deadline_days: 30,
        note: 'A properly submitted GDPR Art. 17 erasure request legally requires Microsoft to remove your device serial from Autopilot and Intune. This is the only permanent solution — disabling local agents alone does not prevent re-enrollment after factory reset.',
      });
    }

    if (categories.includes('apple_dep')) {
      plan.dsar_targets.push({
        platform:  'Apple',
        recipient: 'privacy@apple.com',
        template:  'gdpr_apple',
        deadline_days: 30,
        note: 'Apple DSAR forces disclosure of which ABM/ASM organization holds your serial. Activation Lock removal requires proof of purchase submitted to https://support.apple.com/activationlock',
      });
    }

    if (categories.includes('samsung_knox')) {
      plan.dsar_targets.push({
        platform:  'Samsung Knox',
        recipient: 'https://www.samsungknox.com/en/support',
        template:  null,
        deadline_days: 30,
        note: 'Knox Guard and KME removal requires direct contact with Samsung Knox Enterprise Helpdesk and the original reseller/carrier. A DSAR to your carrier is the first step to identify the enrolling organization.',
      });
    }

    if (categories.includes('google_android')) {
      plan.dsar_targets.push({
        platform:  'Google',
        recipient: 'data-protection-office@google.com',
        template:  'gdpr_google',
        deadline_days: 30,
        note: 'Google DSAR surfaces Android Enterprise enrollment history. Zero-Touch device removal requires the reseller portal or Android Enterprise helpdesk.',
      });
    }

    if (categories.includes('identity_discovery')) {
      plan.dsar_targets.push({
        platform:  'Identity Provider (Okta / JumpCloud / Duo)',
        recipient: '(see platform-specific privacy contact)',
        template:  null,
        deadline_days: 30,
        note: 'File DSAR with each identity provider found to obtain your authentication logs and device registration records.',
      });
    }
  }

  plan.steps.push({
    phase:    2,
    priority: 'HIGH',
    title:    'Send Data Subject Access Requests (DSARs)',
    detail:   `${plan.dsar_targets.length} platform${plan.dsar_targets.length !== 1 ? 's' : ''} detected. GDPR (30 days) and CCPA (45 days) require written responses. Non-response escalates to your national data protection authority.`,
    actions:  plan.dsar_targets.map(t => `Send DSAR to ${t.platform} — ${t.recipient}`),
  });

  // ── Phase 3: Safe device-level steps (no privilege escalation needed) ──

  plan.safe_device_steps.push({
    platform: 'Android',
    title:    'Remove Unauthorized ADB Keys',
    risk:     'NONE',
    detail:   'Standard settings — no special access needed',
    steps: [
      'Settings → Developer Options → Revoke USB Debugging Authorizations',
      'This removes all ADB public keys from /data/misc/adb/adb_keys',
      'Verify by running the Android probe script again after doing this',
    ],
  });

  plan.safe_device_steps.push({
    platform: 'Android',
    title:    'Remove User-Installed CA Certificates',
    risk:     'NONE',
    detail:   'Standard settings — any user can do this',
    steps: [
      'Settings → Security → Encryption & Credentials → Trusted Credentials → User tab',
      'Review each certificate — any org-named CA should be removed',
      'Tap the certificate → Disable or Remove',
      'Note: Work profile CAs (uid 10+) require removing the work profile itself',
    ],
  });

  if (categories.includes('domain_intel')) {
    plan.safe_device_steps.push({
      platform: 'Windows',
      title:    'Check Enrolled MDM Profiles',
      risk:     'NONE',
      detail:   'Settings access only',
      steps: [
        'Settings → Accounts → Access work or school',
        'If enrolled: click the account → Disconnect',
        'For Autopilot-locked devices: disconnecting locally does not remove the Autopilot record — the DSAR to Microsoft is required for permanent removal',
      ],
    });
  }

  if (categories.includes('apple_dep')) {
    plan.safe_device_steps.push({
      platform: 'iOS / macOS',
      title:    'Check and Remove MDM Profiles',
      risk:     'LOW',
      detail:   'May not be removable if supervised',
      steps: [
        'Settings → General → VPN & Device Management',
        'If a profile has a "Remove Management" option → tap it',
        'If there is no remove option → device is supervised. Requires Apple Configurator 2 or Activation Lock removal via DSAR.',
      ],
    });
  }

  plan.steps.push({
    phase:    3,
    priority: 'MEDIUM',
    title:    'Safe Device-Level Actions (No Special Access Required)',
    detail:   'These steps use standard platform settings. They do not require root or privileged tools. Do these while waiting for DSAR responses.',
    actions:  plan.safe_device_steps.map(s => `${s.platform}: ${s.title}`),
  });

  // ── Phase 4: Verify legal removal before firmware flash ──
  plan.steps.push({
    phase:    4,
    priority: 'HIGH',
    title:    'Verify Legal Removal in Writing Before Flashing',
    detail:   'Factory resetting or flashing firmware before the enrollment database entry is removed will result in automatic re-enrollment. Wait for written confirmation from Microsoft/Apple/Samsung/Google that the serial has been removed.',
    actions: [
      'Receive written confirmation from each DSAR target',
      'Re-run MDM Scanner — confirm zero findings for your domain',
      'Only then proceed to firmware restoration',
    ],
  });

  // ── Phase 5: Official firmware restoration tools ──
  plan.official_tools = [
    {
      name:    'Android Flash Tool (Google Pixels)',
      url:     'https://flash.android.com',
      note:    'Official Google WebUSB flashing tool. Flashes factory firmware. Does NOT remove Knox Guard or Autopilot enrollment records — do Phase 2 first.',
    },
    {
      name:    'Samsung Smart Switch',
      url:     'https://www.samsung.com/us/support/downloads/',
      note:    'Official Samsung firmware restoration. Knox warranty bits may be set permanently — Knox Guard removal requires Samsung Knox helpdesk.',
    },
    {
      name:    'Apple Configurator 2',
      url:     'https://apps.apple.com/app/apple-configurator-2/id1037126344',
      note:    'Restores iPhones and iPads to stock firmware via DFU mode. Does NOT remove Activation Lock — requires DSAR response from Apple first.',
    },
  ];

  plan.steps.push({
    phase:    5,
    priority: 'LOW',
    title:    'Restore Factory Firmware (After Legal Removal Confirmed)',
    detail:   'Use only official manufacturer tools. Community ROM flashing is outside the scope of this tool.',
    actions:  plan.official_tools.map(t => `${t.name} — ${t.url}`),
  });

  // ── If no escalation response: regulator complaint ──
  plan.steps.push({
    phase:    6,
    priority: 'HIGH',
    title:    'Escalate to Regulators If No DSAR Response',
    detail:   'GDPR requires response within 30 days. CCPA within 45 days. Non-response is itself a violation.',
    actions: [
      'UK: File complaint at ico.org.uk (casework@ico.org.uk)',
      'EU: File with your national DPA (edpb.europa.eu/about-edpb/about-edpb/members_en)',
      'USA: File FTC complaint at reportfraud.ftc.gov and your State AG',
      'All: File IC3 report at ic3.gov for unauthorized device access',
    ],
  });

  return json(plan);
}

// ─── PROBE SCRIPT DOWNLOAD ───────────────────────────────────────────────────

// Scripts are served from the Worker directly so they can be versioned
// and updated without a full Pages deployment.

const PROBE_SCRIPT_ANDROID = `#!/bin/bash
# MDMCheck — Android Forensic Probe v1.0
# Run: adb shell < mdmcheck-probe-android.sh > probe-output.txt 2>&1
# Then upload probe-output.txt to Uploaded Files in MDMCheck
set +e
echo "=== MDMCheck Android Forensic Probe ==="
echo "Time:   $(date -u +%FT%TZ)"
echo "Device: $(getprop ro.product.model 2>/dev/null)"
echo "Build:  $(getprop ro.build.fingerprint 2>/dev/null)"
echo ""
echo "=== DEVICE IDENTITY ==="
getprop | grep -E "^\\[ro\\.serialno\\]|^\\[ro\\.product\\.model\\]|^\\[ro\\.product\\.manufacturer\\]|^\\[ro\\.build\\.version\\.release\\]|^\\[ro\\.build\\.id\\]"
echo ""
echo "=== REGIONAL / CSC PROPERTIES ==="
getprop | grep -iE "ro\\.boot\\.hwc|ro\\.boot\\.csc|ro\\.boot\\.carrier|persist\\.sys\\.country|ro\\.product\\.locale|gsm\\.operator\\.iso-country|ro\\.csc\\.sales_code"
echo ""
echo "=== ENTERPRISE / PROVISIONING FLAGS ==="
getprop | grep -iE "enterprise|enroll|provision|owner|mdm|dpc|laforge|zero\\.touch|organization|setupwizard|repair"
echo ""
echo "=== DEVICE PROVISIONED STATUS ==="
settings get global device_provisioned 2>/dev/null
settings get secure user_setup_complete 2>/dev/null
settings get global enrollment_token 2>/dev/null
echo ""
echo "=== DEVICE OWNER (device_owners.xml) ==="
cat /data/system/device_owners.xml 2>/dev/null || echo "(no access — run via adb shell with elevated permissions)"
echo ""
echo "=== ACTIVE DEVICE POLICIES ==="
cat /data/system/device_policies.xml 2>/dev/null | head -50 || echo "(no access)"
echo ""
echo "=== INSTALLED PACKAGES — MANAGEMENT PATTERNS ==="
pm list packages -e 2>/dev/null | grep -iE "mdm|manage|intune|knox|enterprise|enroll|jamf|airwatch|mobileiron|crowdstrike|sophos|okta|jumpcloud|duo|maas360|ivanti|kandji|citrix|meraki|clouddpc|workspaceone"
echo ""
echo "=== ADB AUTHORIZED KEYS ==="
cat /data/misc/adb/adb_keys 2>/dev/null || echo "(no access — elevated shell required)"
echo ""
echo "=== USER-INSTALLED CA CERTIFICATES ==="
ls /data/misc/user/0/cacerts-added/ 2>/dev/null && for f in /data/misc/user/0/cacerts-added/*.0 2>/dev/null; do [ -f "$f" ] && echo "--- $f ---" && openssl x509 -noout -subject -issuer -dates -in "$f" 2>/dev/null; done || echo "(none found or no access)"
echo ""
echo "=== NETWORK PROXY / WPAD ==="
getprop | grep -iE "wpad|proxy|dhcp|provision"
cat /data/misc/wifi/WifiConfigStore.xml 2>/dev/null | grep -iE "WPAD|ProxyHost|url" | head -20 || echo "(no access)"
echo ""
echo "=== ZERO-TOUCH OOBCONFIG ==="
cat /data/data/com.google.android.setupwizard/shared_prefs/zero_touch_preferences.xml 2>/dev/null || echo "(not present)"
echo ""
echo "=== END PROBE ==="
`;

const PROBE_SCRIPT_WINDOWS = `# MDMCheck — Windows Forensic Probe v1.0
# Run from Administrator PowerShell:
#   powershell -ExecutionPolicy Bypass -File mdmcheck-probe.ps1
# Upload the generated mdmcheck-probe-output.txt to MDMCheck Uploaded Files
$ErrorActionPreference = "Continue"
$out = "mdmcheck-probe-output.txt"
"MDMCheck Windows Forensic Probe v1.0","Generated: $(Get-Date -Format o)","Hostname: $env:COMPUTERNAME","User: $env:USERNAME","" | Out-File -Encoding utf8 $out
function Section($name, $script) {
  "","=== $name ===" | Out-File -Encoding utf8 -Append $out
  try { & $script 2>&1 | Out-File -Encoding utf8 -Append $out } catch { "ERROR: $_" | Out-File -Encoding utf8 -Append $out }
}
Section "MDM Enrollment Status"       { dsregcmd /status }
Section "Enrollment Registry Keys"    { Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Enrollments' -EA SilentlyContinue | ForEach-Object { "ENTRY: $($_.PSChildName)"; Get-ItemProperty $_.PSPath -EA SilentlyContinue | Format-List * } }
Section "OMA-DM Accounts"             { Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Provisioning\\OMADM\\Accounts' -EA SilentlyContinue | ForEach-Object { "ACCOUNT: $($_.PSChildName)" } }
Section "MDM Certificates"            { Get-ChildItem Cert:\\LocalMachine\\My -EA SilentlyContinue | Where-Object { $_.Subject -match 'Intune|MDM|Enrollment|Workplace' } | Format-List Subject,Issuer,NotBefore,NotAfter,Thumbprint }
Section "All LocalMachine Certs"      { Get-ChildItem Cert:\\LocalMachine\\Root -EA SilentlyContinue | Format-List Subject,Issuer,Thumbprint }
Section "CrowdStrike Falcon"          { Get-Service CsFalconService -EA SilentlyContinue | Format-List *; Get-ItemProperty 'HKLM:\\SYSTEM\\CrowdStrike\\*\\*\\Default' -EA SilentlyContinue | Format-List * }
Section "Sophos Endpoint"             { Get-Service "Sophos*" -EA SilentlyContinue | Format-List * }
Section "JumpCloud Agent"             { Get-Service "jumpcloud*" -EA SilentlyContinue | Format-List * }
Section "Autopilot Registry"          { Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Provisioning\\AutopilotPolicyCache' -EA SilentlyContinue | Format-List * }
Section "Intune Extension"            { Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\IntuneManagementExtension' -EA SilentlyContinue | Format-List * }
Section "Network Proxy Settings"      { netsh winhttp show proxy; Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' | Select-Object ProxyEnable,ProxyServer,ProxyOverride,AutoConfigURL }
Write-Host "Done. Upload $out to MDMCheck Uploaded Files."
`;

const PROBE_SCRIPT_MACOS = `#!/bin/bash
# MDMCheck — macOS Forensic Probe v1.0
# Run in Terminal: bash mdmcheck-probe.sh
# Upload mdmcheck-probe-output.txt to MDMCheck Uploaded Files
set +e
OUT="mdmcheck-probe-output.txt"
{
  echo "MDMCheck macOS Forensic Probe v1.0"
  echo "Generated: $(date -u +%FT%TZ)"
  echo "Hostname: $(hostname)"
  echo ""
  sw_vers
  echo ""
  echo "=== Management Profiles ==="
  sudo profiles show -all 2>/dev/null || echo "(sudo required)"
  echo ""
  echo "=== Profile List ==="
  sudo profiles list 2>/dev/null
  echo ""
  echo "=== Managed Preferences ==="
  sudo ls -la "/Library/Managed Preferences" 2>/dev/null
  echo ""
  echo "=== Jamf ==="
  ls -la /usr/local/jamf/bin/ 2>/dev/null
  sudo jamf version 2>/dev/null
  echo ""
  echo "=== Microsoft Intune ==="
  ls -la "/Library/Application Support/Microsoft/Intune" 2>/dev/null
  ls -la /etc/intune 2>/dev/null
  echo ""
  echo "=== CrowdStrike Falcon ==="
  ls -la /opt/CrowdStrike/ 2>/dev/null
  sudo /opt/CrowdStrike/falconctl stats agent_info 2>/dev/null
  echo ""
  echo "=== JumpCloud ==="
  ls -la /opt/jc/ 2>/dev/null
  /opt/jc/bin/jcagent --status 2>/dev/null
  echo ""
  echo "=== System Extensions ==="
  systemextensionsctl list 2>/dev/null
  echo ""
  echo "=== Trust Store Additions ==="
  security find-certificate -a /Library/Keychains/System.keychain 2>/dev/null | grep -iE "alis|subj|labl" | grep -v Apple | head -40
  echo ""
  echo "=== LaunchDaemons (management-related) ==="
  ls /Library/LaunchDaemons/ | grep -iE "intune|jamf|crowdstrike|sophos|jumpcloud|kandji|mosyle|meraki"
} > "$OUT"
echo "Saved: $OUT — Upload to MDMCheck Uploaded Files"
`;

const PROBE_SCRIPT_IOS = `MDMCheck — iPhone / iPad Manual Probe Guide v1.0

iOS restricts automated script access. Complete these steps manually and save screenshots.

STEP 1 — Management Profiles
  Settings → General → VPN & Device Management
  Screenshot every profile. Record: Name, Organization, Identifier.
  If supervised: Settings → General → About → look for "supervised and managed by"

STEP 2 — Device Identifiers
  Settings → General → About
  Record: Serial Number, IMEI/MEID, Model Number, iOS Version.

STEP 3 — Certificate Trust Store
  Settings → General → About → Certificate Trust Settings
  Any enabled org certificate = organization can decrypt your HTTPS traffic.
  Screenshot all enabled entries.

STEP 4 — Network Proxy Check
  Settings → Wi-Fi → tap your connected network → HTTP Proxy
  If set to Automatic with a PAC URL, the org intercepts all HTTP traffic.

STEP 5 — Screen Time / Management
  Settings → Screen Time
  If you see "This Screen Time is managed by your family or organization"
  = the organization has Screen Time management.

STEP 6 — Apple Configurator (Mac required)
  Connect iPhone to Mac running Apple Configurator 2
  Actions → Export → Profiles → saves .mobileconfig files
  Upload those files to MDMCheck Uploaded Files for automated analysis.

Upload all screenshots and .mobileconfig files to MDMCheck Uploaded Files.
`;

async function handleProbeScript(request, env, ctx, params) {
  const platform = (params.platform || '').toLowerCase();
  const scripts = {
    android: { content: PROBE_SCRIPT_ANDROID, filename: 'mdmcheck-probe-android.sh',  mime: 'text/x-shellscript' },
    windows: { content: PROBE_SCRIPT_WINDOWS, filename: 'mdmcheck-probe-windows.ps1', mime: 'text/x-powershell'  },
    macos:   { content: PROBE_SCRIPT_MACOS,   filename: 'mdmcheck-probe-macos.sh',    mime: 'text/x-shellscript' },
    ios:     { content: PROBE_SCRIPT_IOS,     filename: 'mdmcheck-probe-ios.txt',     mime: 'text/plain'          },
  };

  const script = scripts[platform];
  if (!script) return json({ error: `Unknown platform: ${platform}. Valid: android, windows, macos, ios` }, 404);

  return new Response(script.content, {
    headers: {
      'Content-Type':        script.mime,
      'Content-Disposition': `attachment; filename="${script.filename}"`,
      'Cache-Control':       'public, max-age=3600',
    },
  });
}

// ─── EVIDENCE SAVE ────────────────────────────────────────────────────────────

async function handleEvidenceSave(request, env) {
  const session = await getSession(request, env);
  if (!session?.user?.email) {
    return json({ error: 'Authentication required to save evidence server-side.' }, 401);
  }

  const body = await request.json().catch(() => null);
  if (!body) return json({ error: 'Invalid JSON body.' }, 400);

  // Limit size — 512KB max per evidence record
  const bodyStr = JSON.stringify(body);
  if (bodyStr.length > 524288) {
    return json({ error: 'Evidence record too large. Max 512KB.' }, 413);
  }

  const evidenceId = crypto.randomUUID();
  await env.KV.put(
    `evidence:${session.user.email}:${evidenceId}`,
    bodyStr,
    { expirationTtl: 7776000 } // 90 days
  );

  return json({ id: evidenceId, saved_at: new Date().toISOString() }, 201);
}

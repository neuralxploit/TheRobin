/*
 * VulnCorp Portal — Client-Side JavaScript
 *
 * Contains intentional vulnerabilities for security testing:
 *   - DOM-based XSS (innerHTML from URL hash/params)
 *   - Hardcoded credentials & API keys
 *   - Sensitive data in localStorage
 *   - postMessage without origin validation
 *   - eval() on user input
 *   - Client-side access control bypass
 *   - Open redirect via JS
 *   - Prototype pollution via $.extend
 *   - Exposed internal endpoints and secrets in comments
 *   - Insecure JWT handling
 */

// ═══════════════════════════════════════════════════════════════════════════════
// VULN: Hardcoded credentials & API keys in client-side JavaScript
// Real-world: devs leave test creds, API keys, internal URLs in production JS
// ═══════════════════════════════════════════════════════════════════════════════
var APP_CONFIG = {
    api_base: '/api',
    api_key: 'FAKE_stripe_key_for_testing_do_not_use_1234567890',
    api_secret: 'corp_secret_f8a3b2c1d4e5f6a7b8c9d0e1f2a3b4c5',
    admin_password: 'admin123',
    db_connection: 'sqlite:///corp.db',
    internal_api: 'http://10.0.0.5:8080/internal/v2',
    aws_access_key: 'AKIAIOSFODNN7EXAMPLE',
    aws_secret_key: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    debug_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0.8Fp4M3kPZ1VgKoQvR9x2N0Lm5Jb6HcYt7Ud3Wq0XfSA',
    smtp_password: 'MailPass2024!',
    encryption_key: 'aes256-cbc-key-DO-NOT-SHARE-1234567890abcdef',
    // TODO: remove before production deployment
    backdoor_user: 'debug_admin',
    backdoor_pass: 'D3bug@ccess!2024',
};

// Internal API endpoints - for developer reference
// DELETE BEFORE PRODUCTION
var INTERNAL_ENDPOINTS = [
    '/api/v2/internal/users/export',
    '/api/v2/internal/db/backup',
    '/api/v2/internal/logs/download',
    '/api/v2/internal/config/reload',
    '/api/v2/internal/cache/flush',
    '/admin/phpinfo',
    '/server-status',
    '/.env',
    '/api/v2/internal/shell',   // remote management interface
];


// ═══════════════════════════════════════════════════════════════════════════════
// VULN: DOM-based XSS — reads from URL and writes to innerHTML
// Real-world: Single-page apps reading route params and rendering unsafely
// ═══════════════════════════════════════════════════════════════════════════════

// DOM XSS via location.hash — renders hash content directly into page
function renderHashContent() {
    var hash = decodeURIComponent(window.location.hash.substring(1));
    if (hash) {
        var target = document.getElementById('hash-content');
        if (target) {
            // VULN: Direct innerHTML injection from URL hash
            target.innerHTML = '<div class="alert alert-info">Navigation: ' + hash + '</div>';
        }
    }
}

// DOM XSS via URL parameter — reads 'msg' param and injects into DOM
function showNotification() {
    var params = new URLSearchParams(window.location.search);
    var msg = params.get('msg');
    var status = params.get('status');
    if (msg) {
        // VULN: innerHTML from URL parameter — DOM XSS
        document.getElementById('notification-area').innerHTML =
            '<div class="alert alert-' + (status || 'info') + '">' +
            '<strong>Notice:</strong> ' + msg + '</div>';
    }
}

// DOM XSS via document.referrer
function showReferrerBanner() {
    if (document.referrer) {
        var banner = document.getElementById('referrer-banner');
        if (banner) {
            // VULN: Referrer injected into DOM unsafely
            banner.innerHTML = 'You came from: <a href="' + document.referrer + '">' + document.referrer + '</a>';
        }
    }
}

// DOM XSS in search results — reads search param and highlights matches
function highlightSearchTerm() {
    var params = new URLSearchParams(window.location.search);
    var q = params.get('q');
    if (q) {
        var results = document.querySelectorAll('.search-result-text');
        results.forEach(function(el) {
            // VULN: Regex replacement injects unsanitized search term into HTML
            el.innerHTML = el.textContent.replace(
                new RegExp('(' + q + ')', 'gi'),
                '<mark class="highlight">$1</mark>'
            );
        });
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
// VULN: Sensitive data stored in localStorage (accessible to XSS)
// Real-world: SPAs store JWTs, PII, session data in localStorage
// ═══════════════════════════════════════════════════════════════════════════════

function storeUserSession(userData) {
    // VULN: Storing sensitive data in localStorage — accessible via XSS
    localStorage.setItem('auth_token', userData.token || APP_CONFIG.debug_token);
    localStorage.setItem('user_data', JSON.stringify({
        id: userData.id,
        username: userData.username,
        email: userData.email,
        role: userData.role,
        salary: userData.salary,
        ssn: userData.ssn,    // PII in localStorage!
    }));
    localStorage.setItem('api_key', APP_CONFIG.api_key);
    localStorage.setItem('session_id', userData.session_id || 'sess_' + Math.random().toString(36));

    // Also store in sessionStorage for good measure
    sessionStorage.setItem('csrf_token', 'not_really_validated_' + Date.now());
    sessionStorage.setItem('admin_flag', userData.role === 'admin' ? 'true' : 'false');
}

// Auto-populate localStorage on page load if logged in
$(document).ready(function() {
    var userEl = document.querySelector('[data-user-id]');
    if (userEl) {
        storeUserSession({
            id: userEl.getAttribute('data-user-id'),
            username: userEl.getAttribute('data-username'),
            email: userEl.getAttribute('data-email'),
            role: userEl.getAttribute('data-role'),
        });
    }
    renderHashContent();
    showNotification();
    showReferrerBanner();
    highlightSearchTerm();
    setupPostMessageHandler();
    initClientSideRouter();
});

// Listen for hash changes (DOM XSS retrigger)
window.addEventListener('hashchange', renderHashContent);


// ═══════════════════════════════════════════════════════════════════════════════
// VULN: postMessage without origin validation
// Real-world: Cross-origin messaging without checking event.origin
// ═══════════════════════════════════════════════════════════════════════════════

function setupPostMessageHandler() {
    window.addEventListener('message', function(event) {
        // VULN: No origin check — any page can send messages
        // event.origin is never validated
        console.log('[PostMessage] Received:', event.data);

        var data = event.data;
        if (typeof data === 'string') {
            try { data = JSON.parse(data); } catch(e) { return; }
        }

        switch(data.action) {
            case 'updateProfile':
                // VULN: Attacker can update user profile via cross-origin message
                $.post('/profile/' + data.userId + '/edit', data.fields);
                break;

            case 'renderHTML':
                // VULN: Attacker can inject arbitrary HTML via postMessage
                document.getElementById('dynamic-content').innerHTML = data.html;
                break;

            case 'navigate':
                // VULN: Open redirect via postMessage
                window.location.href = data.url;
                break;

            case 'getToken':
                // VULN: Sends auth token to requesting origin — no origin check
                event.source.postMessage({
                    type: 'authToken',
                    token: localStorage.getItem('auth_token'),
                    apiKey: APP_CONFIG.api_key,
                    sessionId: localStorage.getItem('session_id'),
                }, '*');  // VULN: sends to any origin with *
                break;

            case 'executeAction':
                // VULN: eval of postMessage data
                eval(data.code);
                break;

            default:
                break;
        }
    });
}


// ═══════════════════════════════════════════════════════════════════════════════
// VULN: eval() on user input — calculator feature
// Real-world: Template engines, calculators, dynamic filters using eval
// ═══════════════════════════════════════════════════════════════════════════════

function calculateExpense(expression) {
    try {
        // VULN: eval() on user-controlled input — allows arbitrary JS execution
        var result = eval(expression);
        return result;
    } catch(e) {
        return 'Error: ' + e.message;
    }
}

// Also exposed as a global for the calculator page
window.calculate = calculateExpense;


// ═══════════════════════════════════════════════════════════════════════════════
// VULN: Client-side access control — security checks in JavaScript
// Real-world: SPAs hiding admin features based on JS variables, not server checks
// ═══════════════════════════════════════════════════════════════════════════════

function checkAccess() {
    // VULN: Access control purely in JavaScript — can be bypassed via console
    var userData = JSON.parse(localStorage.getItem('user_data') || '{}');
    var isAdmin = (userData.role === 'admin') ||
                  (sessionStorage.getItem('admin_flag') === 'true');

    // Show/hide admin features based on client-side check only
    if (isAdmin) {
        $('.admin-only').show();
        $('#admin-tools-panel').removeClass('hidden');
    } else {
        $('.admin-only').hide();
    }

    // Client-side salary visibility check — easily bypassed
    if (userData.role === 'admin' || userData.role === 'hr') {
        $('.salary-field').show();
    } else {
        // VULN: Just hiding with CSS — data is still in the DOM
        $('.salary-field').css('display', 'none');
    }

    return isAdmin;
}


// ═══════════════════════════════════════════════════════════════════════════════
// VULN: Open redirect via JavaScript
// Real-world: Login redirects, SSO callbacks, link shorteners
// ═══════════════════════════════════════════════════════════════════════════════

function handleRedirect() {
    var params = new URLSearchParams(window.location.search);
    var returnUrl = params.get('return') || params.get('redirect') || params.get('next');
    if (returnUrl) {
        // VULN: No validation of redirect target — open redirect
        // Attacker: /login?return=https://evil.com/phishing
        setTimeout(function() {
            window.location.href = returnUrl;
        }, 100);
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
// VULN: Prototype pollution via jQuery $.extend
// Real-world: Deep merge of user-controlled JSON into objects
// ═══════════════════════════════════════════════════════════════════════════════

function applyUserSettings(settingsJson) {
    try {
        var userSettings = JSON.parse(settingsJson);
        // VULN: Deep $.extend with user-controlled data — prototype pollution
        // Payload: {"__proto__": {"isAdmin": true, "polluted": "yes"}}
        var mergedConfig = $.extend(true, {}, APP_CONFIG, userSettings);
        return mergedConfig;
    } catch(e) {
        console.error('Invalid settings JSON:', e);
        return APP_CONFIG;
    }
}

// Settings form handler
function saveSettings() {
    var settingsInput = document.getElementById('user-settings-json');
    if (settingsInput) {
        var merged = applyUserSettings(settingsInput.value);
        // After pollution, check if prototype was modified
        var testObj = {};
        if (testObj.isAdmin) {
            document.getElementById('settings-result').innerHTML =
                '<div class="alert alert-danger">Prototype pollution successful! ' +
                'testObj.isAdmin = ' + testObj.isAdmin + '</div>';
        } else {
            document.getElementById('settings-result').innerHTML =
                '<div class="alert alert-success">Settings applied: ' +
                JSON.stringify(merged).substring(0, 200) + '...</div>';
        }
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
// VULN: Insecure JWT handling
// Real-world: JWTs decoded client-side without signature verification
// ═══════════════════════════════════════════════════════════════════════════════

function parseJWT(token) {
    try {
        var parts = token.split('.');
        // VULN: Decoding JWT without verifying signature
        var header = JSON.parse(atob(parts[0]));
        var payload = JSON.parse(atob(parts[1]));
        // No signature verification!
        return { header: header, payload: payload, valid: true };
    } catch(e) {
        return { valid: false, error: e.message };
    }
}

// VULN: JWT "none" algorithm accepted
function verifyToken(token) {
    var parsed = parseJWT(token);
    if (!parsed.valid) return false;

    // VULN: If algorithm is "none", skip verification entirely
    if (parsed.header.alg === 'none' || parsed.header.alg === 'None') {
        console.log('[JWT] Algorithm "none" — skipping signature verification');
        return true;
    }

    // VULN: No actual server-side verification — trusts client-side decode
    return parsed.payload && parsed.payload.sub && parsed.payload.exp > Date.now()/1000;
}


// ═══════════════════════════════════════════════════════════════════════════════
// VULN: Client-side routing with innerHTML injection
// Real-world: Custom SPA routers that render page content from URL
// ═══════════════════════════════════════════════════════════════════════════════

var ROUTES = {
    '/app/home': '<h3>Welcome to CorpPortal</h3><p>Select a section from the menu.</p>',
    '/app/help': '<h3>Help</h3><p>Contact support at admin@corp.local</p>',
};

function initClientSideRouter() {
    var params = new URLSearchParams(window.location.search);
    var page = params.get('page');
    if (page) {
        var contentArea = document.getElementById('spa-content');
        if (contentArea) {
            if (ROUTES[page]) {
                contentArea.innerHTML = ROUTES[page];
            } else {
                // VULN: Reflects arbitrary 'page' param value into innerHTML
                contentArea.innerHTML = '<div class="alert alert-warning">' +
                    'Page not found: <code>' + page + '</code></div>';
            }
        }
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
// VULN: Insecure AJAX requests — sending credentials cross-origin
// Real-world: fetch/XHR with credentials to user-controlled URLs
// ═══════════════════════════════════════════════════════════════════════════════

function fetchExternalResource(url) {
    // VULN: Sends cookies and auth headers to any URL
    return fetch(url, {
        credentials: 'include',
        headers: {
            'Authorization': 'Bearer ' + localStorage.getItem('auth_token'),
            'X-API-Key': APP_CONFIG.api_key,
        }
    }).then(function(r) { return r.json(); });
}

// VULN: JSONP callback injection
function loadExternalData(callbackName) {
    // VULN: User-controlled callback name in JSONP — can execute arbitrary JS
    var script = document.createElement('script');
    script.src = '/api/data/export?callback=' + callbackName;
    document.head.appendChild(script);
}


// ═══════════════════════════════════════════════════════════════════════════════
// VULN: Insecure WebSocket connection
// Real-world: WebSocket without auth, sending sensitive data
// ═══════════════════════════════════════════════════════════════════════════════

function initWebSocket() {
    // VULN: WebSocket connection without TLS (ws:// not wss://)
    // VULN: No authentication token required
    try {
        var ws = new WebSocket('ws://' + window.location.host + '/ws/notifications');
        ws.onopen = function() {
            // VULN: Sends auth token over unencrypted WebSocket
            ws.send(JSON.stringify({
                type: 'auth',
                token: localStorage.getItem('auth_token'),
                apiKey: APP_CONFIG.api_key,
            }));
        };
        ws.onmessage = function(event) {
            var data = JSON.parse(event.data);
            // VULN: Renders WebSocket messages via innerHTML
            var container = document.getElementById('ws-messages');
            if (container) {
                container.innerHTML += '<div class="ws-msg">' + data.message + '</div>';
            }
        };
    } catch(e) {
        // WebSocket not available — silent fail
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
// VULN: Exposed debug/logging functions
// Real-world: Console logging of sensitive data, debug functions left in prod
// ═══════════════════════════════════════════════════════════════════════════════

// VULN: Debug function dumps all sensitive data to console
window.debugDump = function() {
    console.log('=== DEBUG DUMP ===');
    console.log('Config:', APP_CONFIG);
    console.log('Auth Token:', localStorage.getItem('auth_token'));
    console.log('User Data:', localStorage.getItem('user_data'));
    console.log('API Key:', APP_CONFIG.api_key);
    console.log('AWS Keys:', APP_CONFIG.aws_access_key, APP_CONFIG.aws_secret_key);
    console.log('Session:', document.cookie);
    return APP_CONFIG;
};

// VULN: Global function to get admin access — dev backdoor left in code
window.enableDevMode = function() {
    sessionStorage.setItem('admin_flag', 'true');
    localStorage.setItem('user_data', JSON.stringify({
        role: 'admin',
        username: 'dev_admin',
    }));
    checkAccess();
    console.log('[DEV] Admin mode enabled — refresh page to see admin features');
    return 'Admin mode activated';
};

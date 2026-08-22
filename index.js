const config = {
  no_ref: "off", //Control the HTTP referrer header, if you want to create an anonymous link that will hide the HTTP Referer header, please set to "on" .
  theme:"theme/captcha",//Homepage theme, use the empty value for default theme. To use urlcool theme, please fill with "theme/urlcool" . If you need captcha feature, you need to use captcha theme.
  cors: "on",//Allow Cross-origin resource sharing for API requests.
  unique_link:true,//If it is true, the same long url will be shorten into the same short url
  custom_link:false,//Allow users to customize the short url.
  safe_browsing_api_key: "", //Enter Google Safe Browsing API Key to enable url safety check before redirect.
  expiration_ttl: 0, // Short link expiration time in seconds. 86400 = 24 hours. Set to 0 for no expiration.
  
  // CAPTCHA Configuration
  captcha: {
    enabled: true, // Master switch for CAPTCHA service
    api_endpoint: "https://captcha.gurl.eu.org/api", // CAP Worker API endpoint
    require_on_create: true, // Require CAPTCHA when creating short links
    require_on_access: true, // Require CAPTCHA when accessing short links
    timeout: 5000, // API request timeout in milliseconds
    fallback_on_error: true, // Allow operations when CAPTCHA service is down
    max_retries: 2, // Maximum retry attempts for CAPTCHA API calls
  }
  }
  
  const html404 = `<!DOCTYPE html>
  <body>
    <h1>404 Not Found.</h1>
    <p>The url you visit is not found.</p>
    <a href="https://github.com/iemabdullah/URLShorter/" target="_self">Fork me on GitHub</a>
  </body>`
  
  let response_header={
    "content-type": "text/html;charset=UTF-8",
  } 
  
  if (config.cors=="on"){
    response_header={
    "content-type": "text/html;charset=UTF-8",
    "Access-Control-Allow-Origin":"*",
    "Access-Control-Allow-Methods": "POST",
    }
  }
  
  async function randomString(len) {
  　　len = len || 6;
  　　let $chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678';    /****默认去掉了容易混淆的字符oOLl,9gq,Vv,Uu,I1****/
  　　let maxPos = $chars.length;
  　　let result = '';
  　　for (let i = 0; i < len; i++) {
  　　　　result += $chars.charAt(Math.floor(Math.random() * maxPos));
  　　}
  　　return result;
  }
  
  async function sha512(url){
      url = new TextEncoder().encode(url)
  
      const url_digest = await crypto.subtle.digest(
        {
          name: "SHA-512",
        },
        url, // The data you want to hash as an ArrayBuffer
      )
      const hashArray = Array.from(new Uint8Array(url_digest)); // convert buffer to byte array
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      //console.log(hashHex)
      return hashHex
  }
  async function checkURL(URL){
      let str=URL;
      let Expression=/http(s)?:\/\/([\w-]+\.)+[\w-]+(\/[\w- .\/?%&=]*)?/;
      let objExp=new RegExp(Expression);
      if(objExp.test(str)==true){
        if (str[0] == 'h')
          return true;
        else
          return false;
      }else{
          return false;
      }
  } 
  function getKvPutOptions() {
    const MIN_TTL = 60;
    const rawTtl = Number(config.expiration_ttl);
    const hasValidTtl = Number.isFinite(rawTtl) && rawTtl >= MIN_TTL;
    return hasValidTtl ? { expirationTtl: Math.floor(rawTtl) } : {};
  }
  async function save_url(URL){
      let random_key=await randomString()
      let is_exist=await LINKS.get(random_key)
      console.log(is_exist)
      if (is_exist == null) {
          return await LINKS.put(random_key, URL, getKvPutOptions()), random_key
      }
      else
          return save_url(URL)
  }
  async function is_url_exist(url_sha512){
    let is_exist = await LINKS.get(url_sha512)
    console.log(is_exist)
    if (is_exist == null) {
      return false
    }else{
      return is_exist
    }
  }
  async function is_url_safe(url){
  
    let raw = JSON.stringify({"client":{"clientId":"URLShorter","clientVersion":"1.0.7"},"threatInfo":{"threatTypes":["MALWARE","SOCIAL_ENGINEERING","POTENTIALLY_HARMFUL_APPLICATION","UNWANTED_SOFTWARE"],"platformTypes":["ANY_PLATFORM"],"threatEntryTypes":["URL"],"threatEntries":[{"url":url}]}});
  
    let requestOptions = {
      method: 'POST',
      body: raw,
      redirect: 'follow'
    };
  
    let result = await fetch("https://safebrowsing.googleapis.com/v4/threatMatches:find?key="+config.safe_browsing_api_key, requestOptions)
    result = await result.json()
    console.log(result)
    if (Object.keys(result).length === 0){
      return true
    }else{
      return false
    }
  }
  
  // ============ CAPTCHA Service Integration ============
  
  /**
   * Validates CAPTCHA token with retry and fallback mechanism
   * @param {string} token - The CAPTCHA token to validate
   * @param {boolean} keepToken - Whether to keep the token for reuse
   * @returns {Promise<{success: boolean, error?: string, degraded?: boolean}>}
   */
  async function validateCaptchaToken(token, keepToken = false) {
    // If CAPTCHA is disabled, always return success
    if (!config.captcha.enabled) {
      return { success: true, degraded: false };
    }
  
    // Validate token format
    if (!token || typeof token !== 'string' || token.length < 10) {
      return { success: false, error: 'Invalid token format' };
    }
  
    let lastError = null;
    const maxRetries = config.captcha.max_retries || 2;
  
    // Retry mechanism for resilience
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), config.captcha.timeout);
  
        const response = await fetch(`${config.captcha.api_endpoint}/validate`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'URLShorter/1.0.7',
          },
          body: JSON.stringify({ token, keepToken }),
          signal: controller.signal,
        });
  
        clearTimeout(timeoutId);
  
        // Handle various HTTP status codes
        if (response.ok) {
          const result = await response.json();
          return { success: result.success === true, degraded: false };
        }
  
        // Handle specific error codes
        if (response.status === 400 || response.status === 410 || response.status === 404 || response.status === 409) {
          // Client error, no need to retry
          return { success: false, error: 'Invalid or expired token' };
        }
  
        lastError = `HTTP ${response.status}`;
      } catch (error) {
        lastError = error.name === 'AbortError' ? 'Timeout' : error.message;
        console.error(`CAPTCHA validation attempt ${attempt + 1} failed:`, lastError);
  
        // Exponential backoff before retry (except on last attempt)
        if (attempt < maxRetries) {
          await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 100));
        }
      }
    }
  
    // Service degradation: if fallback is enabled, allow operation
    if (config.captcha.fallback_on_error) {
      console.warn(`CAPTCHA service degraded: ${lastError}. Allowing operation due to fallback policy.`);
      return { success: true, degraded: true };
    }
  
    return { success: false, error: lastError || 'CAPTCHA service unavailable' };
  }
  
  /**
   * Checks if CAPTCHA is required for the current operation
   * @param {string} operation - 'create' or 'access'
   * @returns {boolean}
   */
  function isCaptchaRequired(operation) {
    if (!config.captcha.enabled) {
      return false;
    }
  
    switch (operation) {
      case 'create':
        return config.captcha.require_on_create;
      case 'access':
        return config.captcha.require_on_access;
      default:
        return false;
    }
  }
  
  /**
   * Extracts CAPTCHA token from request
   * @param {Request} request - The incoming request
   * @returns {Promise<string|null>}
   */
  async function extractCaptchaToken(request) {
    const contentType = request.headers.get('content-type') || '';
  
    if (contentType.includes('application/json')) {
      try {
        const body = await request.clone().json();
        return body.captcha_token || body.captchaToken || body.token || null;
      } catch {
        return null;
      }
    }
  
    // Try to extract from URL parameters
    const url = new URL(request.url);
    return url.searchParams.get('captcha_token') || url.searchParams.get('token') || null;
  }
  
  // ============ End CAPTCHA Service Integration ============
  async function handleRequest(request) {
    console.log(request)
    
    // Handle POST request - Create short link
    if (request.method === "POST") {
      let req = await request.json()
      console.log(req["url"])
      
      // Validate URL format
      if (!await checkURL(req["url"])) {
        return new Response(JSON.stringify({
          status: 500,
          error: "Invalid URL format"
        }), {
          headers: response_header,
          status: 400
        })
      }
  
      // CAPTCHA validation for link creation
      if (isCaptchaRequired('create')) {
        const captchaToken = req.captcha_token || req.captchaToken || req.token;
        
        if (!captchaToken) {
          return new Response(JSON.stringify({
            status: 403,
            error: "CAPTCHA token required",
            captcha_required: true
          }), {
            headers: response_header,
            status: 403
          })
        }
  
        const validation = await validateCaptchaToken(captchaToken, false);
        
        if (!validation.success) {
          return new Response(JSON.stringify({
            status: 403,
            error: validation.error || "CAPTCHA verification failed",
            captcha_required: true
          }), {
            headers: response_header,
            status: 403
          })
        }
  
        // Log if service is degraded
        if (validation.degraded) {
          console.warn("Request processed under CAPTCHA service degradation");
        }
      }
  
      // Process short link creation
      let stat, random_key
      if (config.unique_link) {
        let url_sha512 = await sha512(req["url"])
        let url_key = await is_url_exist(url_sha512)
        if (url_key) {
          random_key = url_key
        } else {
          stat, random_key = await save_url(req["url"])
          if (typeof(stat) == "undefined") {
            console.log(await LINKS.put(url_sha512, random_key, getKvPutOptions()))
          }
        }
      } else {
        stat, random_key = await save_url(req["url"])
      }
      
      console.log(stat)
      if (typeof(stat) == "undefined") {
        return new Response(JSON.stringify({
          status: 200,
          key: "/" + random_key,
          short_url: "/" + random_key
        }), {
          headers: response_header,
        })
      } else {
        return new Response(JSON.stringify({
          status: 500,
          error: "Reached KV write limitation"
        }), {
          headers: response_header,
          status: 500
        })
      }
    } else if (request.method === "OPTIONS") {  
      return new Response("", {
        headers: response_header,
      })
    }
  
    // Handle GET request - Access short link
    const requestURL = new URL(request.url)
    const path = requestURL.pathname.split("/")[1]
    const params = requestURL.search
  
    console.log(path)
    
    // Serve homepage locally so the Worker does not depend on an external theme repository.
    if (!path) {
      const captchaEnabled = isCaptchaRequired('create');
      const sourceUrl = "https://github.com/iemabdullah/URLShorter";
      const captchaScript = captchaEnabled ? '<script src="https://captcha.gurl.eu.org/cap.min.js"></script>' : '';
      const captchaMarkup = captchaEnabled ? `<div class="captcha-wrap"><cap-widget id="cap" data-cap-api-endpoint="${config.captcha.api_endpoint}/"></cap-widget></div>` : '';
      const html = `<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#f6f7ff">
<meta name="description" content="Fast, secure and reliable URL shortening by Abdullah Bin Shahid.">
<title>URLShorter — Fast, Secure URL Shortening</title>${captchaScript}
<style>
*{box-sizing:border-box}
html{scroll-behavior:smooth}
:root{
 --bg:#f6f7ff;--surface:rgba(255,255,255,.82);--surface2:#fff;--text:#151827;
 --muted:#687087;--border:rgba(76,85,125,.13);--primary:#6d5dfc;--primary2:#8b5cf6;
 --pink:#db2777;--blue:#2563eb;--green:#10b981;--shadow:0 24px 70px rgba(51,45,105,.12);
}
html[data-theme="dark"]{
 --bg:#070b1a;--surface:rgba(13,18,40,.78);--surface2:#0d1228;--text:#f4f6ff;
 --muted:#a6aec5;--border:rgba(175,184,230,.13);--shadow:0 28px 80px rgba(0,0,0,.4);
}
body{
 margin:0;min-height:100vh;color:var(--text);font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;
 background:
 radial-gradient(circle at 8% 5%,rgba(109,93,252,.18),transparent 25%),
 radial-gradient(circle at 92% 12%,rgba(34,211,238,.14),transparent 24%),
 radial-gradient(circle at 75% 90%,rgba(219,39,119,.10),transparent 28%),var(--bg);
 overflow-x:hidden;transition:background .3s,color .3s;
}
body:before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.35;background-image:radial-gradient(rgba(109,93,252,.2) 1px,transparent 1px);background-size:32px 32px;mask-image:linear-gradient(to bottom,#000,transparent 75%)}
a{color:inherit}
.container{width:min(1120px,calc(100% - 32px));margin:auto}
.site-header{
 position:sticky;top:12px;z-index:50;margin:12px auto 0;width:min(1120px,calc(100% - 24px));
 background:var(--surface);border:1px solid var(--border);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
 border-radius:20px;box-shadow:0 10px 35px rgba(30,35,70,.08);
}
.nav{min-height:70px;display:flex;align-items:center;justify-content:space-between;padding:0 18px}
.brand{display:flex;align-items:center;gap:11px;text-decoration:none;font-weight:900;font-size:21px;letter-spacing:-.5px}
.brand-icon{width:42px;height:42px;border-radius:13px;display:grid;place-items:center;color:#fff;background:linear-gradient(135deg,var(--primary),var(--pink));box-shadow:0 9px 24px rgba(109,93,252,.28);font-size:21px}
.brand b{color:var(--primary)}.nav-links{display:flex;gap:26px;align-items:center}
.nav-links a{text-decoration:none;color:var(--muted);font-size:14px;font-weight:700}.nav-links a:hover{color:var(--primary)}
.nav-actions{display:flex;align-items:center;gap:8px}
.icon-btn,.github-btn{height:42px;border:1px solid var(--border);border-radius:12px;background:var(--surface2);color:var(--text);cursor:pointer;font-weight:800}
.icon-btn{width:42px;font-size:18px}.github-btn{padding:0 15px;text-decoration:none;display:flex;align-items:center;gap:7px;background:linear-gradient(135deg,var(--primary),var(--pink));color:#fff;border:0}
.hero{text-align:center;padding:82px 0 50px;position:relative}
.pill{display:inline-flex;gap:8px;align-items:center;padding:8px 13px;border-radius:999px;border:1px solid var(--border);background:var(--surface);font-size:12px;font-weight:800;color:var(--muted);box-shadow:0 8px 24px rgba(60,50,120,.06)}
.dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 12px var(--green)}
.hero h1{font-size:clamp(42px,7vw,78px);line-height:.98;letter-spacing:-3.5px;margin:22px auto 18px;max-width:850px}
.gradient{background:linear-gradient(90deg,#4f46e5,#7c3aed,#db2777,#2563eb);background-size:200%;-webkit-background-clip:text;background-clip:text;color:transparent;animation:gradient 6s linear infinite}
.hero p{max-width:690px;margin:auto;color:var(--muted);font-size:18px;line-height:1.65}
.hero-badges{display:flex;justify-content:center;gap:10px;flex-wrap:wrap;margin:26px 0}
.badge{padding:8px 13px;border:1px solid var(--border);border-radius:999px;background:var(--surface);font-size:12px;font-weight:800;box-shadow:0 7px 20px rgba(50,45,100,.05)}
.shortener{
 position:relative;overflow:hidden;padding:28px;border:1px solid var(--border);border-radius:25px;background:var(--surface);
 backdrop-filter:blur(22px);-webkit-backdrop-filter:blur(22px);box-shadow:var(--shadow)
}
.shortener:before{content:"";position:absolute;width:280px;height:280px;right:-140px;top:-150px;background:rgba(109,93,252,.18);filter:blur(45px);border-radius:50%}
.section-title{margin:0 0 6px;font-size:24px}.section-sub{margin:0 0 22px;color:var(--muted);font-size:14px}
.input-row{display:grid;grid-template-columns:1fr 180px;gap:12px}
.input-wrap{position:relative}
.url-input{width:100%;height:58px;padding:0 17px;border-radius:15px;border:1.5px solid var(--border);background:var(--surface2);color:var(--text);outline:none;font-size:16px;transition:.25s}
.url-input:focus{border-color:var(--primary);box-shadow:0 0 0 4px rgba(109,93,252,.12)}
.primary-btn{height:58px;border:0;border-radius:15px;background:linear-gradient(110deg,#5b5cf0,#7c3aed 48%,#db2777);background-size:200%;color:#fff;font-size:15px;font-weight:850;cursor:pointer;box-shadow:0 14px 30px rgba(99,75,220,.24);transition:.22s}
.primary-btn:hover{transform:translateY(-2px);background-position:100% 0;box-shadow:0 18px 35px rgba(99,75,220,.32)}
.primary-btn:disabled{opacity:.65;cursor:not-allowed;transform:none}
.captcha-wrap{margin-top:17px;display:flex;justify-content:center}
.result{
 display:none;margin-top:18px;padding:18px;border:1px solid rgba(16,185,129,.25);border-radius:18px;
 background:linear-gradient(135deg,rgba(16,185,129,.08),rgba(109,93,252,.07));animation:pop .3s ease
}
.result-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:10px}
.result-title{font-size:14px;font-weight:900}.success{color:var(--green)}
.result-row{display:grid;grid-template-columns:1fr auto;gap:9px}
.result-url{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding:13px 14px;border-radius:12px;border:1px solid var(--border);background:var(--surface2);font-weight:750;color:var(--primary)}
.copy-btn{border:0;border-radius:12px;padding:0 18px;background:var(--green);color:#fff;font-weight:850;cursor:pointer;min-width:92px}.copy-btn:hover{filter:brightness(.95)}
.error{display:none;margin-top:14px;padding:12px 14px;border-radius:12px;background:rgba(244,63,94,.08);color:#e11d48;border:1px solid rgba(244,63,94,.18);font-size:13px;text-align:center}
.trust{display:flex;justify-content:center;gap:22px;flex-wrap:wrap;margin-top:18px;color:var(--muted);font-size:12px;font-weight:700}
.features{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;padding:75px 0 30px}
.feature{padding:24px;border:1px solid var(--border);border-radius:20px;background:var(--surface);box-shadow:0 12px 35px rgba(45,40,90,.06);transition:.25s}
.feature:hover{transform:translateY(-6px);box-shadow:0 22px 45px rgba(45,40,90,.11)}
.feature-icon{width:46px;height:46px;border-radius:14px;display:grid;place-items:center;color:#fff;font-size:21px;margin-bottom:16px;background:linear-gradient(135deg,var(--primary),var(--pink))}
.feature:nth-child(2) .feature-icon{background:linear-gradient(135deg,#10b981,#06b6d4)}
.feature:nth-child(3) .feature-icon{background:linear-gradient(135deg,#2563eb,#06b6d4)}
.feature:nth-child(4) .feature-icon{background:linear-gradient(135deg,#f97316,#db2777)}
.feature h3{margin:0 0 8px;font-size:16px}.feature p{margin:0;color:var(--muted);font-size:13px;line-height:1.65}
.how{padding:70px 0}.center{text-align:center}.center p{color:var(--muted)}
.steps{display:grid;grid-template-columns:repeat(3,1fr);gap:20px;margin-top:30px}
.step{position:relative;text-align:center;padding:28px;border:1px solid var(--border);border-radius:22px;background:var(--surface)}
.num{width:42px;height:42px;margin:0 auto 15px;border-radius:50%;display:grid;place-items:center;color:#fff;font-weight:900;background:linear-gradient(135deg,var(--primary),var(--pink));box-shadow:0 9px 25px rgba(109,93,252,.25)}
.step h3{margin:0 0 8px}.step p{margin:0;color:var(--muted);font-size:13px;line-height:1.6}
.about{padding:35px 0 75px}.about-card{padding:32px;border-radius:24px;background:linear-gradient(135deg,rgba(109,93,252,.10),rgba(34,211,238,.08));border:1px solid var(--border);text-align:center}.about-card p{max-width:760px;margin:10px auto;color:var(--muted);line-height:1.7}
.site-footer{border-top:1px solid var(--border);padding:55px 0 20px;background:rgba(0,0,0,.02)}
.footer-grid{display:grid;grid-template-columns:1.6fr 1fr 1fr 1fr;gap:35px}.footer-title{font-size:16px;font-weight:900;margin:0 0 14px}.footer-text,.footer-links a{color:var(--muted);font-size:13px;line-height:1.7}.footer-links{display:flex;flex-direction:column;gap:7px}.footer-links a{text-decoration:none}.footer-links a:hover{color:var(--primary)}
.personal-link{display:inline-block;margin-top:12px;padding:9px 12px;border:1px solid var(--border);border-radius:10px;color:var(--primary)!important;font-weight:800!important}
.copyright{margin-top:42px;padding-top:18px;border-top:1px solid var(--border);text-align:center;color:var(--muted);font-size:12px}
.top-btn{position:fixed;right:22px;bottom:22px;width:45px;height:45px;border:1px solid rgba(109,93,252,.4);border-radius:50%;background:var(--surface);color:var(--primary);font-size:18px;cursor:pointer;box-shadow:0 12px 30px rgba(50,45,100,.14);z-index:40}
@keyframes gradient{0%{background-position:0}50%{background-position:100%}100%{background-position:0}}
@keyframes pop{from{opacity:0;transform:translateY(8px) scale(.98)}to{opacity:1;transform:none}}
@media(max-width:850px){.nav-links{display:none}.features{grid-template-columns:repeat(2,1fr)}.footer-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:620px){
 .container{width:min(100% - 22px,1120px)}.site-header{width:calc(100% - 14px);top:7px;margin-top:7px}.nav{min-height:62px;padding:0 11px}
 .brand{font-size:18px}.brand-icon{width:37px;height:37px}.github-btn{display:none}.hero{padding:62px 0 35px}.hero h1{font-size:clamp(39px,13vw,58px);letter-spacing:-2.5px}.hero p{font-size:15px}
 .shortener{padding:20px;border-radius:20px}.input-row{grid-template-columns:1fr}.primary-btn{width:100%}
 .features,.steps{grid-template-columns:1fr}.features{padding-top:45px}.how{padding:50px 0}.about{padding-bottom:50px}
 .footer-grid{grid-template-columns:1fr;gap:25px}.result-row{grid-template-columns:1fr}.copy-btn{height:48px}.result-url{white-space:normal;overflow-wrap:anywhere}
}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation:none!important;scroll-behavior:auto!important;transition:none!important}}
</style>
</head>
<body>
<header class="site-header">
<nav class="nav">
<a class="brand" href="#"><span class="brand-icon">↗</span><span>URL<b>Shorter</b></span></a>
<div class="nav-links"><a href="#home">Home</a><a href="#features">Features</a><a href="#how">How It Works</a><a href="#about">About</a></div>
<div class="nav-actions">
<button class="icon-btn" id="themeToggle" title="Toggle theme" aria-label="Toggle dark mode">☾</button>
<a class="github-btn" href="https://github.com/iemabdullah/URLShorter" target="_blank" rel="noopener">GitHub ↗</a>
</div>
</nav>
</header>

<main id="home">
<section class="hero">
<div class="container">
<div class="pill"><span class="dot"></span> Fast • Secure • Reliable URL Shortening</div>
<h1>Shorten <span class="gradient">URLs</span><br>the smarter way.</h1>
<p>Transform long, complicated links into short, clean and shareable URLs — with a beautiful, fast and secure experience.</p>
<div class="hero-badges"><span class="badge">⚡ Lightning Fast</span><span class="badge">🔒 CAPTCHA Protected</span><span class="badge">✓ Reliable</span></div>
</div>
</section>

<section class="container">
<div class="shortener">
<h2 class="section-title">Enter your long URL</h2>
<p class="section-sub">Paste your link below and create a short URL in seconds.</p>
<div class="input-row">
<input class="url-input" id="url" type="url" placeholder="https://example.com/your-long-url" autocomplete="url">
<button class="primary-btn" id="shorten">✦ Shorten URL</button>
</div>
${captchaMarkup}
<div id="error" class="error"></div>
<div id="result" class="result">
<div class="result-head"><div class="result-title"><span class="success">✓</span> Your short URL</div><span class="success" style="font-size:12px;font-weight:800">Ready to share</span></div>
<div class="result-row"><div id="shortUrl" class="result-url"></div><button id="copyBtn" class="copy-btn">Copy</button></div>
</div>
<div class="trust"><span>🛡 Secure processing</span><span>⚡ Fast response</span><span>🔗 Easy to share</span></div>
</div>
</section>

<section id="features" class="container features">
<div class="feature"><div class="feature-icon">⚡</div><h3>Lightning Fast</h3><p>Create short links quickly with a lightweight Worker-powered service.</p></div>
<div class="feature"><div class="feature-icon">🛡</div><h3>Secure & Safe</h3><p>CAPTCHA protection helps reduce unwanted automated link creation and access.</p></div>
<div class="feature"><div class="feature-icon">📊</div><h3>Reliable</h3><p>Simple infrastructure designed for fast redirects and dependable sharing.</p></div>
<div class="feature"><div class="feature-icon">∞</div><h3>Easy to Share</h3><p>Get a clean short URL that is easy to copy, remember and send anywhere.</p></div>
</section>

<section id="how" class="how">
<div class="container">
<div class="center"><h2>How It Works</h2><p>Three simple steps — that's it.</p></div>
<div class="steps">
<div class="step"><div class="num">1</div><h3>Paste URL</h3><p>Enter your long URL into the secure URL field above.</p></div>
<div class="step"><div class="num">2</div><h3>Shorten</h3><p>Click “Shorten URL” and the Worker creates your short link.</p></div>
<div class="step"><div class="num">3</div><h3>Copy & Share</h3><p>Copy your new short URL and share it anywhere you want.</p></div>
</div>
</div>
</section>

<section id="about" class="container about">
<div class="about-card">
<h2>Simple. Modern. Built for the web.</h2>
<p>URLShorter is designed to make URL shortening quick and pleasant on desktop, tablet and mobile. The interface supports light mode by default and a polished dark mode whenever you prefer it.</p>
</div>
</section>
</main>

<footer class="site-footer">
<div class="container">
<div class="footer-grid">
<div><div class="brand"><span class="brand-icon">↗</span><span>URL<b>Shorter</b></span></div><p class="footer-text">A fast, secure and reliable URL shortening service with a clean modern experience.</p></div>
<div><h3 class="footer-title">Quick Links</h3><div class="footer-links"><a href="#home">Home</a><a href="#features">Features</a><a href="#how">How It Works</a><a href="#about">About</a></div></div>
<div><h3 class="footer-title">Source</h3><div class="footer-links"><a href="https://github.com/iemabdullah/URLShorter" target="_blank" rel="noopener">View Source Code ↗</a><a href="https://github.com/iemabdullah/URLShorter" target="_blank" rel="noopener">GitHub Repository</a></div></div>
<div><h3 class="footer-title">Created By</h3><div class="footer-links"><a href="http://abdullah.nyc.mn/" target="_blank" rel="noopener">Abdullah Bin Shahid</a><a class="personal-link" href="http://abdullah.nyc.mn/" target="_blank" rel="noopener">abdullah.nyc.mn ↗</a></div></div>
</div>
<div class="copyright">© ${new Date().getFullYear()} URLShorter by <strong>Abdullah Bin Shahid</strong> · All rights reserved.</div>
</div>
</footer>
<button class="top-btn" id="topBtn" title="Back to top" aria-label="Back to top">↑</button>

<script>
const input=document.getElementById('url'),button=document.getElementById('shorten'),errorBox=document.getElementById('error'),resultBox=document.getElementById('result'),shortUrlBox=document.getElementById('shortUrl'),copyBtn=document.getElementById('copyBtn'),themeToggle=document.getElementById('themeToggle'),topBtn=document.getElementById('topBtn');
let captchaToken=null;
${captchaEnabled ? "const cap=document.getElementById('cap');cap.addEventListener('solve',e=>{captchaToken=e.detail.token;});" : ''}
const root=document.documentElement;
const savedTheme=localStorage.getItem('urlshorter-theme');
if(savedTheme==='dark'){root.setAttribute('data-theme','dark');themeToggle.textContent='☀';}else{root.setAttribute('data-theme','light');themeToggle.textContent='☾';}
themeToggle.addEventListener('click',()=>{const dark=root.getAttribute('data-theme')==='dark';root.setAttribute('data-theme',dark?'light':'dark');themeToggle.textContent=dark?'☾':'☀';localStorage.setItem('urlshorter-theme',dark?'light':'dark');});
window.addEventListener('scroll',()=>{topBtn.style.opacity=window.scrollY>450?'1':'0';topBtn.style.pointerEvents=window.scrollY>450?'auto':'none';});
topBtn.style.opacity='0';topBtn.style.pointerEvents='none';topBtn.addEventListener('click',()=>window.scrollTo({top:0,behavior:'smooth'}));
copyBtn.addEventListener('click',async()=>{try{await navigator.clipboard.writeText(shortUrlBox.textContent);copyBtn.textContent='Copied ✓';setTimeout(()=>copyBtn.textContent='Copy',1500);}catch(e){const t=document.createElement('textarea');t.value=shortUrlBox.textContent;document.body.appendChild(t);t.select();document.execCommand('copy');t.remove();copyBtn.textContent='Copied ✓';setTimeout(()=>copyBtn.textContent='Copy',1500);}});
button.addEventListener('click',async()=>{
 errorBox.style.display='none';resultBox.style.display='none';const url=input.value.trim();
 if(!url){errorBox.textContent='Please enter a URL first.';errorBox.style.display='block';input.focus();return;}
 button.disabled=true;button.textContent='Creating your short link…';
 try{
  const payload={url};
  ${captchaEnabled ? "if(!captchaToken)throw new Error('Please complete the CAPTCHA first.');payload.captcha_token=captchaToken;" : ''}
  const response=await fetch('/',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const data=await response.json();
  if(!response.ok||data.status!==200)throw new Error(data.error||'Unable to shorten this URL.');
  const shortUrl=new URL(data.short_url,location.origin).href;
  shortUrlBox.textContent=shortUrl;resultBox.style.display='block';resultBox.scrollIntoView({behavior:'smooth',block:'nearest'});
 }catch(err){errorBox.textContent=err.message||'Something went wrong.';errorBox.style.display='block';}
 finally{button.disabled=false;button.textContent='✦ Shorten URL';}
});
input.addEventListener('keydown',e=>{if(e.key==='Enter')button.click();});
</script>
</body></html>`;
      return new Response(html, { headers: { "content-type": "text/html;charset=UTF-8" } });
    }
  
    // Retrieve the target URL
    const value = await LINKS.get(path)
    let location
  
    if (params) {
      location = value + params
    } else {
      location = value
    }
    console.log(value)
  
    if (location) {
      // CAPTCHA validation for link access
      if (isCaptchaRequired('access')) {
        const captchaToken = await extractCaptchaToken(request)
        
        if (!captchaToken) {
          // Return CAPTCHA challenge page
          const captchaPage = `
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verification Required</title>
    <script src="https://captcha.gurl.eu.org/cap.min.js"></script>
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; 
             display: flex; justify-content: center; align-items: center; min-height: 100vh; 
             margin: 0; background: linear-gradient(45deg, rgba(14, 46, 75, 1.000) 0.000%, rgba(14, 46, 75, 1.000) 7.692%, rgba(19, 52, 84, 1.000) 7.692%, rgba(19, 52, 84, 1.000) 15.385%, rgba(25, 58, 94, 1.000) 15.385%, rgba(25, 58, 94, 1.000) 23.077%, rgba(31, 65, 104, 1.000) 23.077%, rgba(31, 65, 104, 1.000) 30.769%, rgba(38, 72, 115, 1.000) 30.769%, rgba(38, 72, 115, 1.000) 38.462%, rgba(45, 79, 126, 1.000) 38.462%, rgba(45, 79, 126, 1.000) 46.154%, rgba(52, 86, 138, 1.000) 46.154%, rgba(52, 86, 138, 1.000) 53.846%, rgba(59, 93, 150, 1.000) 53.846%, rgba(59, 93, 150, 1.000) 61.538%, rgba(67, 101, 163, 1.000) 61.538%, rgba(67, 101, 163, 1.000) 69.231%, rgba(75, 109, 176, 1.000) 69.231%, rgba(75, 109, 176, 1.000) 76.923%, rgba(83, 117, 188, 1.000) 76.923%, rgba(83, 117, 188, 1.000) 84.615%, rgba(91, 125, 201, 1.000) 84.615%, rgba(91, 125, 201, 1.000) 92.308%, rgba(99, 134, 214, 1.000) 92.308% 100.000%) }
      .container { background: white; padding: 2rem; border-radius: 10px; box-shadow: 0 10px 40px rgba(0,0,0,0.1); 
                   max-width: 400px; text-align: center; }
      h1 { color: #333; margin-bottom: 1rem; font-size: 1.5rem; }
      p { color: #666; margin-bottom: 2rem; }
      #cap { margin: 2rem 0; display: flex; justify-content: center;}
      .loading { display: none; color: #667eea; margin-top: 1rem; }
    </style>
  </head>
  <body>
    <div class="container">
      <h1>🔒 Verification Required</h1>
      <p>Please complete the CAPTCHA below to access this link.</p>
      
      <cap-widget id="cap" data-cap-api-endpoint="https://captcha.gurl.eu.org/api/"></cap-widget>
      
      <div class="loading" id="loading">Verifying and redirecting...</div>
    </div>
  
    <script>
      const widget = document.querySelector("#cap");
      const loading = document.getElementById("loading");
      
      widget.addEventListener("solve", async function (e) {
        const token = e.detail.token;
        loading.style.display = "block";
        
        // Redirect with token
        window.location.href = window.location.pathname + "?captcha_token=" + encodeURIComponent(token);
      });
    </script>
  </body>
  </html>`
          
          return new Response(captchaPage, {
            headers: {
              "content-type": "text/html;charset=UTF-8",
            },
            status: 403
          })
        }
  
        const validation = await validateCaptchaToken(captchaToken, false)
        
        if (!validation.success) {
          return new Response(`
  <!DOCTYPE html>
  <html>
  <head><title>Verification Failed</title></head>
  <body>
    <h1>❌ Verification Failed</h1>
    <p>${validation.error || 'CAPTCHA verification failed'}</p>
    <a href="${requestURL.pathname}">Try again</a>
  </body>
  </html>`, {
            headers: {
              "content-type": "text/html;charset=UTF-8",
            },
            status: 403
          })
        }
  
        if (validation.degraded) {
          console.warn("Access granted under CAPTCHA service degradation")
        }
      }
  
      // Safe browsing check
      if (config.safe_browsing_api_key) {
        if (!(await is_url_safe(location))) {
          const warning_page = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Unsafe URL</title><style>body{font-family:Arial,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;background:#f7f8fb}.box{max-width:560px;background:#fff;padding:32px;border-radius:14px;box-shadow:0 10px 30px rgba(0,0,0,.08)}h1{color:#c62828}a{color:#087cf0;word-break:break-all}</style></head><body><div class="box"><h1>Unsafe URL</h1><p>This destination was blocked by the URL safety check.</p><a href="${location}">${location}</a></div></body></html>`
          return new Response(warning_page, {
            headers: {
              "content-type": "text/html;charset=UTF-8",
            },
          })
        }
      }
  
      // Redirect to target URL
      if (config.no_ref == "on") {
        const no_ref = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Redirecting...</title></head><body><p>Redirecting...</p><script>location.replace(${JSON.stringify(location)});</script></body></html>`
        return new Response(no_ref, {
          headers: {
            "content-type": "text/html;charset=UTF-8",
          },
        })
      } else {
        return Response.redirect(location, 302)
      }
    }
    
    // If request not in kv, return 404
    return new Response(html404, {
      headers: {
        "content-type": "text/html;charset=UTF-8",
      },
      status: 404
    })
  }
  
  
  
  addEventListener("fetch", async event => {
    event.respondWith(handleRequest(event.request))
  })

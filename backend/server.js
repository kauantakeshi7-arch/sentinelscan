import express from 'express';
import cors from 'cors';
import tls from 'tls';
import dns from 'dns';
import net from 'net';
import { promisify } from 'util';

const resolveTxt = promisify(dns.resolveTxt);
const resolveMx = promisify(dns.resolveMx);
const resolve4 = promisify(dns.resolve4);

const app = express();
const PORT = process.env.PORT || 5001;

app.use(cors());
app.use(express.json());

// Helper to normalize and parse URL/Hostname
function parseTarget(urlInput) {
  let urlStr = urlInput.trim();
  if (!/^https?:\/\//i.test(urlStr)) {
    urlStr = 'https://' + urlStr;
  }
  try {
    const parsed = new URL(urlStr);
    return {
      url: urlStr,
      hostname: parsed.hostname,
      protocol: parsed.protocol,
    };
  } catch (err) {
    throw new Error('Invalid URL format');
  }
}

// 1. Recursive Web Crawler (Spider)
async function crawlLinks(startUrl, hostname) {
  const visited = new Set();
  const urlsToCrawl = [startUrl];
  const maxPages = 8; // Crawl up to 8 pages to keep it fast

  while (urlsToCrawl.length > 0 && visited.size < maxPages) {
    const currentUrl = urlsToCrawl.shift();
    if (visited.has(currentUrl)) continue;

    try {
      visited.add(currentUrl);

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);
      const res = await fetch(currentUrl, {
        signal: controller.signal,
        headers: { 'User-Agent': 'Mozilla/5.0 SecurityScanner/1.0' }
      });
      clearTimeout(timeoutId);

      const contentType = res.headers.get('content-type') || '';
      if (!contentType.includes('text/html')) continue;

      const html = await res.text();

      // Extract internal links using regex
      const hrefRegex = /href=["']([^"']+)["']/gi;
      let match;
      while ((match = hrefRegex.exec(html)) !== null) {
        let href = match[1].trim();

        // Skip anchors, mailto, javascript links
        if (href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('javascript:')) continue;

        let absoluteUrl;
        try {
          absoluteUrl = new URL(href, currentUrl).href;
        } catch (e) {
          continue;
        }

        const parsed = new URL(absoluteUrl);
        // Ensure same domain & not static assets (images, css, pdf)
        const isSameDomain = parsed.hostname === hostname;
        const isNotAsset = !/\.(png|jpe?g|gif|pdf|zip|css|js|woff2?|svg)$/i.test(parsed.pathname);

        if (isSameDomain && isNotAsset) {
          const cleanUrl = absoluteUrl.split('#')[0]; // Remove hash
          if (!visited.has(cleanUrl) && !urlsToCrawl.includes(cleanUrl)) {
            urlsToCrawl.push(cleanUrl);
          }
        }
      }
    } catch (err) {
      // Ignore crawl failures on individual links
    }
  }

  return Array.from(visited);
}

// 2. DNS Subdomain Brute-Forcer
async function scanSubdomains(domain) {
  const commonSubdomains = [
    'admin', 'api', 'dev', 'test', 'staging', 'mail', 
    'vpn', 'shop', 'auth', 'portal', 'db', 'ftp', 
    'ssh', 'cpanel', 'webmail', 'secure', 'static'
  ];

  const results = [];
  const checks = commonSubdomains.map(async (sub) => {
    const fqdn = `${sub}.${domain}`;
    try {
      const addresses = await resolve4(fqdn);
      if (addresses && addresses.length > 0) {
        // Resolve open ports (80/443) on discovered subdomains
        const port80 = await checkPort(fqdn, 80, 800);
        const port443 = await checkPort(fqdn, 443, 800);

        results.push({
          subdomain: fqdn,
          ip: addresses[0],
          status: 'Active',
          ports: [
            { port: 80, name: 'HTTP', status: port80.status === 'open' ? 'Open' : 'Closed' },
            { port: 443, name: 'HTTPS', status: port443.status === 'open' ? 'Open' : 'Closed' }
          ]
        });
      }
    } catch (e) {
      // DNS resolve failed, subdomain is inactive
    }
  });

  await Promise.all(checks);
  return results;
}

// 3. Vulnerability auditing logic on single Page
async function auditPageVulnerabilities(pageUrl, hostname) {
  const findings = [];
  const cleanUrl = pageUrl.endsWith('/') ? pageUrl.slice(0, -1) : pageUrl;

  // A. SQL Injection (SQLi)
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);
    const res = await fetch(`${cleanUrl}/?id=1'`, {
      method: 'GET',
      signal: controller.signal,
      headers: { 'User-Agent': 'Mozilla/5.0 SecurityScanner/1.0' }
    });
    clearTimeout(timeoutId);
    
    const body = await res.text();
    const sqlErrors = [
      /you have an error in your sql syntax/i,
      /warning: mysql_/i,
      /PostgreSQL query failed:/i,
      /Microsoft OLE DB Provider for SQL Server/i,
      /Unclosed quotation mark after the character string/i,
      /sqlite3_prepare_v2/i,
      /SQLite3::SQLException/i
    ];

    if (sqlErrors.some(regex => regex.test(body))) {
      findings.push({
        name: 'SQL Injection (SQLi) Vulnerability',
        path: pageUrl,
        severity: 'Critical',
        desc: `A database syntax error was reflected when injecting a single quote at parameters on page: ${pageUrl}. Attackers can exploit this to leak database tables.`,
        fix: 'Use Parameterized Queries or Prepared Statements. Sanitize all URL query inputs.'
      });
    }
  } catch (e) {}

  // B. Reflected XSS
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);
    const testPayload = '<sentinel-xss-test>';
    const res = await fetch(`${cleanUrl}/?q=${encodeURIComponent(testPayload)}`, {
      method: 'GET',
      signal: controller.signal,
      headers: { 'User-Agent': 'Mozilla/5.0 SecurityScanner/1.0' }
    });
    clearTimeout(timeoutId);
    
    const body = await res.text();
    if (body.includes(testPayload)) {
      findings.push({
        name: 'Reflected Cross-Site Scripting (XSS)',
        path: pageUrl,
        severity: 'High',
        desc: `URL parameter inputs are reflected raw in the HTML body on page: ${pageUrl}. Attackers can hijack browser sessions.`,
        fix: 'Enforce HTML entity encoding (escape <, >, &) before writing values in the response body.'
      });
    }
  } catch (e) {}

  // C. Local File Inclusion (LFI)
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);
    const res = await fetch(`${cleanUrl}/../../../../etc/passwd`, {
      method: 'GET',
      signal: controller.signal,
      headers: { 'User-Agent': 'Mozilla/5.0 SecurityScanner/1.0' }
    });
    clearTimeout(timeoutId);
    
    const body = await res.text();
    if ((/root:x:0:0:/i.test(body) || /bin:x:1:1:/i.test(body)) && res.status === 200) {
      findings.push({
        name: 'Local File Inclusion (Path Traversal)',
        path: pageUrl,
        severity: 'Critical',
        desc: `Exposed system files (/etc/passwd) on folder navigation payload at: ${pageUrl}.`,
        fix: 'Implement strict path navigation parsing and run application in sandbox namespaces.'
      });
    }
  } catch (e) {}

  return findings;
}

// 4. Headers Scanner
async function scanHeaders(url) {
  const results = {
    score: 100,
    findings: [],
    headers: {}
  };

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 6000);

    const response = await fetch(url, {
      method: 'HEAD',
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityScanner/1.0'
      }
    });
    clearTimeout(timeoutId);

    const headers = {};
    response.headers.forEach((val, key) => {
      headers[key.toLowerCase()] = val;
    });
    results.headers = headers;

    const securityHeaders = [
      {
        name: 'content-security-policy',
        prettyName: 'Content-Security-Policy (CSP)',
        severity: 'High',
        deduction: 25,
        desc: 'Prevents Cross-Site Scripting (XSS) and data injection attacks by restricting resources the browser is allowed to load.',
        fix: 'Define a CSP header specifying trusted domains for scripts, styles, and other assets.',
        remediations: {
          nginx: 'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\';" always;',
          apache: 'Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\';"',
          iis: '<header name="Content-Security-Policy" value="default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\';" />'
        }
      },
      {
        name: 'strict-transport-security',
        prettyName: 'Strict-Transport-Security (HSTS)',
        severity: 'Medium',
        deduction: 15,
        desc: 'Forces the browser to only connect to the site using secure HTTPS connections.',
        fix: 'Add the Strict-Transport-Security header (e.g., max-age=63072000; includeSubDomains; preload).',
        remediations: {
          nginx: 'add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;',
          apache: 'Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"',
          iis: '<header name="Strict-Transport-Security" value="max-age=63072000; includeSubDomains; preload" />'
        }
      },
      {
        name: 'x-frame-options',
        prettyName: 'X-Frame-Options',
        severity: 'Medium',
        deduction: 15,
        desc: 'Protects visitors against Clickjacking attacks by preventing the site from being embedded in frames/iframes.',
        fix: 'Set X-Frame-Options to DENY or SAMEORIGIN, or configure frame-ancestors in CSP.',
        remediations: {
          nginx: 'add_header X-Frame-Options "SAMEORIGIN" always;',
          apache: 'Header always set X-Frame-Options "SAMEORIGIN"',
          iis: '<header name="X-Frame-Options" value="SAMEORIGIN" />'
        }
      },
      {
        name: 'x-content-type-options',
        prettyName: 'X-Content-Type-Options',
        severity: 'Low',
        deduction: 10,
        desc: 'Prevents the browser from MIME-sniffing a response away from the declared content-type.',
        fix: 'Set X-Content-Type-Options to nosniff.',
        remediations: {
          nginx: 'add_header X-Content-Type-Options "nosniff" always;',
          apache: 'Header always set X-Content-Type-Options "nosniff"',
          iis: '<header name="X-Content-Type-Options" value="nosniff" />'
        }
      },
      {
        name: 'referrer-policy',
        prettyName: 'Referrer-Policy',
        severity: 'Low',
        deduction: 5,
        desc: 'Controls how much referrer information is sent with requests.',
        fix: 'Set Referrer-Policy to no-referrer-when-downgrade or strict-origin-when-cross-origin.',
        remediations: {
          nginx: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
          apache: 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
          iis: '<header name="Referrer-Policy" value="strict-origin-when-cross-origin" />'
        }
      },
      {
        name: 'permissions-policy',
        prettyName: 'Permissions-Policy',
        severity: 'Low',
        deduction: 5,
        desc: 'Allows controlling which browser features (like camera, microphone, geolocation) are enabled or disabled.',
        fix: 'Implement Permissions-Policy header to restrict access to sensitive device APIs.',
        remediations: {
          nginx: 'add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;',
          apache: 'Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"',
          iis: '<header name="Permissions-Policy" value="geolocation=(), microphone=(), camera=()" />'
        }
      }
    ];

    securityHeaders.forEach(sh => {
      if (!headers[sh.name]) {
        results.findings.push({
          header: sh.prettyName,
          status: 'Missing',
          severity: sh.severity,
          desc: sh.desc,
          fix: sh.fix,
          remediations: sh.remediations
        });
        results.score -= sh.deduction;
      } else {
        results.findings.push({
          header: sh.prettyName,
          status: 'Present',
          severity: 'None',
          value: headers[sh.name]
        });
      }
    });

    const infoHeaders = ['server', 'x-powered-by', 'x-aspnet-version'];
    infoHeaders.forEach(ih => {
      if (headers[ih]) {
        results.findings.push({
          header: ih,
          status: 'Exposed',
          severity: 'Low',
          desc: `Server configuration information is exposed via the "${ih}" header: "${headers[ih]}".`,
          fix: 'Remove or mask the header in your web server configurations.'
        });
        results.score -= 5;
      }
    });

    results.score = Math.max(0, results.score);
  } catch (error) {
    results.error = `Could not analyze headers: ${error.message}`;
    results.score = 0;
  }
  return results;
}

// 5. SSL/TLS Certificate Validator
async function scanSSL(hostname) {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: hostname,
      port: 443,
      servername: hostname,
      rejectUnauthorized: false
    }, () => {
      const cert = socket.getPeerCertificate(true);
      const isAuthorized = socket.authorized;
      const protocol = socket.getProtocol();
      const cipher = socket.getCipher();

      socket.destroy();

      if (!cert || Object.keys(cert).length === 0) {
        resolve({
          valid: false,
          score: 0,
          error: 'No SSL certificate found.'
        });
        return;
      }

      const validFrom = new Date(cert.valid_from);
      const validTo = new Date(cert.valid_to);
      const now = new Date();
      const daysRemaining = Math.ceil((validTo - now) / (1000 * 60 * 60 * 24));

      let score = 100;
      const issues = [];

      if (now < validFrom || now > validTo) {
        score = 0;
        issues.push('Certificate is expired or not yet active.');
      } else if (daysRemaining < 30) {
        score -= 30;
        issues.push(`Certificate will expire soon in ${daysRemaining} days.`);
      }

      if (!isAuthorized) {
        score -= 40;
        issues.push(`Certificate is not trusted (Self-signed or invalid chain). Reason: ${socket.authorizationError}`);
      }

      if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
        score -= 25;
        issues.push(`Outdated protocol version detected: ${protocol}. Upgrade to TLS 1.2 or 1.3.`);
      }

      resolve({
        valid: true,
        score: Math.max(0, score),
        subject: cert.subject,
        issuer: cert.issuer,
        validFrom,
        validTo,
        daysRemaining,
        protocol,
        cipher,
        isAuthorized,
        issues
      });
    });

    socket.on('error', (err) => {
      resolve({
        valid: false,
        score: 0,
        error: `Connection failed: ${err.message}`
      });
    });

    socket.setTimeout(5000);
    socket.on('timeout', () => {
      socket.destroy();
      resolve({
        valid: false,
        score: 0,
        error: 'Connection timeout. Port 443 might be closed or blocked.'
      });
    });
  });
}

// 6. Exposed Files Scanner
async function scanExposedFiles(url) {
  const filesToCheck = [
    { path: '/.git/HEAD', name: 'Git Directory (.git/) Exposure', severity: 'Critical', desc: 'Allows attackers to download repository source code and config files.', fix: 'Block public access to .git folders in server configuration.' },
    { path: '/.env', name: 'Environment File (.env) Exposure', severity: 'Critical', desc: 'Exposes database passwords, API keys, and sensitive environment variables.', fix: 'Ensure .env files are kept outside the web root or block access.' },
    { path: '/wp-config.php.bak', name: 'WordPress Backup File Exposure', severity: 'High', desc: 'Contains database credentials and site configurations.', fix: 'Remove backup files from the production web root.' },
    { path: '/robots.txt', name: 'Robots.txt configuration', severity: 'Info', desc: 'Publicly details disallowed paths, which might help attackers map sensitive directories.', fix: 'Ensure robots.txt does not leak internal panel paths.' },
    { path: '/.well-known/security.txt', name: 'Security Contact File (security.txt)', severity: 'Info', desc: 'Standardized file for reporting security vulnerabilities.', fix: 'Consider adding a security.txt to help security researchers contact you.' }
  ];

  const results = {
    score: 100,
    findings: []
  };

  const cleanUrl = url.endsWith('/') ? url.slice(0, -1) : url;

  const checks = filesToCheck.map(async (file) => {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 4000);

      const res = await fetch(`${cleanUrl}${file.path}`, {
        method: 'GET',
        signal: controller.signal,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityScanner/1.0'
        }
      });
      clearTimeout(timeoutId);

      if (res.status === 200) {
        const text = await res.text();
        const isHtml = text.trim().toLowerCase().startsWith('<!doctype html') || text.trim().toLowerCase().startsWith('<html');

        if (file.path.endsWith('.txt') || file.path.endsWith('security.txt')) {
          results.findings.push({
            name: file.name,
            path: file.path,
            status: 'Found',
            severity: 'Info',
            desc: `Found at ${file.path}.`
          });
        } else if (!isHtml) {
          results.findings.push({
            name: file.name,
            path: file.path,
            status: 'Exposed',
            severity: file.severity,
            desc: file.desc,
            fix: file.fix
          });
          results.score -= (file.severity === 'Critical' ? 40 : 25);
        }
      }
    } catch (e) {
      // Ignore
    }
  });

  await Promise.all(checks);
  results.score = Math.max(0, results.score);
  return results;
}

// 7. Exposed API Directories, Swagger, Open Redirect, and Web Vulnerability checks
async function scanAdvancedHacking(crawledUrls, cleanUrl, hostname) {
  const results = {
    score: 100,
    findings: []
  };

  // Perform active SQLi/XSS/LFI audits on up to 5 crawled URLs
  const auditPromises = crawledUrls.slice(0, 5).map(async (page) => {
    const pageFindings = await auditPageVulnerabilities(page, hostname);
    pageFindings.forEach(f => {
      results.findings.push(f);
      results.score -= (f.severity === 'Critical' ? 30 : 20);
    });
  });

  await Promise.all(auditPromises);

  // Perform domain-level active scanning
  await Promise.all([
    // A. CORS Check
    (async () => {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 4000);
        const res = await fetch(cleanUrl, {
          method: 'GET',
          signal: controller.signal,
          headers: {
            'Origin': 'http://evil-attacker.com',
            'User-Agent': 'Mozilla/5.0 SecurityScanner/1.0'
          }
        });
        clearTimeout(timeoutId);

        const allowOrigin = res.headers.get('access-control-allow-origin');
        const allowCredentials = res.headers.get('access-control-allow-credentials');

        if (allowOrigin === 'http://evil-attacker.com' && allowCredentials === 'true') {
          results.findings.push({
            name: 'CORS Origin Reflection',
            path: cleanUrl,
            severity: 'High',
            desc: 'The server reflects untrusted Origins in Access-Control-Allow-Origin while setting credentials to true. Credential hijacking possible.',
            fix: 'Maintain a strict whitelist of trusted Origins.'
          });
          results.score -= 25;
        } else if (allowOrigin === '*') {
          results.findings.push({
            name: 'Permissive CORS Policies',
            path: cleanUrl,
            severity: 'Low',
            desc: 'Wildcard CORS allowed. While safe for public assets, restricted endpoints should scopes origins.',
            fix: 'Set explicit domains in the CORS configs.'
          });
          results.score -= 10;
        }
      } catch (e) {}
    })(),

    // B. .git/config leak
    (async () => {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 4000);
        const res = await fetch(`${cleanUrl}/.git/config`, {
          method: 'GET',
          signal: controller.signal,
          headers: { 'User-Agent': 'Mozilla/5.0 SecurityScanner/1.0' }
        });
        clearTimeout(timeoutId);
        const text = await res.text();
        if (res.status === 200 && (text.includes('[core]') || text.includes('repositoryformatversion'))) {
          results.findings.push({
            name: '.git/config Repository Leak',
            path: `${cleanUrl}/.git/config`,
            severity: 'Critical',
            desc: 'The internal git config folder is readable publicly, leaking developer repository keys and tokens.',
            fix: 'Configure server directory policies to deny access to hidden folders (e.g. .*).'
          });
          results.score -= 40;
        }
      } catch (e) {}
    })(),

    // C. WP user enumeration
    (async () => {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 4000);
        const res = await fetch(`${cleanUrl}/wp-json/wp/v2/users`, {
          method: 'GET',
          signal: controller.signal,
          headers: { 'User-Agent': 'Mozilla/5.0 SecurityScanner/1.0' }
        });
        clearTimeout(timeoutId);
        if (res.status === 200) {
          const data = await res.json();
          if (Array.isArray(data) && data.length > 0 && data[0].slug) {
            const usernames = data.map(u => u.slug).join(', ');
            results.findings.push({
              name: 'WordPress User Enumeration',
              path: `${cleanUrl}/wp-json/wp/v2/users`,
              severity: 'High',
              desc: `WordPress users API is exposed. Attackers can harvest usernames. Discovered logins: [${usernames}]`,
              fix: 'Disable WP-JSON REST users path.'
            });
            results.score -= 25;
          }
        }
      } catch (e) {}
    })(),

    // D. Exposed Swagger Docs
    (async () => {
      const paths = ['/swagger-ui.html', '/api-docs', '/swagger/v1/swagger.json', '/v2/api-docs'];
      let foundPath = null;
      for (const p of paths) {
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 2000);
          const res = await fetch(`${cleanUrl}${p}`, {
            method: 'GET',
            signal: controller.signal,
            headers: { 'User-Agent': 'Mozilla/5.0 SecurityScanner/1.0' }
          });
          clearTimeout(timeoutId);
          if (res.status === 200) {
            const text = await res.text();
            if (text.includes('swagger') || text.includes('openapi') || text.includes('Swagger')) {
              foundPath = p;
              break;
            }
          }
        } catch (e) {}
      }
      if (foundPath) {
        results.findings.push({
          name: 'Exposed API Documentation (Swagger)',
          path: `${cleanUrl}${foundPath}`,
          severity: 'Medium',
          desc: `Exposed API schema configuration layout found at: ${foundPath}.`,
          fix: 'Do not build and expose Swagger UIs on production releases.'
        });
        results.score -= 20;
      }
    })(),

    // E. Open Redirect
    (async () => {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 4000);
        const res = await fetch(`${cleanUrl}/?redirect=https://google.com`, {
          method: 'GET',
          redirect: 'manual',
          signal: controller.signal,
          headers: { 'User-Agent': 'Mozilla/5.0 SecurityScanner/1.0' }
        });
        clearTimeout(timeoutId);
        const location = res.headers.get('location');
        if ((res.status >= 300 && res.status < 400) && location && location.includes('google.com')) {
          results.findings.push({
            name: 'Open Redirect Vulnerability',
            path: cleanUrl,
            severity: 'High',
            desc: 'The server redirected arbitrary parameters straight to an injected external URL. Used in phishing campaigns.',
            fix: 'Enforce domain parameter validation on redirect redirects.'
          });
          results.score -= 30;
        }
      } catch (e) {}
    })(),

    // F. Verb Tampering PUT
    (async () => {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 3000);
        const res = await fetch(`${cleanUrl}/sentinel_test_file.txt`, {
          method: 'PUT',
          body: 'Sentinel security check',
          signal: controller.signal,
          headers: { 'User-Agent': 'Mozilla/5.0 SecurityScanner/1.0' }
        });
        clearTimeout(timeoutId);
        if (res.status === 200 || res.status === 201 || res.status === 204) {
          results.findings.push({
            name: 'Arbitrary File Upload (HTTP PUT Enabled)',
            path: `${cleanUrl}/sentinel_test_file.txt`,
            severity: 'Critical',
            desc: 'HTTP PUT method is enabled on root web folders accepting uploads. Attackers can upload code files.',
            fix: 'Restrict HTTP allowed methods to strictly GET/POST/OPTIONS.'
          });
          results.score -= 40;
        }
      } catch (e) {}
    })(),

    // G. Backups fuzzing
    (async () => {
      const backupFiles = ['/backup.sql', '/db.sql', '/database.sql', '/dump.sql', '/backup.zip'];
      let foundBackup = null;
      for (const file of backupFiles) {
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 2000);
          const res = await fetch(`${cleanUrl}${file}`, {
            method: 'GET',
            signal: controller.signal,
            headers: { 'User-Agent': 'Mozilla/5.0 SecurityScanner/1.0' }
          });
          clearTimeout(timeoutId);
          if (res.status === 200) {
            const text = await res.text();
            const isHtml = text.trim().toLowerCase().startsWith('<!doctype html') || text.trim().toLowerCase().startsWith('<html');
            if (!isHtml) {
              foundBackup = file;
              break;
            }
          }
        } catch (e) {}
      }
      if (foundBackup) {
        results.findings.push({
          name: 'Database Backup Exposure',
          path: `${cleanUrl}${foundBackup}`,
          severity: 'Critical',
          desc: `Exposed SQL database backup found at path: ${foundBackup}. Exposes full tables schemas.`,
          fix: 'Delete backup files from public root folder directories.'
        });
        results.score -= 40;
      }
    })(),

    // H. CMS CVE
    (async () => {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 4000);
        const res = await fetch(cleanUrl, {
          method: 'GET',
          signal: controller.signal,
          headers: { 'User-Agent': 'Mozilla/5.0 SecurityScanner/1.0' }
        });
        clearTimeout(timeoutId);
        
        const body = await res.text();
        const wpRegex = /wp-content|wp-includes|name="generator" content="WordPress/i;
        if (wpRegex.test(body)) {
          const verMatch = body.match(/name="generator" content="WordPress\s+([0-9\.]+)/i) || 
                           body.match(/wp-includes\/js\/wp-embed\.min\.js\?ver=([0-9\.]+)/i);
          const version = verMatch ? verMatch[1] : 'Unknown';

          if (version !== 'Unknown' && parseFloat(version) < 6.2) {
            results.findings.push({
              name: `Vulnerable WordPress CMS Detected (${version})`,
              path: cleanUrl,
              severity: 'High',
              desc: `WordPress version ${version} detected. This version is outdated and contains known vulnerabilities: [CVE-2022-21661 (SQLi in WP_Query), CVE-2022-21662 (XSS), CVE-2022-21664 (XML-RPC SSRF)].`,
              fix: 'Upgrade WordPress CMS.'
            });
            results.score -= 25;
          }
        }
      } catch (e) {}
    })()
  ]);

  results.score = Math.max(0, results.score);
  return results;
}

// DNS Configuration Check
async function scanDNS(hostname) {
  const results = {
    score: 100,
    spf: { present: false, value: '', issues: [] },
    dmarc: { present: false, value: '', issues: [] },
    mx: { present: false, records: [] }
  };

  try {
    const mxRecords = await resolveMx(hostname);
    if (mxRecords && mxRecords.length > 0) {
      results.mx.present = true;
      results.mx.records = mxRecords;
    } else {
      results.score -= 10;
    }
  } catch (err) {
    results.score -= 10;
  }

  try {
    const txtRecords = await resolveTxt(hostname);
    const flatTxt = txtRecords.flat();
    const spfRecord = flatTxt.find(rec => rec.toLowerCase().startsWith('v=spf1'));

    if (spfRecord) {
      results.spf.present = true;
      results.spf.value = spfRecord;
      if (spfRecord.includes('?all')) {
        results.spf.issues.push('SPF record uses weak policy (?all). Consider switching to softfail (~all) or fail (-all).');
        results.score -= 10;
      }
    } else {
      results.spf.issues.push('No SPF record found. Spammers can easily spoof emails from your domain.');
      results.score -= 25;
    }
  } catch (err) {
    results.spf.issues.push('No SPF record found or DNS query failed.');
    results.score -= 25;
  }

  try {
    const dmarcRecords = await resolveTxt(`_dmarc.${hostname}`);
    const flatDmarc = dmarcRecords.flat();
    const dmarcRecord = flatDmarc.find(rec => rec.toUpperCase().startsWith('v=DMARC1'));

    if (dmarcRecord) {
      results.dmarc.present = true;
      results.dmarc.value = dmarcRecord;

      if (dmarcRecord.includes('p=none')) {
        results.dmarc.issues.push('DMARC policy is set to "none". Email spoofing reports are logged but not blocked.');
        results.score -= 10;
      }
    } else {
      results.dmarc.issues.push('No DMARC record found. Vulnerable to email spoofing/phishing impersonation.');
      results.score -= 25;
    }
  } catch (err) {
    results.dmarc.issues.push('No DMARC record found or DNS query failed.');
    results.score -= 25;
  }

  results.score = Math.max(0, results.score);
  return results;
}

// 8. TCP Port Checker
function checkPort(host, port, timeout = 1500) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let status = 'closed';
    socket.setTimeout(timeout);
    socket.connect(port, host, () => {
      status = 'open';
      socket.destroy();
    });
    socket.on('error', () => {
      status = 'closed';
      socket.destroy();
    });
    socket.on('timeout', () => {
      status = 'filtered';
      socket.destroy();
    });
    socket.on('close', () => {
      resolve({ port, status });
    });
  });
}

async function scanPorts(hostname) {
  const portsToScan = [
    { port: 21, name: 'FTP', risk: 'High', desc: 'File Transfer Protocol. Often transmits credentials in plain text. Vulnerable to interception.' },
    { port: 22, name: 'SSH', risk: 'Medium', desc: 'Secure Shell for remote access. Safe if key-based, but vulnerable to password brute-force if misconfigured.' },
    { port: 23, name: 'Telnet', risk: 'Critical', desc: 'Unencrypted remote shell. Credentials and data sent in plain text. Should never be publicly open.' },
    { port: 80, name: 'HTTP', risk: 'Info', desc: 'Plain web server access. Should redirect visitors to HTTPS.' },
    { port: 443, name: 'HTTPS', risk: 'None', desc: 'Encrypted web traffic. Standard secure port.' },
    { port: 8080, name: 'HTTP Alt', risk: 'Low', desc: 'Alternative port often used for test panels, dev frameworks, or proxy servers.' }
  ];

  const results = {
    score: 100,
    findings: []
  };

  try {
    const checks = portsToScan.map(async (p) => {
      const result = await checkPort(hostname, p.port);
      if (result.status === 'open') {
        results.findings.push({
          port: p.port,
          name: p.name,
          status: 'Open',
          risk: p.risk,
          desc: p.desc
        });
        if (p.risk === 'Critical') results.score -= 40;
        else if (p.risk === 'High') results.score -= 25;
        else if (p.risk === 'Medium') results.score -= 15;
        else if (p.risk === 'Low') results.score -= 5;
      } else {
        results.findings.push({
          port: p.port,
          name: p.name,
          status: 'Closed/Blocked',
          risk: 'None',
          desc: `${p.name} is not exposed publicly.`
        });
      }
    });

    await Promise.all(checks);
  } catch (err) {
    // Ignore
  }

  results.score = Math.max(0, results.score);
  return results;
}

// 9. Domain Host Geolocation and IP Resolver
async function scanServerInfo(hostname) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);
    const res = await fetch(`http://ip-api.com/json/${hostname}`, {
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    const data = await res.json();
    if (data.status === 'success') {
      return {
        ip: data.query,
        country: data.country,
        countryCode: data.countryCode,
        city: data.city,
        isp: data.isp,
        org: data.org
      };
    }
  } catch (e) {
    // Ignore
  }
  return {
    ip: 'Unknown',
    country: 'Unknown',
    countryCode: '',
    city: 'Unknown',
    isp: 'Unknown',
    org: 'Unknown'
  };
}

// Main Scan API Route
app.post('/api/scan', async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'URL parameter is required' });
  }

  try {
    const target = parseTarget(url);
    const cleanUrl = target.url.endsWith('/') ? target.url.slice(0, -1) : target.url;

    // 1. Run HTML Crawler/Spider first
    const crawledUrls = await crawlLinks(target.url, target.hostname);

    // 2. Run parallel audits (including subdomains and subpages hacking scan)
    const [headers, ssl, files, dnsResult, hacking, ports, subdomains, serverInfo] = await Promise.all([
      scanHeaders(target.url),
      scanSSL(target.hostname),
      scanExposedFiles(target.url),
      scanDNS(target.hostname),
      scanAdvancedHacking(crawledUrls, cleanUrl, target.hostname),
      scanPorts(target.hostname),
      scanSubdomains(target.hostname),
      scanServerInfo(target.hostname)
    ]);

    // Calculate Overall Security Grade incorporating active hacking, crawler and subdomains
    const totalScore = Math.round((headers.score + ssl.score + files.score + dnsResult.score + hacking.score + ports.score) / 6);
    let grade = 'F';
    if (totalScore >= 90) grade = 'A';
    else if (totalScore >= 80) grade = 'B';
    else if (totalScore >= 70) grade = 'C';
    else if (totalScore >= 50) grade = 'D';

    res.json({
      target,
      scanTime: new Date().toISOString(),
      overallScore: totalScore,
      grade,
      crawledUrlsCount: crawledUrls.length,
      sections: {
        headers,
        ssl,
        files,
        dns: dnsResult,
        hacking,
        ports,
        subdomains
      },
      serverInfo
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || 'An error occurred during scan' });
  }
});

// 10. Nuclei-style custom exploit runner
app.post('/api/exploit', async (req, res) => {
  const { target, method, path, headers, body, matchType, matchValue } = req.body;

  if (!target) {
    return res.status(400).json({ error: 'Target URL is required' });
  }

  try {
    const targetInfo = parseTarget(target);
    const cleanUrl = targetInfo.url.endsWith('/') ? targetInfo.url.slice(0, -1) : targetInfo.url;
    const finalUrl = `${cleanUrl}${path || ''}`;

    const requestHeaders = {
      'User-Agent': 'Mozilla/5.0 ExploitRunner/1.0'
    };

    if (headers) {
      headers.forEach(h => {
        if (h.key && h.value) {
          requestHeaders[h.key] = h.value;
        }
      });
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(finalUrl, {
      method: method || 'GET',
      headers: requestHeaders,
      body: method !== 'GET' && method !== 'HEAD' ? body : undefined,
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    const responseText = await response.text();
    const responseHeaders = [];
    response.headers.forEach((val, key) => {
      responseHeaders.push({ key, value: val });
    });

    // Run exploit validation match logic
    let matched = false;
    if (matchType === 'status') {
      matched = response.status === Number(matchValue);
    } else if (matchType === 'body') {
      matched = responseText.includes(matchValue);
    } else if (matchType === 'regex') {
      try {
        const regex = new RegExp(matchValue, 'i');
        matched = regex.test(responseText);
      } catch (e) {
        matched = false;
      }
    }

    res.json({
      url: finalUrl,
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
      matched,
      bodyLength: responseText.length,
      bodyExcerpt: responseText.slice(0, 1000) // Truncate response body preview
    });

  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to execute request' });
  }
});

app.listen(PORT, () => {
  console.log(`Security Scanner API running on http://localhost:${PORT}`);
});

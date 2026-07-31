import express from 'express';
import cors from 'cors';
import tls from 'tls';
import dns from 'dns';
import net from 'net';
import { promisify } from 'util';

const resolveTxt = promisify(dns.resolveTxt);
const resolveMx = promisify(dns.resolveMx);

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

// 1. Headers Scanner with code remediation snippets
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

// 2. SSL/TLS Certificate Validator
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

// 3. Exposed Files Scanner
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

// 4. DNS Configuration Check
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

// 5. Active Hacking Vulnerabilities Scanner
async function scanHacking(url, hostname) {
  const results = {
    score: 100,
    findings: []
  };

  const cleanUrl = url.endsWith('/') ? url.slice(0, -1) : url;

  await Promise.all([
    // A. SQL Injection (SQLi) Probe
    (async () => {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 4000);
        const testUrl = `${cleanUrl}/?id=1'`;
        const res = await fetch(testUrl, {
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
          /SQLite3::SQLException/i,
          /ORA-01756: quoted string not properly terminated/i
        ];

        const isVulnerable = sqlErrors.some(regex => regex.test(body));
        
        if (isVulnerable) {
          results.findings.push({
            name: 'SQL Injection (SQLi) Vulnerability',
            status: 'Vulnerable',
            severity: 'Critical',
            desc: 'The application returned database-specific error logs when injected with a single quote. This indicates raw input is parsed directly into database queries.',
            fix: 'Implement Prepared Statements (Parameterized Queries) or ORMs instead of direct SQL concatenation.'
          });
          results.score -= 40;
        } else {
          results.findings.push({
            name: 'SQL Injection Protection',
            status: 'Secure',
            severity: 'None',
            desc: 'Database queries did not reflect syntax errors when input fields were injected.'
          });
        }
      } catch (e) {
        results.findings.push({
          name: 'SQL Injection Protection',
          status: 'Secure',
          severity: 'None',
          desc: 'Database queries did not reflect syntax errors.'
        });
      }
    })(),

    // B. Reflected Cross-Site Scripting (XSS) Probe
    (async () => {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 4000);
        const testPayload = '<sentinel-xss-test>';
        const testUrl = `${cleanUrl}/?q=${encodeURIComponent(testPayload)}`;
        const res = await fetch(testUrl, {
          method: 'GET',
          signal: controller.signal,
          headers: { 'User-Agent': 'Mozilla/5.0 SecurityScanner/1.0' }
        });
        clearTimeout(timeoutId);
        
        const body = await res.text();
        const isReflected = body.includes(testPayload);

        if (isReflected) {
          results.findings.push({
            name: 'Reflected Cross-Site Scripting (XSS)',
            status: 'Vulnerable',
            severity: 'High',
            desc: 'User inputs are reflected directly back in the HTML response without HTML-encoding. Attackers can execute arbitrary JavaScript in the victim\'s browser.',
            fix: 'Escape all user inputs before displaying them (convert < to &lt;, > to &gt;, etc.) or use modern UI frameworks that handle sanitization automatically.'
          });
          results.score -= 30;
        } else {
          results.findings.push({
            name: 'Reflected XSS Protection',
            status: 'Secure',
            severity: 'None',
            desc: 'Inputs injected via query parameters are correctly sanitized or not reflected.'
          });
        }
      } catch (e) {
        results.findings.push({
          name: 'Reflected XSS Protection',
          status: 'Secure',
          severity: 'None',
          desc: 'Inputs are correctly sanitized.'
        });
      }
    })(),

    // C. Directory Traversal / Path Traversal Probe
    (async () => {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 4000);
        const testUrl = `${cleanUrl}/../../../../etc/passwd`;
        const res = await fetch(testUrl, {
          method: 'GET',
          signal: controller.signal,
          headers: { 'User-Agent': 'Mozilla/5.0 SecurityScanner/1.0' }
        });
        clearTimeout(timeoutId);
        
        const body = await res.text();
        const hasEtcPasswd = /root:x:0:0:/i.test(body) || /bin:x:1:1:/i.test(body);

        if (hasEtcPasswd && res.status === 200) {
          results.findings.push({
            name: 'Directory Traversal (Local File Inclusion)',
            status: 'Vulnerable',
            severity: 'Critical',
            desc: 'The server returned system files (/etc/passwd) when queried with path traversal sequences. Attackers can read sensitive server files.',
            fix: 'Sanitize file paths, block directory traversal dot-dot-slash patterns (../) and run the application with minimal privileges.'
          });
          results.score -= 40;
        } else {
          results.findings.push({
            name: 'Path Traversal Protection',
            status: 'Secure',
            severity: 'None',
            desc: 'Local configuration and system files are not exposed to directory traversal queries.'
          });
        }
      } catch (e) {
        results.findings.push({
          name: 'Path Traversal Protection',
          status: 'Secure',
          severity: 'None',
          desc: 'Local configuration and system files are protected.'
        });
      }
    })(),

    // D. CORS Misconfiguration Probe
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
            name: 'CORS Origin Reflection Vulnerability',
            status: 'Vulnerable',
            severity: 'High',
            desc: 'The server reflects untrusted Origins back in Access-Control-Allow-Origin while setting credentials to true. Any malicious site can make authenticated API requests on behalf of your users.',
            fix: 'Avoid dynamic reflection of origins. Maintain a strict whitelist of trusted subdomains.'
          });
          results.score -= 25;
        } else if (allowOrigin === '*') {
          results.findings.push({
            name: 'Permissive CORS Access',
            status: 'Weak',
            severity: 'Low',
            desc: 'The API is configured with Access-Control-Allow-Origin: *. While safe for public assets, it should be restricted for authenticated/private endpoints.',
            fix: 'Set specific client domains in CORS policies instead of using wildcard *.'
          });
          results.score -= 10;
        } else {
          results.findings.push({
            name: 'CORS Access Policies',
            status: 'Secure',
            severity: 'None',
            desc: 'Cross-Origin policies are properly scoped and do not reflect wildcard attackers.'
          });
        }
      } catch (e) {
        results.findings.push({
          name: 'CORS Access Policies',
          status: 'Secure',
          severity: 'None',
          desc: 'Cross-Origin policies are secure.'
        });
      }
    })(),

    // E. Cookie Security Configuration Probe
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

        const cookies = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
        if (cookies.length > 0) {
          const insecureCookies = [];
          cookies.forEach(cookie => {
            const parts = cookie.split(';').map(p => p.trim().toLowerCase());
            const hasHttpOnly = parts.includes('httponly');
            const hasSecure = parts.includes('secure');
            const name = cookie.split('=')[0];

            if (!hasHttpOnly || !hasSecure) {
              insecureCookies.push({
                name,
                missingHttpOnly: !hasHttpOnly,
                missingSecure: !hasSecure
              });
            }
          });

          if (insecureCookies.length > 0) {
            const desc = insecureCookies.map(c => 
              `Cookie "${c.name}" is missing: ${c.missingHttpOnly ? 'HttpOnly' : ''}${c.missingHttpOnly && c.missingSecure ? ' and ' : ''}${c.missingSecure ? 'Secure' : ''} flags.`
            ).join(' ');

            results.findings.push({
              name: 'Insecure Cookie Attributes',
              status: 'Weak',
              severity: 'Medium',
              desc: `Cookies are exposed to client-side scripts or sent over plain HTTP. Details: ${desc}`,
              fix: 'Add the "HttpOnly" flag to prevent XSS script access and the "Secure" flag to enforce TLS/HTTPS transmission.'
            });
            results.score -= 20;
          } else {
            results.findings.push({
              name: 'Secure Cookie Flags',
              status: 'Secure',
              severity: 'None',
              desc: 'All session and user cookies are configured with HttpOnly and Secure flags.'
            });
          }
        }
      } catch (e) {
        // Ignore
      }
    })()
  ]);

  results.score = Math.max(0, results.score);
  return results;
}

// 6. TCP Port Checker
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

// 7. Domain Host Geolocation and IP Resolver
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
    // Ignore and fallback
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

// Main API Route
app.post('/api/scan', async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'URL parameter is required' });
  }

  try {
    const target = parseTarget(url);

    // Run all scans concurrently
    const [headers, ssl, files, dnsResult, hacking, ports, serverInfo] = await Promise.all([
      scanHeaders(target.url),
      scanSSL(target.hostname),
      scanExposedFiles(target.url),
      scanDNS(target.hostname),
      scanHacking(target.url, target.hostname),
      scanPorts(target.hostname),
      scanServerInfo(target.hostname)
    ]);

    // Calculate Overall Security Grade incorporating active hacking and port tests
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
      sections: {
        headers,
        ssl,
        files,
        dns: dnsResult,
        hacking,
        ports
      },
      serverInfo
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || 'An error occurred during scan' });
  }
});

app.listen(PORT, () => {
  console.log(`Security Scanner API running on http://localhost:${PORT}`);
});

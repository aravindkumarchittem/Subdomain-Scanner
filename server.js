const express = require('express');
const cors = require('cors');
const dns = require('dns').promises;
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const app = express();

const SECURITYTRAILS_API_KEY = 'F6WJRqWtxnY4SSmgX95cGA3cNUW6FvYZ';

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// Known vulnerable CNAME patterns for subdomain takeover
const takeoverPatterns = [
  /github\.io\.?$/,
  /herokuapp\.com\.?$/,
  /amazonaws\.com\.?$/,
  /azurewebsites\.net\.?$/,
  /myshopify\.com\.?$/,
  /wordpress\.com\.?$/,
  /bitbucket\.io\.?$/,
  /\.cloudfront\.net\.?$/,
  /\.s3-website[.-].*\.amazonaws\.com\.?$/,
  /\.firebaseapp\.com\.?$/,
  /\.netlify\.app\.?$/,
  /\.ghost\.io\.?$/,
  /\.readthedocs\.io\.?$/,
  /\.surge\.sh\.?$/,
  /\.pantheonsite\.io\.?$/
];

function isVulnerableCNAME(cname) {
  return takeoverPatterns.some(pattern => pattern.test(cname));
}

async function getDNSRecords(subdomain) {
  const result = {
    ips: [],
    cname: null,
    mx: [],
    txt: [],
    ns: [],
    exists: false,
    dnsError: null
  };

  try {
    const [
      aRecords, 
      aaaaRecords, 
      cnameRecords,
      mxRecords,
      txtRecords,
      nsRecords
    ] = await Promise.allSettled([
      dns.resolve4(subdomain),
      dns.resolve6(subdomain),
      dns.resolveCname(subdomain),
      dns.resolveMx(subdomain),
      dns.resolveTxt(subdomain),
      dns.resolveNs(subdomain)
    ]);

    if (aRecords.status === 'fulfilled') {
      result.ips = result.ips.concat(aRecords.value);
      result.exists = true;
    }
    if (aaaaRecords.status === 'fulfilled') {
      result.ips = result.ips.concat(aaaaRecords.value);
      result.exists = true;
    }
    if (cnameRecords.status === 'fulfilled' && cnameRecords.value.length > 0) {
      result.cname = cnameRecords.value[0];
      result.exists = true;
    }
    if (mxRecords.status === 'fulfilled') {
      result.mx = mxRecords.value.map(mx => mx.exchange);
      result.exists = true;
    }
    if (txtRecords.status === 'fulfilled') {
      result.txt = txtRecords.value.flat();
      result.exists = true;
    }
    if (nsRecords.status === 'fulfilled') {
      result.ns = nsRecords.value;
      result.exists = true;
    }

    if (!result.exists) {
      result.dnsError = 'NXDOMAIN';
    }
  } catch (err) {
    result.dnsError = err.code || 'UNKNOWN_ERROR';
  }

  return result;
}

async function checkHttpStatus(subdomain) {
  try {
    let resp = await fetch(`https://${subdomain}`, { 
      method: 'GET', 
      timeout: 5000,
      redirect: 'manual',
      headers: { 'User-Agent': 'Mozilla/5.0 (Subdomain Scanner)' }
    });
    
    if (!resp.ok && resp.status !== 301 && resp.status !== 302) {
      resp = await fetch(`http://${subdomain}`, { 
        method: 'GET', 
        timeout: 5000,
        redirect: 'manual'
      });
    }

    return {
      status: resp.ok ? 'active' : 'inactive',
      statusCode: resp.status,
      redirectUrl: [301, 302].includes(resp.status) ? resp.headers.get('location') : null
    };
  } catch (e) {
    return {
      status: 'inactive',
      statusCode: null,
      redirectUrl: null,
      error: e.message
    };
  }
}

app.post('/scan', async (req, res) => {
  const { domain } = req.body;

  if (!domain) {
    return res.status(400).json({ error: 'Please provide a domain.' });
  }

  try {
    // Get subdomains from SecurityTrails API
    const stRes = await fetch(`https://api.securitytrails.com/v1/domain/${domain}/subdomains`, {
      headers: { 'APIKEY': SECURITYTRAILS_API_KEY }
    });

    if (!stRes.ok) {
      const msg = await stRes.text();
      console.error(`❌ SecurityTrails API Error: ${stRes.status} - ${msg}`);
      return res.status(stRes.status).json({ error: `SecurityTrails API error (${stRes.status})` });
    }

    const stData = await stRes.json();

    if (!stData.subdomains || stData.subdomains.length === 0) {
      return res.json({ error: 'No subdomains found or invalid domain.' });
    }

    const subdomains = stData.subdomains.map(sub => `${sub}.${domain}`);

    // Batch process to avoid rate limits
    const batchSize = 5;
    const results = [];

    for (let i = 0; i < subdomains.length; i += batchSize) {
      const batch = subdomains.slice(i, i + batchSize);

      const batchResults = await Promise.all(batch.map(async (sub) => {
        // DNS records and HTTP status together
        const [dnsRecords, httpStatus] = await Promise.all([
          getDNSRecords(sub),
          checkHttpStatus(sub)
        ]);

        return {
          domain: sub,
          status: httpStatus.status,
          statusCode: httpStatus.statusCode,
          redirectUrl: httpStatus.redirectUrl,
          ips: dnsRecords.ips.length ? dnsRecords.ips : null,
          cname: dnsRecords.cname,
          mx: dnsRecords.mx.length ? dnsRecords.mx : null,
          txt: dnsRecords.txt.length ? dnsRecords.txt : null,
          ns: dnsRecords.ns.length ? dnsRecords.ns : null,
          vulnerable: dnsRecords.cname ? isVulnerableCNAME(dnsRecords.cname) : false,
          dnsError: dnsRecords.dnsError,
          httpError: httpStatus.error
        };
      }));

      results.push(...batchResults);

      // Small delay for rate limiting
      await new Promise(resolve => setTimeout(resolve, 1000));
    }

    res.json({
      domain,
      subdomains: results,
      stats: {
        total: results.length,
        active: results.filter(s => s.status === 'active').length,
        vulnerable: results.filter(s => s.vulnerable).length,
        withRedirects: results.filter(s => s.redirectUrl).length
      }
    });
  } catch (err) {
    console.error("❌ Unexpected Error:", err);
    res.status(500).json({
      error: 'An unexpected error occurred during scanning.',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('⚠️ Server Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));

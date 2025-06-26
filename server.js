const express = require('express');
const cors = require('cors');
const dns = require('dns').promises;
const path = require('path');
require('dotenv').config();

const fetch = (...args) =>
  import('node-fetch').then(({ default: fetch }) => fetch(...args));

const app = express();
const PORT = process.env.PORT || 3000;

const SECURITYTRAILS_API_KEY = process.env.SECURITYTRAILS_API_KEY;

const takeoverPatterns = [
  /github\.io\.?$/,
  /herokuapp\.com\.?$/,
  /amazonaws\.com\.?$/,
  /azurewebsites\.net\.?$/,
  /myshopify\.com\.?$/,
  /wordpress\.com\.?$/,
  /bitbucket\.io\.?$/
];

// Middleware
app.use(cors());
app.use(express.json());

// Serve static files (index.html, CSS, etc.)
app.use(express.static(path.join(__dirname)));

// Serve homepage
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Scanner endpoint
app.post('/scan', async (req, res) => {
  const { domain } = req.body;

  if (!domain) {
    return res.status(400).json({ error: 'Please provide a domain.' });
  }

  try {
    const stRes = await fetch(
      `https://api.securitytrails.com/v1/domain/${domain}/subdomains`,
      {
        headers: { APIKEY: SECURITYTRAILS_API_KEY }
      }
    );

    if (!stRes.ok) {
      const msg = await stRes.text();
      return res.status(stRes.status).json({ error: `SecurityTrails API error: ${msg}` });
    }

    const stData = await stRes.json();

    if (!stData.subdomains || stData.subdomains.length === 0) {
      return res.json({ error: 'No subdomains found or invalid domain.' });
    }

    const subdomains = stData.subdomains.map(sub => `${sub}.${domain}`);

    const checked = await Promise.all(
      subdomains.map(async sub => {
        let status = 'inactive';
        try {
          let resp = await fetch(`https://${sub}`, { method: 'GET' });
          if (!resp.ok) {
            resp = await fetch(`http://${sub}`, { method: 'GET' });
          }
          status = resp.ok ? 'active' : 'inactive';
        } catch (_) {
          status = 'inactive';
        }

        let cname = null;
        let vulnerable = false;
        try {
          const cnames = await dns.resolveCname(sub);
          if (cnames.length > 0) {
            cname = cnames[0];
            vulnerable = takeoverPatterns.some(pattern => pattern.test(cname));
          }
        } catch (_) {}

        return {
          domain: sub,
          status,
          cname,
          vulnerable
        };
      })
    );

    res.json({ subdomains: checked });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Unexpected error occurred during scanning.' });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`🚀 Server running on PORT ${PORT}`);
});

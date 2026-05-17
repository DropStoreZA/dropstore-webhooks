const express = require('express');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.SHOPIFY_WEBHOOK_SECRET || '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';

app.use(express.raw({ type: 'application/json' }));

function verifyHmac(req, res, next) {
  const hmacHeader = req.headers['x-shopify-hmac-sha256'];
  if (!hmacHeader) return res.status(401).json({ error: 'Missing HMAC header' });
  const digest = crypto.createHmac('sha256', SECRET).update(req.body).digest('base64');
  const valid = crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmacHeader));
  if (!valid) return res.status(401).json({ error: 'Invalid HMAC' });
  next();
}

app.get('/', (req, res) => res.json({ status: 'ok' }));

app.get('/register-webhooks', async (req, res) => {
  const shop = req.query.shop;
  const token = req.query.token;
  const webhooks = [
    { topic: 'customers/data_request', address: 'https://dropstore-webhooks.onrender.com/webhooks/customers/data_request' },
    { topic: 'customers/redact', address: 'https://dropstore-webhooks.onrender.com/webhooks/customers/redact' },
    { topic: 'shop/redact', address: 'https://dropstore-webhooks.onrender.com/webhooks/shop/redact' }
  ];
  const results = [];
  for (const wh of webhooks) {
    const r = await fetch(`https://${shop}/admin/api/2026-04/webhooks.json`, {
      method: 'POST',
      headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ webhook: { topic: wh.topic, address: wh.address, format: 'json' } })
    });
    results.push(await r.json());
  }
  res.json(results);
});

app.post('/webhooks/customers/data_request', verifyHmac, (req, res) => {
  console.log('Customer data request received');
  res.status(200).json({ received: true });
});

app.post('/webhooks/customers/redact', verifyHmac, (req, res) => {
  console.log('Customer redact received');
  res.status(200).json({ received: true });
});

app.post('/webhooks/shop/redact', verifyHmac, (req, res) => {
  console.log('Shop redact received');
  res.status(200).json({ received: true });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const { checkVendorWithRetry } = require('./sanctionsService');
const { updateVendorRecord } = require('./mondayService');

const app = express();
const PORT = process.env.PORT || 3000;

// Capture raw body before JSON parsing — needed for HMAC signature verification
app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  })
);

function verifyMondaySignature(req) {
  const signature = req.headers['x-monday-signature'];

  // Basic UI webhooks don't send a signature — skip verification in dev mode.
  // Signature enforcement applies only to published marketplace app webhooks.
  if (!signature) {
    console.warn('[auth] No x-monday-signature header — skipping verification (dev mode)');
    return true;
  }

  if (!req.rawBody) return false;

  const hmac = crypto.createHmac('sha256', process.env.MONDAY_SIGNING_SECRET);
  hmac.update(req.rawBody);
  const digest = `sha256=${hmac.digest('hex')}`;
  return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(signature));
}

app.post('/webhook', async (req, res) => {
  // Monday.com URL verification challenge (required during app setup)
  if (req.body.challenge) {
    return res.status(200).json({ challenge: req.body.challenge });
  }

  if (!verifyMondaySignature(req)) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  const { event } = req.body;
  const itemId = event?.pulseId;
  const vendorName = event?.pulseName;
  // Use personal API token for dev; marketplace apps use shortLivedToken instead
  const apiToken = process.env.MONDAY_API_TOKEN;

  if (!itemId || !vendorName) {
    return res.status(400).json({ error: 'Missing itemId or vendorName in payload' });
  }

  // Respond immediately — Monday.com times out if we wait for the full check
  res.status(200).json({ status: 'received' });

  // Async compliance check runs after response is sent
  processVendor(itemId, vendorName, apiToken);
});

async function processVendor(itemId, vendorName, apiToken) {
  try {
    console.log(`[vendor] Checking: "${vendorName}" (item ${itemId})`);

    const { riskLevel, details } = await checkVendorWithRetry(vendorName);

    console.log(`[vendor] Result for "${vendorName}": ${riskLevel}`);

    await updateVendorRecord(itemId, riskLevel, details, apiToken);

    console.log(`[vendor] Monday.com updated for item ${itemId}`);
  } catch (err) {
    console.error(`[vendor] Failed to process item ${itemId}:`, err.message);
  }
}

app.listen(PORT, () => {
  console.log(`VendorScreen AI listening on port ${PORT}`);
});

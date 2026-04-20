/**
 * ════════════════════════════════════════════════════════════
 *  Flash Clean — Secure Payment Backend
 *  Node.js + Express
 * ════════════════════════════════════════════════════════════
 *
 *  ENVIRONMENT VARIABLES — set in Railway dashboard:
 *
 *    STRIPE_SECRET_KEY        sk_live_...
 *    STRIPE_WEBHOOK_SECRET    whsec_...
 *    TWILIO_ACCOUNT_SID       AC...
 *    TWILIO_AUTH_TOKEN        your-auth-token
 *    TWILIO_FROM              whatsapp:+15558072617
 *    TWILIO_TO                whatsapp:+61426365751
 *    ALLOWED_ORIGIN           https://flashclean.com.au
 *    CAPTURE_SECRET_KEY       your-secret-password
 *    EMAIL_USER               your Gmail address
 *    EMAIL_PASS               Gmail App Password
 *    EMAIL_TO                 your business notification email
 * ════════════════════════════════════════════════════════════
 */

'use strict';

require('dotenv').config();

const express    = require('express');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const sqlite3    = require('sqlite3').verbose();
const stripe     = require('stripe')(process.env.STRIPE_SECRET_KEY);
const twilio     = require('twilio')(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
const nodemailer = require('nodemailer');
const crypto     = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

app.disable('x-powered-by');
// needed for correct client IP when behind Railway/Cloudflare/etc
app.set('trust proxy', 1);

// ── SQLITE (WEBHOOK IDEMPOTENCY) ─────────────────────────────
const db = new sqlite3.Database('./flashclean.db', (err) => {
  if (err) {
    console.error('[sqlite] Failed to open database:', err.message);
  } else {
    console.log('[sqlite] Database opened');
  }
});

db.serialize(() => {
  db.run(
    `CREATE TABLE IF NOT EXISTS processed_events (
       id          TEXT PRIMARY KEY,
       type        TEXT,
       created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
     )`,
    (err) => {
      if (err) console.error('[sqlite] Failed to ensure processed_events table:', err.message);
    }
  );
});

app.use(helmet({
  // This backend is API-only; CSP is usually managed by the frontend.
  contentSecurityPolicy: false,
}));

function getAllowedOrigins() {
  // Prefer ALLOWED_ORIGINS="https://a.com,https://b.com" but keep backwards-compatible ALLOWED_ORIGIN.
  const list = (process.env.ALLOWED_ORIGINS || process.env.ALLOWED_ORIGIN || 'https://flashclean.com.au')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
  return new Set(list);
}

const allowedOrigins = getAllowedOrigins();

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false,
});

const sensitiveLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

function constantTimeEquals(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function requireAdminKey(req, res, next) {
  // Do NOT accept secrets in JSON body (they may be logged by proxies).
  const key = req.get('x-capture-key');
  if (!process.env.CAPTURE_SECRET_KEY) return res.status(500).json({ error: 'Server misconfigured.' });
  if (!constantTimeEquals(key, process.env.CAPTURE_SECRET_KEY)) return res.status(401).json({ error: 'Unauthorized.' });
  next();
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

// ── EMAIL TRANSPORTER ────────────────────────────────────────
// Railway has no IPv6 egress. Pre-resolve smtp.gmail.com to IPv4 and connect by IP literal,
// so no library code path can re-resolve and pick the AAAA record.
const dns = require('dns');
dns.setDefaultResultOrder('ipv4first');

const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = Number(process.env.SMTP_PORT || 465);
const SMTP_SECURE = process.env.SMTP_SECURE
  ? process.env.SMTP_SECURE === 'true'
  : SMTP_PORT === 465;

let transporter; // reassigned once IPv4 resolves

function buildTransporter(host) {
  return nodemailer.createTransport({
    host,
    port: SMTP_PORT,
    secure: SMTP_SECURE,
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    // SNI must be the hostname since host is an IP literal.
    tls: { servername: SMTP_HOST, family: 4 },
    lookup: (hostname, opts, cb) => dns.lookup(hostname, { family: 4 }, cb),
    family: 4,
    connectionTimeout: 15_000,
    greetingTimeout: 15_000,
    socketTimeout: 20_000,
  });
}

// Initial transporter uses the hostname; gets replaced with IPv4 literal once resolved.
transporter = buildTransporter(SMTP_HOST);

dns.lookup(SMTP_HOST, { family: 4 }, (err, address) => {
  if (err) {
    console.error('[email] ❌ IPv4 lookup failed for', SMTP_HOST, err.message);
    return;
  }
  console.log('[email] Resolved', SMTP_HOST, '→', address, '(IPv4)');
  transporter = buildTransporter(address);
  transporter.verify()
    .then(() => console.log('[email] ✅ SMTP verified via IPv4:', address))
    .catch(e => console.error('[email] ❌ SMTP verify failed:', e.code, e.message));
});

// Validate SMTP credentials at startup (logs only, no secrets)
transporter.verify()
  .then(() => {
    console.log('[email] ✅ SMTP transporter verified for:', process.env.EMAIL_USER);
  })
  .catch((err) => {
    console.error('[email] ❌ SMTP verify failed:', err?.code, err?.command, err?.message);
  });

// ── CORS ─────────────────────────────────────────────────────
app.use(apiLimiter);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Stripe-Signature, X-Capture-Key');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── WEBHOOK must be raw body BEFORE express.json() ───────────
app.post('/webhook', express.raw({ type: 'application/json', limit: '1mb' }), handleWebhook);

// ── JSON body parser for all other routes ────────────────────
app.use(express.json({ limit: '50kb' }));

// ── HEALTH CHECK ─────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', service: 'Flash Clean Backend' }));

// ── DEBUG (DISABLED BY DEFAULT) ──────────────────────────────
app.get('/debug/webhook-events', sensitiveLimiter, requireAdminKey, (req, res) => {
  if (process.env.ENABLE_DEBUG_ENDPOINTS !== 'true') {
    return res.status(404).json({ error: 'Not found.' });
  }

  const limit = Math.max(1, Math.min(200, Number(req.query.limit) || 50));
  db.all(
    'SELECT id, type, created_at FROM processed_events ORDER BY created_at DESC LIMIT ?',
    [limit],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error.' });
      res.json({ count: rows.length, events: rows });
    }
  );
});


// ════════════════════════════════════════════════════════════
//  POST /create-payment-intent
//  Creates a Stripe PaymentIntent with capture_method: manual
//  Card is AUTHORISED (held) but NOT charged yet.
//  Charge happens after job is done via POST /capture
// ════════════════════════════════════════════════════════════
app.post('/create-payment-intent', async (req, res) => {
  const { amount, currency, description, receipt_email, metadata, idempotencyKey } = req.body;

  // SECURITY: ideally compute price server-side from a booking ID.
  // At minimum, enforce integer cents with a sane min/max to reduce tampering impact.
  const amountCents = Number(amount);
  if (!Number.isFinite(amountCents) || !Number.isInteger(amountCents) || amountCents < 50 || amountCents > 500000) {
    return res.status(400).json({ error: 'Invalid amount.' });
  }

  try {
    const paymentIntent = await stripe.paymentIntents.create(
      {
        amount:         amountCents,
        currency:       (currency || 'aud').toLowerCase(),
        description:    typeof description === 'string' ? description.slice(0, 500) : 'Flash Clean Booking',
        receipt_email:  receipt_email || undefined,
        metadata:       (metadata && typeof metadata === 'object') ? metadata : {},
        capture_method: 'manual',   // ✅ Hold card — capture after job is done
      },
      {
        idempotencyKey: typeof idempotencyKey === 'string' ? idempotencyKey : undefined, // ✅ Prevents double-charges on retry
      }
    );

    res.json({ clientSecret: paymentIntent.client_secret });

  } catch (err) {
    console.error('[/create-payment-intent]', err.type, err.code, err.message);
    res.status(500).json({ error: 'Payment service unavailable. Please try again.' });
  }
});


// ════════════════════════════════════════════════════════════
//  POST /notify
//  Called after payment confirmation.
//  Sends: WhatsApp + customer confirmation email + business alert
// ════════════════════════════════════════════════════════════
app.post('/notify', async (req, res) => {
  const { bookingData, paymentIntentId } = req.body;

  if (!bookingData || !bookingData['Name']) {
    return res.status(400).json({ error: 'Invalid booking data.' });
  }

  const b = bookingData;

  // SECURITY: do not trust a client-provided "paid" flag. Verify with Stripe.
  let verifiedStatus = 'unverified';
  let verifiedAmountCents = null;
  let verifiedCurrency = null;
  if (paymentIntentId) {
    try {
      const pi = await stripe.paymentIntents.retrieve(paymentIntentId);
      verifiedStatus = pi.status; // e.g. requires_capture, succeeded, requires_payment_method
      verifiedAmountCents = pi.amount;
      verifiedCurrency = pi.currency;
    } catch (err) {
      console.warn('[/notify] Unable to verify paymentIntentId:', err.message);
    }
  }

  const paid =
    verifiedStatus === 'requires_capture' ||
    verifiedStatus === 'succeeded' ||
    verifiedStatus === 'processing';

  // ── WHATSAPP ─────────────────────────────────────────────
  const msg =
    (paid ? '💰 PAYMENT AUTHORISED – NEW BOOKING\n\n' : '🧹 NEW FLASH CLEAN BOOKING\n\n') +
    '👤 Name: '      + (b['Name'] || '')          + '\n' +
    '📞 Phone: '     + (b['Phone'] || '')         + '\n' +
    '📧 Email: '     + (b['Email'] || '')         + '\n\n' +
    '🏠 Service: '   + (b['Service'] || '')       + '\n' +
    '🔄 Frequency: ' + (b['Frequency'] || '')     + '\n' +
    '🛏 Beds: '      + (b['Bedrooms'] || '')      + '  🚿 Baths: ' + (b['Bathrooms'] || '') + '\n' +
    '💰 Price: '     + (b['Est. Price'] || '')    + (paid ? ' ✅ AUTHORISED' : '') + '\n' +
    (paymentIntentId ? '🔑 Stripe PI: ' + paymentIntentId + '\n' : '') +
    (paymentIntentId ? '🧾 Verified: ' + verifiedStatus + '\n' : '') +
    '📅 Date: '      + (b['Pref. Date'] || '')    + '  ⏰ ' + (b['Pref. Time'] || '') + '\n\n' +
    '📍 Address: '   + (b['Address'] || '')       + '\n\n' +
    '➕ Extras:\n' +
    '  Oven: '            + (b['Oven Cleaning'] || '')     + '\n' +
    '  Fridge: '          + (b['Fridge Cleaning'] || '')   + '\n' +
    '  Int. Windows: '    + (b['Interior Windows'] || '')  + '\n' +
    '  Ext. Windows: '    + (b['External Windows'] || '')  + '\n' +
    '  Laundry: '         + (b['Laundry/Ironing'] || '')   + '\n' +
    '  Carpet: '          + (b['Carpet Cleaning'] || '')   + '\n\n' +
    (b['Special Notes'] ? '📝 Notes: ' + b['Special Notes'] + '\n\n' : '') +
    '🔑 Access: '    + (b['Home Access'] || '');

  // ── CUSTOMER EMAIL ───────────────────────────────────────
  const customerEmail = {
    from:    `"Flash Clean Sydney" <${process.env.EMAIL_USER}>`,
    to:      b['Email'],
    subject: '✅ Booking Confirmed – Flash Clean Sydney',
    html: `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
        <div style="background:#0ea5e9;padding:30px 40px;text-align:center;">
          <h1 style="color:#fff;margin:0;font-size:26px;">⚡ Flash Clean</h1>
          <p style="color:#e0f2fe;margin:6px 0 0;font-size:14px;">Professional Cleaning Services Sydney</p>
        </div>
        <div style="background:#fff;padding:35px 40px;">
          <h2 style="color:#0f172a;margin:0 0 8px;">Your booking is confirmed! 🎉</h2>
          <p style="color:#475569;margin:0 0 24px;">Hi ${escapeHtml(b['Name'])}, thanks for booking with Flash Clean. Here's your booking summary:</p>
          <div style="background:#f0f9ff;border-left:4px solid #0ea5e9;border-radius:8px;padding:20px 24px;margin-bottom:24px;">
            <table style="width:100%;border-collapse:collapse;">
              <tr><td style="padding:6px 0;color:#64748b;font-size:14px;width:130px;">📋 Service</td>    <td style="padding:6px 0;color:#0f172a;font-weight:600;font-size:14px;">${escapeHtml(b['Service'])}</td></tr>
              <tr><td style="padding:6px 0;color:#64748b;font-size:14px;">🔄 Frequency</td>  <td style="padding:6px 0;color:#0f172a;font-size:14px;">${escapeHtml(b['Frequency'])}</td></tr>
              <tr><td style="padding:6px 0;color:#64748b;font-size:14px;">📅 Date</td>        <td style="padding:6px 0;color:#0f172a;font-size:14px;">${escapeHtml(b['Pref. Date'])}</td></tr>
              <tr><td style="padding:6px 0;color:#64748b;font-size:14px;">⏰ Time</td>        <td style="padding:6px 0;color:#0f172a;font-size:14px;">${escapeHtml(b['Pref. Time'])}</td></tr>
              <tr><td style="padding:6px 0;color:#64748b;font-size:14px;">📍 Address</td>     <td style="padding:6px 0;color:#0f172a;font-size:14px;">${escapeHtml(b['Address'])}</td></tr>
              <tr><td style="padding:6px 0;color:#64748b;font-size:14px;">🛏 Bedrooms</td>    <td style="padding:6px 0;color:#0f172a;font-size:14px;">${escapeHtml(b['Bedrooms'])}</td></tr>
              <tr><td style="padding:6px 0;color:#64748b;font-size:14px;">🚿 Bathrooms</td>   <td style="padding:6px 0;color:#0f172a;font-size:14px;">${escapeHtml(b['Bathrooms'])}</td></tr>
              ${b['Oven Cleaning']    === 'Yes' ? `<tr><td style="padding:6px 0;color:#64748b;font-size:14px;">✅ Extra</td><td style="padding:6px 0;font-size:14px;">Oven Cleaning</td></tr>` : ''}
              ${b['Fridge Cleaning']  === 'Yes' ? `<tr><td style="padding:6px 0;color:#64748b;font-size:14px;">✅ Extra</td><td style="padding:6px 0;font-size:14px;">Fridge Cleaning</td></tr>` : ''}
              ${b['Interior Windows'] === 'Yes' ? `<tr><td style="padding:6px 0;color:#64748b;font-size:14px;">✅ Extra</td><td style="padding:6px 0;font-size:14px;">Interior Windows</td></tr>` : ''}
              ${b['External Windows'] === 'Yes' ? `<tr><td style="padding:6px 0;color:#64748b;font-size:14px;">✅ Extra</td><td style="padding:6px 0;font-size:14px;">External Windows</td></tr>` : ''}
              ${b['Laundry/Ironing']  === 'Yes' ? `<tr><td style="padding:6px 0;color:#64748b;font-size:14px;">✅ Extra</td><td style="padding:6px 0;font-size:14px;">Laundry/Ironing</td></tr>` : ''}
              ${b['Carpet Cleaning']  === 'Yes' ? `<tr><td style="padding:6px 0;color:#64748b;font-size:14px;">✅ Extra</td><td style="padding:6px 0;font-size:14px;">Carpet Cleaning</td></tr>` : ''}
              ${b['Special Notes'] ? `<tr><td style="padding:6px 0;color:#64748b;font-size:14px;">📝 Notes</td><td style="padding:6px 0;font-size:14px;">${escapeHtml(b['Special Notes'])}</td></tr>` : ''}
            </table>
          </div>
          <div style="background:#0ea5e9;border-radius:8px;padding:16px 24px;margin-bottom:24px;text-align:center;">
            <p style="color:#e0f2fe;margin:0 0 4px;font-size:13px;">Total Amount (Card Authorised)</p>
            <p style="color:#fff;margin:0;font-size:28px;font-weight:900;">${escapeHtml(b['Est. Price'])}</p>
            <p style="color:#bbf7d0;margin:4px 0 0;font-size:12px;">✅ Your card has been authorised. Payment is collected after your clean is complete.</p>
          </div>
          <p style="color:#475569;font-size:14px;margin:0 0 8px;">Need to make changes? Contact us:</p>
          <p style="color:#0ea5e9;font-size:14px;margin:0;"><strong>📞 +61 426 365 751</strong></p>
          <p style="color:#0ea5e9;font-size:14px;margin:4px 0 0;"><strong>🌐 flashclean.com.au</strong></p>
        </div>
        <div style="background:#f1f5f9;padding:20px 40px;text-align:center;">
          <p style="color:#94a3b8;font-size:12px;margin:0;">⚡ Flash Clean Sydney | $10M Public Liability Insurance</p>
        </div>
      </div>
    `,
  };

  // ── BUSINESS NOTIFICATION EMAIL ──────────────────────────
  const businessEmail = {
    from:    `"Flash Clean Bookings" <${process.env.EMAIL_USER}>`,
    to:      process.env.EMAIL_TO,
    subject: `💰 New Booking – ${b['Name']} – ${b['Pref. Date']} – ${b['Est. Price']}`,
    html: `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:24px;">
        <h2 style="color:#0ea5e9;margin:0 0 16px;">⚡ New Flash Clean Booking</h2>
        <table style="width:100%;border-collapse:collapse;font-size:14px;">
          <tr style="background:#f0f9ff;"><td style="padding:8px 12px;color:#64748b;width:140px;">👤 Name</td>       <td style="padding:8px 12px;font-weight:600;">${escapeHtml(b['Name'])}</td></tr>
          <tr>                            <td style="padding:8px 12px;color:#64748b;">📞 Phone</td>      <td style="padding:8px 12px;">${escapeHtml(b['Phone'])}</td></tr>
          <tr style="background:#f0f9ff;"><td style="padding:8px 12px;color:#64748b;">📧 Email</td>      <td style="padding:8px 12px;">${escapeHtml(b['Email'])}</td></tr>
          <tr>                            <td style="padding:8px 12px;color:#64748b;">🏠 Service</td>    <td style="padding:8px 12px;">${escapeHtml(b['Service'])}</td></tr>
          <tr style="background:#f0f9ff;"><td style="padding:8px 12px;color:#64748b;">🔄 Frequency</td> <td style="padding:8px 12px;">${escapeHtml(b['Frequency'])}</td></tr>
          <tr>                            <td style="padding:8px 12px;color:#64748b;">📅 Date</td>       <td style="padding:8px 12px;">${escapeHtml(b['Pref. Date'])}</td></tr>
          <tr style="background:#f0f9ff;"><td style="padding:8px 12px;color:#64748b;">⏰ Time</td>       <td style="padding:8px 12px;">${escapeHtml(b['Pref. Time'])}</td></tr>
          <tr>                            <td style="padding:8px 12px;color:#64748b;">📍 Address</td>    <td style="padding:8px 12px;">${escapeHtml(b['Address'])}</td></tr>
          <tr style="background:#f0f9ff;"><td style="padding:8px 12px;color:#64748b;">🛏 Beds/Baths</td><td style="padding:8px 12px;">${escapeHtml(b['Bedrooms'])} bed / ${escapeHtml(b['Bathrooms'])} bath</td></tr>
          <tr>                            <td style="padding:8px 12px;color:#64748b;">💰 Price</td>      <td style="padding:8px 12px;font-weight:700;color:#0ea5e9;">${escapeHtml(b['Est. Price'])} ${paid ? '✅ AUTHORISED' : ''}</td></tr>
          ${paymentIntentId ? `<tr style="background:#f0f9ff;"><td style="padding:8px 12px;color:#64748b;">🔑 Stripe PI</td><td style="padding:8px 12px;font-family:monospace;">${escapeHtml(paymentIntentId)}</td></tr>` : ''}
          ${paymentIntentId ? `<tr><td style="padding:8px 12px;color:#64748b;">🧾 Verified</td><td style="padding:8px 12px;">${escapeHtml(verifiedStatus)} (${verifiedCurrency ? escapeHtml(verifiedCurrency.toUpperCase()) : ''}${verifiedAmountCents ? ' ' + (verifiedAmountCents / 100).toFixed(2) : ''})</td></tr>` : ''}
          <tr>                            <td style="padding:8px 12px;color:#64748b;">🔑 Access</td>     <td style="padding:8px 12px;">${escapeHtml(b['Home Access'])}</td></tr>
          ${b['Special Notes'] ? `<tr style="background:#f0f9ff;"><td style="padding:8px 12px;color:#64748b;">📝 Notes</td><td style="padding:8px 12px;">${escapeHtml(b['Special Notes'])}</td></tr>` : ''}
        </table>
        <div style="margin-top:16px;padding:12px 16px;background:#fef3c7;border-radius:6px;font-size:13px;color:#92400e;">
          ⚠️ Card is <strong>authorised (on hold)</strong> — capture payment after job is complete.
        </div>
      </div>
    `,
  };

  // ── SEND ALL ─────────────────────────────────────────────
  const results = { whatsapp: false, customerEmail: false, businessEmail: false };

  try {
    await twilio.messages.create({ from: process.env.TWILIO_FROM, to: process.env.TWILIO_TO, body: msg });
    results.whatsapp = true;
  } catch (err) { console.error('[/notify] WhatsApp error:', err.message); }

  try {
    await transporter.sendMail(customerEmail);
    results.customerEmail = true;
    console.log('[/notify] ✅ Customer email sent to:', b['Email']);
  } catch (err) {
    console.error('[/notify] Customer email error:', err?.code, err?.command, err?.response, err?.message);
  }

  try {
    await transporter.sendMail(businessEmail);
    results.businessEmail = true;
    console.log('[/notify] ✅ Business email sent to:', process.env.EMAIL_TO);
  } catch (err) {
    console.error('[/notify] Business email error:', err?.code, err?.command, err?.response, err?.message);
  }

  res.json({ sent: true, results });
});


// ════════════════════════════════════════════════════════════
//  POST /capture
//  Capture payment after job is complete (original amount)
//  Header: X-Capture-Key: <secret>
//  Body: { "paymentIntentId": "pi_xxx" }
// ════════════════════════════════════════════════════════════
app.post('/capture', sensitiveLimiter, requireAdminKey, async (req, res) => {
  const { paymentIntentId } = req.body;
  if (!paymentIntentId) return res.status(400).json({ error: 'Missing paymentIntentId.' });
  try {
    const pi = await stripe.paymentIntents.capture(paymentIntentId);
    console.log('[/capture] ✅ Captured:', pi.id, '$' + pi.amount / 100);
    res.json({ captured: true, amount: pi.amount / 100, id: pi.id });
  } catch (err) {
    console.error('[/capture] Error:', err.message);
    res.status(500).json({ error: 'Capture failed. ' + err.message });
  }
});


// ════════════════════════════════════════════════════════════
//  POST /capture-with-amount
//  Capture with a DIFFERENT amount (e.g. customer added extras)
//  Amount must be within the original authorized amount.
//  Header: X-Capture-Key: <secret>
//  Body: { "paymentIntentId": "pi_xxx", "amountCents": 21000 }
// ════════════════════════════════════════════════════════════
app.post('/capture-with-amount', sensitiveLimiter, requireAdminKey, async (req, res) => {
  const { paymentIntentId, amountCents } = req.body;
  if (!paymentIntentId || !amountCents) return res.status(400).json({ error: 'Missing fields.' });
  try {
    await stripe.paymentIntents.update(paymentIntentId, { amount: Math.round(amountCents) });
    const pi = await stripe.paymentIntents.capture(paymentIntentId);
    console.log('[/capture-with-amount] ✅ Captured:', pi.id, '$' + pi.amount / 100);
    res.json({ captured: true, amount: pi.amount / 100, id: pi.id });
  } catch (err) {
    console.error('[/capture-with-amount] Error:', err.message);
    res.status(500).json({ error: 'Capture failed. ' + err.message });
  }
});


// ════════════════════════════════════════════════════════════
//  POST /cancel-authorization
//  Release the hold without charging (job cancelled)
//  Header: X-Capture-Key: <secret>
//  Body: { "paymentIntentId": "pi_xxx" }
// ════════════════════════════════════════════════════════════
app.post('/cancel-authorization', sensitiveLimiter, requireAdminKey, async (req, res) => {
  const { paymentIntentId } = req.body;
  try {
    const pi = await stripe.paymentIntents.cancel(paymentIntentId);
    console.log('[/cancel-auth] ✅ Cancelled:', pi.id);
    res.json({ cancelled: true, id: pi.id });
  } catch (err) {
    console.error('[/cancel-auth] Error:', err.message);
    res.status(500).json({ error: 'Cancellation failed. ' + err.message });
  }
});


// ════════════════════════════════════════════════════════════
//  POST /charge-extra
//  Charge extra to same card AFTER original payment captured.
//  Body: { "originalPaymentIntentId": "pi_xxx", "extraAmountCents": 6000,
//          "description": "Oven add-on" }
//  Header: X-Capture-Key: <secret>
// ════════════════════════════════════════════════════════════
app.post('/charge-extra', sensitiveLimiter, requireAdminKey, async (req, res) => {
  const { originalPaymentIntentId, extraAmountCents, description } = req.body;
  if (!originalPaymentIntentId || !extraAmountCents) return res.status(400).json({ error: 'Missing fields.' });
  try {
    const original = await stripe.paymentIntents.retrieve(originalPaymentIntentId);
    if (!original.payment_method) return res.status(400).json({ error: 'No payment method found.' });
    const extra = await stripe.paymentIntents.create({
      amount:         Math.round(extraAmountCents),
      currency:       original.currency || 'aud',
      payment_method: original.payment_method,
      description:    description || 'Flash Clean — Extra charge',
      receipt_email:  original.receipt_email || undefined,
      confirm:        true,
      off_session:    true,
      capture_method: 'automatic',
      metadata: { original_payment_intent: originalPaymentIntentId, type: 'extra_charge' },
    });
    console.log('[/charge-extra] ✅ Extra charged:', extra.id, '$' + extra.amount / 100);
    res.json({ charged: true, id: extra.id, amount: extra.amount / 100, status: extra.status });
  } catch (err) {
    console.error('[/charge-extra] Error:', err.message);
    if (err.code === 'authentication_required') return res.status(402).json({ error: 'Card requires authentication. Customer must re-enter card details.' });
    if (err.code === 'card_declined') return res.status(402).json({ error: 'Card declined. Please contact the customer.' });
    res.status(500).json({ error: 'Extra charge failed. ' + err.message });
  }
});


// ════════════════════════════════════════════════════════════
//  POST /webhook
//  Stripe sends signed events here. Verify signature first.
// ════════════════════════════════════════════════════════════
async function handleWebhook(req, res) {
  const sig           = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
  } catch (err) {
    console.warn('[/webhook] Signature failed:', err.message);
    return res.status(400).send('Webhook error');
  }

  // Idempotency: skip events we've already processed
  const eventId = event.id;
  const eventType = event.type;

  db.get('SELECT id FROM processed_events WHERE id = ?', [eventId], (err, row) => {
    if (err) {
      console.error('[/webhook] DB error checking idempotency:', err.message);
      // Fail closed: do not acknowledge to Stripe so it can retry later.
      return res.status(500).send('Webhook storage error');
    }

    if (row) {
      console.log('[/webhook] Duplicate event ignored:', eventId, eventType);
      return res.json({ received: true, duplicate: true });
    }

    db.run(
      'INSERT INTO processed_events (id, type) VALUES (?, ?)',
      [eventId, eventType],
      (insertErr) => {
        if (insertErr) {
          console.error('[/webhook] DB insert error:', insertErr.message);
          return res.status(500).send('Webhook storage error');
        }

        processWebhookEvent(event, res);
      }
    );
  });
}

function processWebhookEvent(event, res) {
  const type = event.type;

  switch (type) {
    case 'payment_intent.amount_capturable_updated': {
      const pi = event.data.object;
      console.log('[/webhook] 🔒 Card authorised (hold placed):', pi.id, '$' + pi.amount / 100);
      break;
    }
    case 'payment_intent.succeeded': {
      const pi = event.data.object;
      console.log('[/webhook] ✅ Payment captured:', pi.id, '$' + pi.amount / 100);
      break;
    }
    case 'payment_intent.payment_failed': {
      const pi = event.data.object;
      console.warn('[/webhook] ❌ Payment failed:', pi.id, pi.last_payment_error?.code);
      break;
    }
    default:
      break;
  }

  res.json({ received: true });
}


// ── START SERVER ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`⚡ Flash Clean backend running on port ${PORT}`);
});

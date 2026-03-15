/**
 * ════════════════════════════════════════════════════════════
 *  Flash Clean — Secure Payment Backend
 *  Node.js + Express
 * ════════════════════════════════════════════════════════════
 *
 *  ENVIRONMENT VARIABLES — set these in your Railway dashboard:
 *
 *    STRIPE_SECRET_KEY        sk_live_...
 *    STRIPE_WEBHOOK_SECRET    whsec_...
 *    TWILIO_ACCOUNT_SID       AC...
 *    TWILIO_AUTH_TOKEN        your-auth-token
 *    TWILIO_FROM              whatsapp:+15558072617
 *    TWILIO_TO                whatsapp:+61426365751
 *    ALLOWED_ORIGIN           https://flashclean.com.au
 *    CAPTURE_SECRET_KEY       your-secret-password
 *
 *    EMAIL_USER               your Gmail address e.g. hello@flashclean.com.au
 *    EMAIL_PASS               Gmail App Password (NOT your normal password)
 *                             Get it: myaccount.google.com → Security → App Passwords
 *    EMAIL_TO                 your business email to receive booking notifications
 *
 *  INSTALL:
 *    npm install express stripe twilio dotenv nodemailer
 * ════════════════════════════════════════════════════════════
 */

'use strict';

require('dotenv').config();

const express    = require('express');
const stripe     = require('stripe')(process.env.STRIPE_SECRET_KEY);
const twilio     = require('twilio')(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
const nodemailer = require('nodemailer');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── EMAIL TRANSPORTER ─────────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,   // Gmail App Password
  },
});

const app  = express();
const PORT = process.env.PORT || 3000;

// ── CORS ──────────────────────────────────────────────────────
// Only allow requests from your own domain
app.use((req, res, next) => {
  const origin = process.env.ALLOWED_ORIGIN || 'https://flashclean.com.au';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── BODY PARSING ──────────────────────────────────────────────
// IMPORTANT: /webhook must receive raw bytes for signature verification.
// Register it BEFORE express.json() so the raw body is preserved.
app.post(
  '/webhook',
  express.raw({ type: 'application/json' }),
  handleWebhook
);

// All other routes can use JSON parsing
app.use(express.json());


// ════════════════════════════════════════════════════════════
//  POST /create-payment-intent
//  Called by the frontend to create a Stripe PaymentIntent.
//  The secret key never leaves this server.
// ════════════════════════════════════════════════════════════
app.post('/create-payment-intent', async (req, res) => {
  const { amount, currency, description, receipt_email, idempotencyKey, metadata } = req.body;

  // Basic server-side validation
  if (!amount || typeof amount !== 'number' || amount < 100) {
    return res.status(400).json({ error: 'Invalid payment amount.' });
  }
  if (!idempotencyKey || typeof idempotencyKey !== 'string') {
    return res.status(400).json({ error: 'Missing idempotency key.' });
  }

  try {
    const paymentIntent = await stripe.paymentIntents.create(
      {
        amount:         Math.round(amount),    // always integer cents
        currency:       currency || 'aud',
        description:    description || 'Flash Clean Booking',
        receipt_email:  receipt_email || undefined,
        metadata:       metadata || {},
        capture_method: 'manual',   // ✅ Authorize only — funds held but NOT charged yet
                                    // Capture manually from Stripe Dashboard after job done
                                    // Authorization expires after 7 days
      },
      {
        // ✅ FIX 3: Idempotency key — if the same key is sent again (e.g. on network retry),
        // Stripe returns the SAME PaymentIntent instead of creating a new one.
        // This completely prevents double-charges.
        idempotencyKey,
      }
    );

    // ✅ Only send the client_secret — never send the full PaymentIntent object
    res.json({ clientSecret: paymentIntent.client_secret });

  } catch (err) {
    // ✅ FIX 4: Log full error server-side; return only a generic message to the client
    console.error('[/create-payment-intent]', err.type, err.code, err.message);
    res.status(500).json({ error: 'Payment service unavailable. Please try again.' });
  }
});


// ════════════════════════════════════════════════════════════
//  POST /notify
//  Called by the frontend AFTER payment confirmation.
//  Sends WhatsApp via Twilio + emails via Gmail
// ════════════════════════════════════════════════════════════
app.post('/notify', async (req, res) => {
  const { bookingData, paid, paymentId } = req.body;

  if (!bookingData || !bookingData['Name']) {
    return res.status(400).json({ error: 'Invalid booking data.' });
  }

  const b = bookingData;

  // ── WHATSAPP MESSAGE ──────────────────────────────────────
  const msg =
    (paid ? '💰 PAYMENT RECEIVED – NEW BOOKING\n\n' : '🧹 NEW FLASH CLEAN BOOKING\n\n') +
    '👤 Name: '     + b['Name']    + '\n' +
    '📞 Phone: '    + b['Phone']   + '\n' +
    '📧 Email: '    + b['Email']   + '\n\n' +
    '🏠 Service: '  + b['Service'] + '\n' +
    '🔄 Frequency: '+ b['Frequency'] + '\n' +
    '🛏 Beds: '     + b['Bedrooms']  + '  🚿 Baths: ' + b['Bathrooms'] + '\n' +
    '💰 Price: '    + b['Est. Price'] + (paid ? ' ✅ PAID' : '') + '\n' +
    (paymentId ? '🔑 Stripe ID: ' + paymentId + '\n' : '') +
    '📅 Date: '     + b['Pref. Date'] + '  ⏰ ' + b['Pref. Time'] + '\n\n' +
    '📍 Address: '  + b['Address'] + '\n\n' +
    '➕ Extras:\n' +
    '  Oven: '       + b['Oven Cleaning']    + '\n' +
    '  Fridge: '     + b['Fridge Cleaning']  + '\n' +
    '  Int. Windows: '+ b['Interior Windows']+ '\n' +
    '  Ext. Windows: '+ b['External Windows']+ '\n' +
    '  Laundry: '    + b['Laundry/Ironing']  + '\n' +
    '  Carpet: '     + b['Carpet Cleaning']  + '\n\n' +
    (b['Special Notes'] ? '📝 Notes: ' + b['Special Notes'] + '\n\n' : '') +
    '🔑 Access: '   + b['Home Access'];

  // ── CUSTOMER CONFIRMATION EMAIL ───────────────────────────
  const customerEmail = {
    from: `"Flash Clean Sydney" <${process.env.EMAIL_USER}>`,
    to:   b['Email'],
    subject: '✅ Booking Confirmed – Flash Clean Sydney',
    html: `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#f9f9f9;padding:0;">

        <!-- HEADER -->
        <div style="background:#0ea5e9;padding:30px 40px;text-align:center;">
          <h1 style="color:#fff;margin:0;font-size:26px;letter-spacing:-0.5px;">⚡ Flash Clean</h1>
          <p style="color:#e0f2fe;margin:6px 0 0;font-size:14px;">Professional Cleaning Services Sydney</p>
        </div>

        <!-- BODY -->
        <div style="background:#fff;padding:35px 40px;">
          <h2 style="color:#0f172a;margin:0 0 8px;">Your booking is confirmed! 🎉</h2>
          <p style="color:#475569;margin:0 0 24px;">Hi ${b['Name']}, thanks for booking with Flash Clean. Here's a summary of your booking:</p>

          <!-- BOOKING DETAILS -->
          <div style="background:#f0f9ff;border-left:4px solid #0ea5e9;border-radius:8px;padding:20px 24px;margin-bottom:24px;">
            <table style="width:100%;border-collapse:collapse;">
              <tr><td style="padding:6px 0;color:#64748b;font-size:14px;width:130px;">📋 Service</td>        <td style="padding:6px 0;color:#0f172a;font-weight:600;font-size:14px;">${b['Service']}</td></tr>
              <tr><td style="padding:6px 0;color:#64748b;font-size:14px;">🔄 Frequency</td>     <td style="padding:6px 0;color:#0f172a;font-size:14px;">${b['Frequency']}</td></tr>
              <tr><td style="padding:6px 0;color:#64748b;font-size:14px;">📅 Date</td>           <td style="padding:6px 0;color:#0f172a;font-size:14px;">${b['Pref. Date']}</td></tr>
              <tr><td style="padding:6px 0;color:#64748b;font-size:14px;">⏰ Time</td>           <td style="padding:6px 0;color:#0f172a;font-size:14px;">${b['Pref. Time']}</td></tr>
              <tr><td style="padding:6px 0;color:#64748b;font-size:14px;">📍 Address</td>        <td style="padding:6px 0;color:#0f172a;font-size:14px;">${b['Address']}</td></tr>
              <tr><td style="padding:6px 0;color:#64748b;font-size:14px;">🛏 Bedrooms</td>       <td style="padding:6px 0;color:#0f172a;font-size:14px;">${b['Bedrooms']}</td></tr>
              <tr><td style="padding:6px 0;color:#64748b;font-size:14px;">🚿 Bathrooms</td>      <td style="padding:6px 0;color:#0f172a;font-size:14px;">${b['Bathrooms']}</td></tr>
              ${b['Oven Cleaning']    === 'Yes' ? `<tr><td style="padding:6px 0;color:#64748b;font-size:14px;">✅ Extra</td><td style="padding:6px 0;color:#0f172a;font-size:14px;">Oven Cleaning</td></tr>` : ''}
              ${b['Fridge Cleaning']  === 'Yes' ? `<tr><td style="padding:6px 0;color:#64748b;font-size:14px;">✅ Extra</td><td style="padding:6px 0;color:#0f172a;font-size:14px;">Fridge Cleaning</td></tr>` : ''}
              ${b['Interior Windows'] === 'Yes' ? `<tr><td style="padding:6px 0;color:#64748b;font-size:14px;">✅ Extra</td><td style="padding:6px 0;color:#0f172a;font-size:14px;">Interior Windows</td></tr>` : ''}
              ${b['External Windows'] === 'Yes' ? `<tr><td style="padding:6px 0;color:#64748b;font-size:14px;">✅ Extra</td><td style="padding:6px 0;color:#0f172a;font-size:14px;">External Windows</td></tr>` : ''}
              ${b['Laundry/Ironing']  === 'Yes' ? `<tr><td style="padding:6px 0;color:#64748b;font-size:14px;">✅ Extra</td><td style="padding:6px 0;color:#0f172a;font-size:14px;">Laundry/Ironing</td></tr>` : ''}
              ${b['Carpet Cleaning']  === 'Yes' ? `<tr><td style="padding:6px 0;color:#64748b;font-size:14px;">✅ Extra</td><td style="padding:6px 0;color:#0f172a;font-size:14px;">Carpet Cleaning</td></tr>` : ''}
              ${b['Special Notes'] ? `<tr><td style="padding:6px 0;color:#64748b;font-size:14px;">📝 Notes</td><td style="padding:6px 0;color:#0f172a;font-size:14px;">${b['Special Notes']}</td></tr>` : ''}
            </table>
          </div>

          <!-- PRICE BOX -->
          <div style="background:#0ea5e9;border-radius:8px;padding:16px 24px;margin-bottom:24px;text-align:center;">
            <p style="color:#e0f2fe;margin:0 0 4px;font-size:13px;">Total Amount ${paid ? '(Card Authorised)' : ''}</p>
            <p style="color:#fff;margin:0;font-size:28px;font-weight:900;">${b['Est. Price']}</p>
            ${paid ? '<p style="color:#bbf7d0;margin:4px 0 0;font-size:12px;">✅ Your card has been authorised. Payment is collected after your clean is complete.</p>' : ''}
          </div>

          ${b['Special Notes'] ? '' : ''}

          <p style="color:#475569;font-size:14px;margin:0 0 8px;">Our team will confirm your booking shortly. If you need to make any changes please contact us:</p>
          <p style="color:#0ea5e9;font-size:14px;margin:0;"><strong>📞 +61 426 365 751</strong></p>
          <p style="color:#0ea5e9;font-size:14px;margin:4px 0 0;"><strong>🌐 flashclean.com.au</strong></p>
        </div>

        <!-- FOOTER -->
        <div style="background:#f1f5f9;padding:20px 40px;text-align:center;border-top:1px solid #e2e8f0;">
          <p style="color:#94a3b8;font-size:12px;margin:0;">⚡ Flash Clean Sydney &nbsp;|&nbsp; ABN: [Your ABN]</p>
          <p style="color:#94a3b8;font-size:12px;margin:4px 0 0;">$10M Public Liability Insurance &nbsp;|&nbsp; All cleaners background checked</p>
          <p style="color:#cbd5e1;font-size:11px;margin:8px 0 0;">You're receiving this because you made a booking at flashclean.com.au</p>
        </div>

      </div>
    `,
  };

  // ── BUSINESS NOTIFICATION EMAIL ───────────────────────────
  const businessEmail = {
    from:    `"Flash Clean Bookings" <${process.env.EMAIL_USER}>`,
    to:      process.env.EMAIL_TO,
    subject: `💰 New Booking – ${b['Name']} – ${b['Pref. Date']} – ${b['Est. Price']}`,
    html: `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:24px;">
        <h2 style="color:#0ea5e9;margin:0 0 16px;">⚡ New Flash Clean Booking</h2>
        <table style="width:100%;border-collapse:collapse;font-size:14px;">
          <tr style="background:#f0f9ff;"><td style="padding:8px 12px;color:#64748b;width:140px;">👤 Name</td>        <td style="padding:8px 12px;font-weight:600;">${b['Name']}</td></tr>
          <tr>                            <td style="padding:8px 12px;color:#64748b;">📞 Phone</td>       <td style="padding:8px 12px;">${b['Phone']}</td></tr>
          <tr style="background:#f0f9ff;"><td style="padding:8px 12px;color:#64748b;">📧 Email</td>       <td style="padding:8px 12px;">${b['Email']}</td></tr>
          <tr>                            <td style="padding:8px 12px;color:#64748b;">🏠 Service</td>     <td style="padding:8px 12px;">${b['Service']}</td></tr>
          <tr style="background:#f0f9ff;"><td style="padding:8px 12px;color:#64748b;">🔄 Frequency</td>  <td style="padding:8px 12px;">${b['Frequency']}</td></tr>
          <tr>                            <td style="padding:8px 12px;color:#64748b;">📅 Date</td>        <td style="padding:8px 12px;">${b['Pref. Date']}</td></tr>
          <tr style="background:#f0f9ff;"><td style="padding:8px 12px;color:#64748b;">⏰ Time</td>        <td style="padding:8px 12px;">${b['Pref. Time']}</td></tr>
          <tr>                            <td style="padding:8px 12px;color:#64748b;">📍 Address</td>     <td style="padding:8px 12px;">${b['Address']}</td></tr>
          <tr style="background:#f0f9ff;"><td style="padding:8px 12px;color:#64748b;">🛏 Beds/Baths</td> <td style="padding:8px 12px;">${b['Bedrooms']} bed / ${b['Bathrooms']} bath</td></tr>
          <tr>                            <td style="padding:8px 12px;color:#64748b;">💰 Price</td>       <td style="padding:8px 12px;font-weight:700;color:#0ea5e9;">${b['Est. Price']} ${paid ? '✅ PAID' : ''}</td></tr>
          ${paymentId ? `<tr style="background:#f0f9ff;"><td style="padding:8px 12px;color:#64748b;">🔑 Stripe ID</td><td style="padding:8px 12px;font-family:monospace;">${paymentId}</td></tr>` : ''}
          <tr>                            <td style="padding:8px 12px;color:#64748b;">🔑 Access</td>      <td style="padding:8px 12px;">${b['Home Access']}</td></tr>
          ${b['Special Notes'] ? `<tr style="background:#f0f9ff;"><td style="padding:8px 12px;color:#64748b;">📝 Notes</td><td style="padding:8px 12px;">${b['Special Notes']}</td></tr>` : ''}
        </table>
        <div style="margin-top:16px;padding:12px 16px;background:#fef3c7;border-radius:6px;font-size:13px;color:#92400e;">
          ⚠️ Card is <strong>authorised (on hold)</strong> — capture payment after job is complete via /capture endpoint.
        </div>
      </div>
    `,
  };

  // ── SEND EVERYTHING ───────────────────────────────────────
  const results = { whatsapp: false, customerEmail: false, businessEmail: false };

  // 1. WhatsApp
  try {
    await twilio.messages.create({
      from: process.env.TWILIO_FROM,
      to:   process.env.TWILIO_TO,
      body: msg,
    });
    results.whatsapp = true;
  } catch (err) {
    console.error('[/notify] Twilio error:', err.code, err.message);
  }

  // 2. Customer confirmation email
  try {
    await transporter.sendMail(customerEmail);
    results.customerEmail = true;
    console.log('[/notify] ✅ Customer email sent to:', b['Email']);
  } catch (err) {
    console.error('[/notify] Customer email error:', err.message);
  }

  // 3. Business notification email
  try {
    await transporter.sendMail(businessEmail);
    results.businessEmail = true;
    console.log('[/notify] ✅ Business email sent to:', process.env.EMAIL_TO);
  } catch (err) {
    console.error('[/notify] Business email error:', err.message);
  }

  res.json({ sent: true, results });
});


// ════════════════════════════════════════════════════════════
//  POST /capture
//  Call this AFTER the cleaning job is complete to charge the card.
//  Requires a secret capture key so only you can trigger it.
//
//  Usage: POST https://flashclean-backend-production.up.railway.app/capture
//  Body:  { "paymentIntentId": "pi_xxx", "captureKey": "your-secret-key" }
//
//  Set CAPTURE_SECRET_KEY in Railway env vars (any secret string you choose)
// ════════════════════════════════════════════════════════════
app.post('/capture', async (req, res) => {
  const { paymentIntentId, captureKey } = req.body;

  // Simple secret key check — only you can capture
  if (captureKey !== process.env.CAPTURE_SECRET_KEY) {
    return res.status(401).json({ error: 'Unauthorized.' });
  }

  if (!paymentIntentId) {
    return res.status(400).json({ error: 'Missing paymentIntentId.' });
  }

  try {
    const paymentIntent = await stripe.paymentIntents.capture(paymentIntentId);
    console.log('[/capture] ✅ Payment captured:', paymentIntent.id, '$' + paymentIntent.amount / 100);
    res.json({ captured: true, amount: paymentIntent.amount / 100, id: paymentIntent.id });
  } catch (err) {
    console.error('[/capture] Error:', err.message);
    res.status(500).json({ error: 'Capture failed. ' + err.message });
  }
});


// ════════════════════════════════════════════════════════════
//  POST /cancel-authorization
//  Call this to release the hold without charging (e.g. job cancelled).
//  Body: { "paymentIntentId": "pi_xxx", "captureKey": "your-secret-key" }
// ════════════════════════════════════════════════════════════
app.post('/cancel-authorization', async (req, res) => {
  const { paymentIntentId, captureKey } = req.body;

  if (captureKey !== process.env.CAPTURE_SECRET_KEY) {
    return res.status(401).json({ error: 'Unauthorized.' });
  }

  try {
    const paymentIntent = await stripe.paymentIntents.cancel(paymentIntentId);
    console.log('[/cancel-auth] ✅ Authorization cancelled:', paymentIntent.id);
    res.json({ cancelled: true, id: paymentIntent.id });
  } catch (err) {
    console.error('[/cancel-auth] Error:', err.message);
    res.status(500).json({ error: 'Cancellation failed. ' + err.message });
  }
});
//  ✅ FIX 2: Stripe sends signed events here after payment succeeds.
//  We verify the signature before trusting ANY event data.
//  This is the authoritative source of truth — not the browser.
// ════════════════════════════════════════════════════════════
async function handleWebhook(req, res) {
  const sig           = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  try {
    // ✅ constructEvent will THROW if the signature doesn't match.
    // This rejects any spoofed or replayed events.
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
  } catch (err) {
    // Signature mismatch — reject silently with no detail
    console.warn('[/webhook] Signature verification failed:', err.message);
    return res.status(400).send('Webhook error');
  }

  // Handle verified events
  switch (event.type) {
    case 'payment_intent.amount_capturable_updated': {
      // Fires when card is authorized and ready to capture
      const pi = event.data.object;
      console.log('[/webhook] 🔒 Card authorized (hold placed):', pi.id, '$' + pi.amount / 100);
      // Card is held — capture after job is done via POST /capture
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

    case 'charge.dispute.created': {
      console.error('[/webhook] ⚠️ Dispute created:', event.data.object.id);
      break;
    }

    default:
      break;
  }

  // Always return 200 quickly so Stripe doesn't retry
  res.json({ received: true });
}


// ════════════════════════════════════════════════════════════
//  Health check — useful for uptime monitoring
// ════════════════════════════════════════════════════════════
app.get('/health', (req, res) => res.json({ status: 'ok' }));


// ── Catch-all: never leak stack traces ───────────────────────
app.use((err, req, res, _next) => {
  console.error('[unhandled]', err);
  res.status(500).json({ error: 'Internal server error.' });
});


app.listen(PORT, () => {
  console.log('Flash Clean backend running on port', PORT);
  console.log('Stripe key loaded:', process.env.STRIPE_SECRET_KEY ? '✅' : '❌ MISSING');
  console.log('Webhook secret:   ', process.env.STRIPE_WEBHOOK_SECRET ? '✅' : '❌ MISSING');
  console.log('Twilio SID:       ', process.env.TWILIO_ACCOUNT_SID ? '✅' : '❌ MISSING');
  console.log('Twilio token:     ', process.env.TWILIO_AUTH_TOKEN ? '✅' : '❌ MISSING');
});

module.exports = app;

/**
 * ════════════════════════════════════════════════════════════
 *  Flash Clean — Secure Payment Backend
 *  Node.js + Express
 * ════════════════════════════════════════════════════════════
 *
 *  DEPLOY OPTIONS (all free tiers available):
 *    • Vercel:            vercel deploy
 *    • Cloudflare Workers: wrangler deploy  (see cloudflare-worker.js)
 *    • Railway / Render:  push to GitHub → auto-deploy
 *
 *  ENVIRONMENT VARIABLES — set these in your hosting dashboard,
 *  NEVER hardcode them here or commit them to git:
 *
 *    STRIPE_SECRET_KEY        sk_live_...   (Stripe Dashboard → API Keys)
 *    STRIPE_WEBHOOK_SECRET    whsec_...     (Stripe Dashboard → Webhooks → signing secret)
 *    TWILIO_ACCOUNT_SID       AC...         (Twilio Console → Account Info)
 *    TWILIO_AUTH_TOKEN        (rotate at:   console.twilio.com → rotate Auth Token)
 *    TWILIO_FROM              whatsapp:+15558072617
 *    TWILIO_TO                whatsapp:+61426365751
 *    ALLOWED_ORIGIN           https://flashclean.com.au
 *
 *  INSTALL:
 *    npm init -y
 *    npm install express stripe twilio dotenv
 *
 *  RUN LOCALLY:
 *    node backend.js
 *    (use `stripe listen --forward-to localhost:3000/webhook` to test webhooks)
 * ════════════════════════════════════════════════════════════
 */

'use strict';

require('dotenv').config();    // loads .env file locally; on production use dashboard env vars

const express = require('express');
const stripe  = require('stripe')(process.env.STRIPE_SECRET_KEY);
const twilio  = require('twilio')(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

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
        amount:        Math.round(amount),    // always integer cents
        currency:      currency || 'aud',
        description:   description || 'Flash Clean Booking',
        receipt_email: receipt_email || undefined,
        metadata:      metadata || {},        // stored on Stripe — useful for reconciliation
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
//  Called by the frontend AFTER client-side payment confirmation.
//  Sends the WhatsApp notification via Twilio.
//  ✅ FIX 1: Twilio credentials are env vars, never in the browser.
// ════════════════════════════════════════════════════════════
app.post('/notify', async (req, res) => {
  const { bookingData, paid, paymentId } = req.body;

  if (!bookingData || !bookingData['Name']) {
    return res.status(400).json({ error: 'Invalid booking data.' });
  }

  const b = bookingData;
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

  try {
    await twilio.messages.create({
      from: process.env.TWILIO_FROM,   // ✅ env var — never hardcoded
      to:   process.env.TWILIO_TO,     // ✅ env var — never hardcoded
      body: msg,
    });
    res.json({ sent: true });
  } catch (err) {
    console.error('[/notify] Twilio error:', err.code, err.message);
    // Non-fatal — booking is already logged in Google Sheets
    res.status(500).json({ error: 'Notification failed. Booking still recorded.' });
  }
});


// ════════════════════════════════════════════════════════════
//  POST /webhook  (registered above, before express.json())
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
    case 'payment_intent.succeeded': {
      const pi = event.data.object;
      console.log('[/webhook] ✅ Payment confirmed:', pi.id, '$' + pi.amount / 100);
      // ── HERE: mark the booking as confirmed in your database ──
      // e.g. await db.bookings.update({ stripeId: pi.id }, { status: 'confirmed' })
      break;
    }

    case 'payment_intent.payment_failed': {
      const pi = event.data.object;
      console.warn('[/webhook] ❌ Payment failed:', pi.id, pi.last_payment_error?.code);
      // ── HERE: notify customer / mark booking as failed ──
      break;
    }

    case 'charge.dispute.created': {
      // Alert on chargebacks
      console.error('[/webhook] ⚠️ Dispute created:', event.data.object.id);
      break;
    }

    default:
      // Unhandled event types — safe to ignore
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

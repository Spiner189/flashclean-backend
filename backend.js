/**
 * ════════════════════════════════════════════════════════════
 *  Flash Clean — Secure Payment Backend (v3 — Supabase mirror)
 *  Node.js + Express + PostgreSQL + Supabase
 * ════════════════════════════════════════════════════════════
 *
 *  CHANGES FROM v2:
 *  ────────────────────────────────────────────────────────────
 *   1. mirrorBookingToSupabase() — successful PaymentIntent
 *      bookings are now also written to Supabase public.bookings
 *      and public.jobs so the Flash Clean web app shows new
 *      bookings instantly. Idempotent on stripe_payment_intent.
 *   2. Triggered from runFulfilment() AFTER Sheets/email/WhatsApp
 *      already succeeded. Mirror failures are logged but never
 *      block the existing notification pipeline.
 *   3. processCheckoutSessionCompleted is now a SAFE STUB —
 *      Flash Clean uses PaymentIntents, not Checkout Sessions.
 *      The previous version was broken (would fail NOT-NULL
 *      constraints on public.jobs.id/title).
 *   4. ntfy push now includes real customer details (name,
 *      address, date/time, hrs, price, phone) instead of just
 *      the Stripe session ID.
 *   5. Customer SMS + branded email + Google Sheets row are
 *      ALSO triggered via the Supabase send-booking-notifications
 *      Edge Function (in addition to the existing Gmail +
 *      WhatsApp + Apps Script flow).
 *
 *  CHANGES FROM v1:
 *  ────────────────────────────────────────────────────────────
 *   (See git history — server-side pricing, Postgres replacing
 *    SQLite, anti-abuse on /notify, webhook fulfilment idempotency,
 *    parallelized notifications, dispute alerts.)
 *
 *  ENVIRONMENT VARIABLES — set in Railway dashboard:
 *
 *    DATABASE_URL             postgresql://... (auto-set by Railway Postgres)
 *    STRIPE_SECRET_KEY        sk_live_...
 *    STRIPE_WEBHOOK_SECRET    whsec_...
 *    TWILIO_ACCOUNT_SID       AC...
 *    TWILIO_AUTH_TOKEN        your-auth-token
 *    TWILIO_FROM              whatsapp:+15558072617
 *    TWILIO_TO                whatsapp:+61426365751
 *    ALLOWED_ORIGINS          https://flashclean.com.au,https://www.flashclean.com.au
 *    CAPTURE_SECRET_KEY       your-secret-password
 *    GOOGLE_PLACES_API_KEY    Google Places API key
 *    GOOGLE_PLACE_ID          Google Business Profile place id
 *    EMAIL_USER               your Gmail address
 *    EMAIL_PASS               Gmail App Password (or use Gmail API vars below)
 *    EMAIL_TO                 your business notification email
 *    SMTP_HOST / SMTP_PORT / SMTP_SECURE   optional overrides
 *    GMAIL_CLIENT_ID / GMAIL_CLIENT_SECRET / GMAIL_REFRESH_TOKEN  Gmail API alternative
 *    GOOGLE_SHEETS_WEB_APP_URL  Apps Script web app URL for booking rows
 *    STRICT_PRICING           "true" to reject requests without `pricing` object
 *    NOTIFY_FALLBACK_DELAY_MS optional (default 0; if >0, /notify also fulfils
 *                              after this delay if webhook hasn't yet)
 *
 *    --- Supabase mirror (required for web app sync) ---
 *    SUPABASE_URL             Supabase project URL — https://kkhblqdcigmepqfnmiol.supabase.co
 *    SUPABASE_SERVICE_ROLE_KEY service_role key (server only — never expose to clients)
 *    NTFY_TOPIC               ntfy topic name (POST to https://ntfy.sh/$NTFY_TOPIC)
 * ════════════════════════════════════════════════════════════
 */

'use strict';

require('dotenv').config();

const { createClient } = require('@supabase/supabase-js');
const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const { Pool }   = require('pg');
const stripe     = require('stripe')(process.env.STRIPE_SECRET_KEY);
const twilio     = require('twilio')(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
const nodemailer = require('nodemailer');
const { google } = require('googleapis');
const crypto     = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

app.disable('x-powered-by');
app.set('trust proxy', 1);

// ════════════════════════════════════════════════════════════
//  POSTGRES (persistent across Railway deploys)
// ════════════════════════════════════════════════════════════
if (!process.env.DATABASE_URL) {
  console.error('[fatal] DATABASE_URL not set. Connect Railway Postgres to this service.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Railway internal Postgres URLs use *.railway.internal — no SSL needed.
  // External URLs require SSL. Detect and configure accordingly.
  ssl: process.env.DATABASE_URL.includes('.railway.internal')
    ? false
    : { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
});

pool.on('error', (err) => {
  console.error('[pg] Unexpected error on idle client:', err.message);
});

async function initSchema() {
  // Idempotent — safe to run on every startup.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS bookings (
      payment_intent_id      TEXT PRIMARY KEY,
      booking_data           JSONB NOT NULL,
      computed_amount_cents  INTEGER NOT NULL,
      currency               TEXT NOT NULL DEFAULT 'aud',
      status                 TEXT NOT NULL DEFAULT 'pending',
      created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      fulfilled_at           TIMESTAMPTZ
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS processed_events (
      id          TEXT PRIMARY KEY,
      type        TEXT NOT NULL,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_bookings_status_created
    ON bookings (status, created_at DESC);
  `);
  console.log('[pg] ✅ Schema ready');
}

// ════════════════════════════════════════════════════════════
//  SUPABASE (Stripe Checkout → public.bookings / public.jobs)
//  Schema: see supabase-schema-stripe-checkout.sql
// ════════════════════════════════════════════════════════════
let supabaseAdmin = null;

function getSupabaseAdmin() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) return null;
  if (!supabaseAdmin) {
    supabaseAdmin = createClient(url, key, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
  }
  return supabaseAdmin;
}

/**
 * checkout.session.completed handler (SAFE STUB).
 *
 * Flash Clean uses Stripe PaymentIntents (not Checkout Sessions) — see
 * /create-payment-intent and runFulfilment. Booking persistence to Supabase
 * happens in mirrorBookingToSupabase() called from runFulfilment().
 *
 * If Stripe ever fires checkout.session.completed (e.g. you add a Checkout
 * Session flow in future), this stub logs and returns cleanly so we don't
 * crash. Do NOT add jobs.insert({}) or bookings.upsert() with empty payloads
 * here — those will fail the NOT-NULL constraints on public.jobs.id /
 * public.jobs.title and public.bookings.client / public.bookings.address.
 */
async function processCheckoutSessionCompleted(session) {
  const stripeSessionId = session?.id || 'unknown';
  console.warn(
    '[/webhook] checkout.session.completed received but Flash Clean uses PaymentIntents, not Checkout Sessions. ' +
    `Session ${stripeSessionId} ignored. The Supabase backup webhook will handle it if needed.`
  );
  // Do not throw — Stripe should not retry this event for our flow.
}

/**
 * Helper: clean phone number for Australian SMS format.
 */
function cleanPhoneAU(raw) {
  if (!raw) return '';
  const digits = String(raw).replace(/\D/g, '');
  if (digits.startsWith('61') && digits.length === 11) return '0' + digits.substring(2);
  if (digits.length === 9 && !digits.startsWith('0')) return '0' + digits;
  return digits;
}

/**
 * Helper: format date as "Thu Apr 23 2026" for jobs.date.
 */
function formatDayTitle(d) {
  return d.toDateString().replace(/\s(\d)/, ' $1');
}

/**
 * Helper: convert "2026-05-01" or "May 1, 2026" or similar to YYYY-MM-DD.
 * Returns null if unparseable.
 */
function toDayKey(rawDate) {
  if (!rawDate) return null;
  const s = String(rawDate).trim();
  // Already YYYY-MM-DD
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;
  const d = new Date(s);
  if (isNaN(d.getTime())) return null;
  // Format as YYYY-MM-DD in Sydney TZ
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd}`;
}

/**
 * Helper: parse "$295.50" → 29550 cents. Returns null if unparseable.
 */
function parsePriceToCents(rawPrice) {
  if (rawPrice == null) return null;
  const s = String(rawPrice).replace(/[^\d.]/g, '');
  if (!s) return null;
  const n = Number(s);
  if (!Number.isFinite(n)) return null;
  return Math.round(n * 100);
}

/**
 * Helper: derive estimated hours from service/beds/baths.
 * Adjust to match Flash Clean's actual pricing logic if needed.
 */
function estimateHours(b) {
  const beds = Number(b['Bedrooms']) || 1;
  const baths = Number(b['Bathrooms']) || 1;
  const service = String(b['Service'] || '').toLowerCase();
  let h = 2 + beds * 0.75 + baths * 0.5;
  if (service.includes('deep')) h *= 1.5;
  if (service.includes('move')) h *= 1.7;
  return Math.round(h * 2) / 2;
}

/**
 * Build extras array from bookingData flags (Yes/No keys).
 */
function buildExtrasArray(b) {
  const extras = [];
  if (String(b['Oven Cleaning'] || '').match(/^(yes|y|true)$/i)) extras.push('Inside oven');
  if (String(b['Fridge Cleaning'] || '').match(/^(yes|y|true)$/i)) extras.push('Inside fridge');
  if (String(b['Interior Windows'] || '').match(/^(yes|y|true)$/i)) extras.push('Interior windows');
  if (String(b['External Windows'] || '').match(/^(yes|y|true)$/i)) extras.push('External windows');
  if (String(b['Laundry/Ironing'] || '').match(/^(yes|y|true)$/i)) extras.push('Laundry/Ironing');
  if (String(b['Carpet Cleaning'] || '').match(/^(yes|y|true)$/i)) extras.push('Carpet cleaning');
  return extras;
}

/**
 * Map Flash Clean Frequency strings → standard freq values used in jobs table.
 */
function normalizeFreq(raw) {
  const s = String(raw || '').toLowerCase();
  if (s.includes('week') && !s.includes('fort') && !s.includes('two')) return 'Weekly';
  if (s.includes('fort') || s.includes('two')) return 'Fortnightly';
  if (s.includes('month')) return 'Monthly';
  return 'One Time';
}

/**
 * Mirror a successful booking to Supabase (public.bookings + public.jobs).
 *
 * Called from runFulfilment AFTER the Postgres claim succeeds. Idempotent on
 * stripe_payment_intent — re-running is safe.
 *
 * Returns { ok, bookingId, jobId, error } — never throws so it can't break
 * the existing Sheets/Email/WhatsApp pipeline.
 */
async function mirrorBookingToSupabase(bookingData, paymentIntentId, paymentIntent) {
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
    console.warn('[supabase-mirror] SUPABASE_* env not set — skipping mirror.');
    return { ok: false, error: 'supabase_not_configured' };
  }
  const sb = getSupabaseAdmin();
  if (!sb) return { ok: false, error: 'supabase_client_unavailable' };

  const b = bookingData || {};
  const priceCents = paymentIntent?.amount || parsePriceToCents(b['Est. Price']) || 0;
  const dayKey = toDayKey(b['Pref. Date']);
  const freq = normalizeFreq(b['Frequency']);
  const extras = buildExtrasArray(b);
  const hrs = estimateHours(b);
  const phoneClean = cleanPhoneAU(b['Phone']);

  // 1) Idempotency check — has this PaymentIntent already been mirrored?
  try {
    const { data: existing } = await sb
      .from('bookings')
      .select('id, job_id')
      .eq('stripe_payment_intent', paymentIntentId)
      .maybeSingle();

    if (existing?.job_id) {
      console.log(`[supabase-mirror] Already mirrored ${paymentIntentId} → job ${existing.job_id}, skipping.`);
      return { ok: true, bookingId: existing.id, jobId: existing.job_id, alreadyMirrored: true };
    }
  } catch (err) {
    console.error('[supabase-mirror] Idempotency check failed:', err.message);
    // Continue anyway — upsert below handles duplicates.
  }

  // 2) Insert/update bookings row
  const bookingRow = {
    client: b['Name'] || 'Unknown',
    phone: phoneClean,
    email: b['Email'] || '',
    address: b['Address'] || 'Address not provided',
    requested_date: dayKey,
    requested_time: b['Pref. Time'] || '9:00 AM',
    hrs: hrs,
    freq: freq,
    bedrooms: Number(b['Bedrooms']) || null,
    bathrooms: Number(b['Bathrooms']) || null,
    property_type: b['Service'] || 'Residential',
    extras: extras,
    instructions: b['Special Notes'] || null,
    price_cents: priceCents,
    currency: paymentIntent?.currency || 'aud',
    stripe_payment_intent: paymentIntentId,
    payment_status: 'paid',
    paid_at: new Date().toISOString(),
    source: 'railway-primary',
    raw_payload: { paymentIntent, bookingData: b },
  };

  let supabaseBookingId = null;
  try {
    const { data: bookingInsert, error: bookErr } = await sb
      .from('bookings')
      .insert(bookingRow)
      .select('id')
      .single();
    if (bookErr) {
      console.error('[supabase-mirror] bookings insert failed:', bookErr.message, bookErr);
      return { ok: false, error: 'bookings_insert_failed: ' + bookErr.message };
    }
    supabaseBookingId = bookingInsert.id;
  } catch (err) {
    console.error('[supabase-mirror] bookings insert exception:', err.message);
    return { ok: false, error: err.message };
  }

  // 3) Create the job row in public.jobs
  const jobId = 'AUTO-' + crypto.randomUUID().replace(/-/g, '');
  const dateObj = dayKey ? new Date(dayKey + 'T00:00:00+10:00') : new Date();
  const dollarPrice = '$' + (priceCents / 100).toFixed(2).replace(/\.00$/, '');
  const accessText = b['Home Access'] || '';
  const instructionsText = b['Special Notes'] || '';

  try {
    const { error: jobErr } = await sb.from('jobs').insert({
      id: jobId,
      title: 'HOME CLEANING',
      date: formatDayTitle(dateObj),
      day_key: dayKey,
      time: b['Pref. Time'] || '9:00 AM',
      freq: freq,
      hrs: hrs,
      price: dollarPrice,
      price_cents: priceCents,
      client: b['Name'] || 'Unknown',
      phone: phoneClean,
      email: b['Email'] || '',
      address: b['Address'] || 'Address not provided',
      access: accessText,
      extras: extras,
      payment: 'paid (stripe)',
      special_req: false,
      team: [],
      property_type: b['Service'] || 'Residential',
      bedrooms: Number(b['Bedrooms']) || null,
      bathrooms: Number(b['Bathrooms']) || null,
      instructions: instructionsText,
      description:
        `New website booking\n` +
        `Frequency: ${freq} · ${hrs} hrs · ${dollarPrice} · Paid via Stripe`,
      status: 'pending',
      reminder_sent: false,
    });

    if (jobErr) {
      console.error('[supabase-mirror] jobs insert failed:', jobErr.message, jobErr);
      // Save error on booking for debugging — don't lose the booking.
      await sb.from('bookings').update({ notes: 'job_creation_failed: ' + jobErr.message }).eq('id', supabaseBookingId);
      return { ok: false, bookingId: supabaseBookingId, error: 'jobs_insert_failed: ' + jobErr.message };
    }
  } catch (err) {
    console.error('[supabase-mirror] jobs insert exception:', err.message);
    await sb.from('bookings').update({ notes: 'job_creation_exception: ' + err.message }).eq('id', supabaseBookingId);
    return { ok: false, bookingId: supabaseBookingId, error: err.message };
  }

  // 4) Link booking → job
  try {
    await sb
      .from('bookings')
      .update({ job_id: jobId, job_created_at: new Date().toISOString() })
      .eq('id', supabaseBookingId);
  } catch (err) {
    console.error('[supabase-mirror] booking↔job link failed:', err.message);
    // Not fatal — booking and job both exist, just unlinked.
  }

  // 5) Fire-and-forget: customer SMS + branded email + Google Sheets via Supabase function
  try {
    fetch(`${process.env.SUPABASE_URL}/functions/v1/send-booking-notifications`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ booking_id: supabaseBookingId }),
    }).catch((err) => console.error('[supabase-mirror] notifications fire failed (non-fatal):', err.message));
  } catch (_) { /* swallow */ }

  // 6) ntfy push to Patrick with rich detail (replaces the old "Stripe session: ..." message)
  const topic = String(process.env.NTFY_TOPIC || '').trim();
  if (topic) {
    const ntfyBody = [
      `💰 New paid booking: ${b['Name'] || 'Unknown'}`,
      `📅 ${b['Pref. Date'] || dayKey || 'TBD'} at ${b['Pref. Time'] || 'TBD'}`,
      `📍 ${b['Address'] || ''}`,
      `⏱️ ${hrs}h · ${dollarPrice} ${freq.toLowerCase()}`,
      `📞 ${phoneClean}`,
    ].join('\n');
    try {
      await fetch(`https://ntfy.sh/${encodeURIComponent(topic)}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'Title': '💰 New Flash Clean Booking',
          'Priority': '4',
          'Tags': 'money,calendar',
        },
        body: ntfyBody,
      });
    } catch (err) {
      console.error('[supabase-mirror] ntfy push failed (non-fatal):', err.message);
    }
  }

  console.log(`[supabase-mirror] ✅ ${paymentIntentId} → booking ${supabaseBookingId}, job ${jobId}`);
  return { ok: true, bookingId: supabaseBookingId, jobId };
}

// ════════════════════════════════════════════════════════════
//  PRICING (server-side — single source of truth)
//  Replicates the frontend rules in index.html exactly.
//  Any change here must be mirrored in the frontend, and vice
//  versa, or customers see a different price than they pay.
// ════════════════════════════════════════════════════════════
const BASE_PRICES   = { house: 95, apartment: 95, deep: 220, carpet: 0, move: 360, airbnb: 95, office: 0, construction: 0, recurring: 95 };
const BED_EXTRA     = { house: 50, apartment: 50, deep: 55,  carpet: 0, move: 60,  airbnb: 30, office: 0, construction: 0, recurring: 47 };
const BATH_EXTRA    = { house: 25, apartment: 25, deep: 35,  carpet: 0, move: 60,  airbnb: 20, office: 0, construction: 0, recurring: 24 };
const FREQ_DISCOUNT = { once: 1, weekly: 0.85, fortnightly: 0.95, monthly: 1 };

const ADDON_FLAT = {
  oven:    60,
  fridge:  40,
  laundry: 35,
  balcony: 45,
  garage:  65,
  walls:   85,
  party:   120,
};

function clampInt(value, min, max, fallback = min) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

function calcCarpet(carpet) {
  if (!carpet || typeof carpet !== 'object') return 0;
  const beds = clampInt(carpet.bed, 1, 10, 1);
  const living = clampInt(carpet.living, 0, 10, 0); // 0 means not selected
  const hallway = !!carpet.hallway;
  const bedPrice = 90 + (beds - 1) * 45;
  const livingPrice = living > 0 ? living * 45 : 0;
  const hallwayPrice = hallway ? 35 : 0;
  return bedPrice + livingPrice + hallwayPrice;
}

/**
 * Calculate total in cents from pricing inputs.
 * Returns { totalCents, breakdown } or { error } on invalid input.
 */
function calculatePriceCents(pricing) {
  if (!pricing || typeof pricing !== 'object') {
    return { error: 'Missing pricing object.' };
  }

  const service = String(pricing.service || '').toLowerCase();
  const frequency = String(pricing.frequency || 'once').toLowerCase();

  if (!(service in BASE_PRICES)) {
    return { error: `Unknown service: ${service}` };
  }
  if (!(frequency in FREQ_DISCOUNT)) {
    return { error: `Unknown frequency: ${frequency}` };
  }

  const beds = clampInt(pricing.beds, 1, 6, 1);
  const baths = clampInt(pricing.baths, 1, 6, 1);
  const extras = (pricing.extras && typeof pricing.extras === 'object') ? pricing.extras : {};

  const base = BASE_PRICES[service];
  const bedDelta = (beds - 1) * BED_EXTRA[service];
  const bathDelta = (baths - 1) * BATH_EXTRA[service];
  const discount = FREQ_DISCOUNT[frequency];
  const baseTotal = Math.round((base + bedDelta + bathDelta) * discount);

  // Extras (no discount applied).
  let extrasTotal = 0;
  if (extras.oven)    extrasTotal += ADDON_FLAT.oven;
  if (extras.fridge)  extrasTotal += ADDON_FLAT.fridge;
  if (extras.laundry) extrasTotal += ADDON_FLAT.laundry;
  if (extras.balcony) extrasTotal += ADDON_FLAT.balcony;
  if (extras.garage)  extrasTotal += ADDON_FLAT.garage;
  if (extras.walls)   extrasTotal += ADDON_FLAT.walls;
  if (extras.party)   extrasTotal += ADDON_FLAT.party;

  const winInt  = clampInt(extras.windows_int, 0, 20, 0);
  const winExt  = clampInt(extras.windows_ext, 0, 20, 0);
  const blinds  = clampInt(extras.blinds, 0, 20, 0);
  if (winInt > 0) extrasTotal += winInt * 45;
  if (winExt > 0) extrasTotal += winExt * 45;
  if (blinds > 0) extrasTotal += blinds * 45;

  if (extras.carpet) extrasTotal += calcCarpet(extras.carpet);

  const totalDollars = baseTotal + extrasTotal;
  const totalCents = totalDollars * 100;

  return {
    totalCents,
    breakdown: { base: baseTotal, extras: extrasTotal, total: totalDollars, discount },
  };
}

// ════════════════════════════════════════════════════════════
//  MIDDLEWARE
// ════════════════════════════════════════════════════════════
app.use(helmet({ contentSecurityPolicy: false }));

function getAllowedOrigins() {
  const list = (process.env.ALLOWED_ORIGINS || process.env.ALLOWED_ORIGIN ||
    'https://flashclean.com.au,https://www.flashclean.com.au')
    .split(',').map(s => s.trim()).filter(Boolean);
  return new Set(list);
}
const allowedOrigins = getAllowedOrigins();

const apiLimiter = rateLimit({
  windowMs: 60 * 1000, limit: 120,
  standardHeaders: true, legacyHeaders: false,
});

const sensitiveLimiter = rateLimit({
  windowMs: 60 * 1000, limit: 20,
  standardHeaders: true, legacyHeaders: false,
});

// NEW: tighter limit for payment intent creation specifically.
const paymentIntentLimiter = rateLimit({
  windowMs: 60 * 1000, limit: 8,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many payment attempts. Please wait a minute.' },
});

function constantTimeEquals(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function requireAdminKey(req, res, next) {
  const key = req.get('x-capture-key');
  if (!process.env.CAPTURE_SECRET_KEY) return res.status(500).json({ error: 'Server misconfigured.' });
  if (!constantTimeEquals(key, process.env.CAPTURE_SECRET_KEY)) return res.status(401).json({ error: 'Unauthorized.' });
  next();
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}

// ── EMAIL (unchanged from v1) ────────────────────────────────
const dns = require('dns');
dns.setDefaultResultOrder('ipv4first');

const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = Number(process.env.SMTP_PORT || 465);
const SMTP_SECURE = process.env.SMTP_SECURE
  ? process.env.SMTP_SECURE === 'true'
  : SMTP_PORT === 465;

let transporter;
function buildTransporter(host) {
  return nodemailer.createTransport({
    host, port: SMTP_PORT, secure: SMTP_SECURE,
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    tls: { servername: SMTP_HOST, family: 4 },
    family: 4,
    connectionTimeout: 15_000, greetingTimeout: 15_000, socketTimeout: 20_000,
  });
}
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

function hasGmailApiConfig() {
  return Boolean(
    process.env.GMAIL_CLIENT_ID && process.env.GMAIL_CLIENT_SECRET &&
    process.env.GMAIL_REFRESH_TOKEN && process.env.EMAIL_USER
  );
}

async function sendEmailViaGmailApi({ from, to, subject, html }) {
  const oauth2Client = new google.auth.OAuth2(
    process.env.GMAIL_CLIENT_ID, process.env.GMAIL_CLIENT_SECRET
  );
  oauth2Client.setCredentials({ refresh_token: process.env.GMAIL_REFRESH_TOKEN });
  const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
  const mime =
    `From: ${from}\r\nTo: ${to}\r\nSubject: ${subject}\r\n` +
    `MIME-Version: 1.0\r\nContent-Type: text/html; charset="UTF-8"\r\n` +
    `Content-Transfer-Encoding: 7bit\r\n\r\n${html}`;
  const raw = Buffer.from(mime).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  await gmail.users.messages.send({ userId: 'me', requestBody: { raw } });
}

async function sendMail(message) {
  if (hasGmailApiConfig()) { await sendEmailViaGmailApi(message); return; }
  await transporter.sendMail(message);
}

if (hasGmailApiConfig()) {
  console.log('[email] Using Gmail API transport for:', process.env.EMAIL_USER);
}

// ── CORS ─────────────────────────────────────────────────────
const corsMiddleware = cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.has(origin)) return callback(null, true);
    // Cleaner rejection — actually surfaces an error rather than silent no-headers.
    callback(new Error(`Origin ${origin} not allowed by CORS`));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Stripe-Signature', 'X-Capture-Key'],
  maxAge: 86400,
});
app.use(corsMiddleware);
app.options('*', corsMiddleware);

app.use(apiLimiter);

// ── WEBHOOK must use raw body BEFORE express.json() ──────────
app.post('/webhook', express.raw({ type: 'application/json', limit: '1mb' }), handleWebhook);

// ── JSON body parser for everything else ─────────────────────
app.use(express.json({ limit: '50kb' }));

// ════════════════════════════════════════════════════════════
//  HEALTH CHECKS
// ════════════════════════════════════════════════════════════
app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.get('/health/deep', sensitiveLimiter, requireAdminKey, async (req, res) => {
  const checks = {
    stripe_secret_key: Boolean(process.env.STRIPE_SECRET_KEY),
    stripe_webhook_secret: Boolean(process.env.STRIPE_WEBHOOK_SECRET),
    database_url: Boolean(process.env.DATABASE_URL),
    twilio_configured: Boolean(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN),
    email_configured: Boolean(process.env.EMAIL_USER && (process.env.EMAIL_PASS || hasGmailApiConfig())),
    allowed_origins: Array.from(allowedOrigins),
    strict_pricing: process.env.STRICT_PRICING === 'true',
    stripe_api: 'unchecked', postgres: 'unchecked',
  };

  if (checks.stripe_secret_key) {
    try { await stripe.paymentMethods.list({ limit: 1 }); checks.stripe_api = 'ok'; }
    catch (err) { checks.stripe_api = `fail: ${err.type || 'unknown'}`; }
  }

  try { await pool.query('SELECT 1'); checks.postgres = 'ok'; }
  catch (err) { checks.postgres = `fail: ${err.message}`; }

  const healthy = checks.stripe_api === 'ok' && checks.postgres === 'ok' &&
                  checks.stripe_secret_key && checks.stripe_webhook_secret;
  res.status(healthy ? 200 : 503).json({ status: healthy ? 'ok' : 'degraded', checks });
});

// Admin: list bookings paid but never fulfilled (catches webhook config issues).
app.get('/admin/unfulfilled', sensitiveLimiter, requireAdminKey, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT payment_intent_id, computed_amount_cents, status, created_at,
             booking_data->>'Name' AS name, booking_data->>'Email' AS email
        FROM bookings
       WHERE status = 'pending'
         AND created_at < NOW() - INTERVAL '5 minutes'
       ORDER BY created_at DESC
       LIMIT 100;
    `);
    res.json({ count: rows.length, bookings: rows });
  } catch (err) {
    console.error('[/admin/unfulfilled]', err.message);
    res.status(500).json({ error: 'Database error.' });
  }
});

// ════════════════════════════════════════════════════════════
//  GOOGLE REVIEWS (unchanged)
// ════════════════════════════════════════════════════════════
const googleReviewsCache = { expiresAt: 0, data: null };

app.get('/google-reviews', apiLimiter, async (req, res) => {
  try {
    const now = Date.now();
    if (googleReviewsCache.data && googleReviewsCache.expiresAt > now) {
      return res.json(googleReviewsCache.data);
    }
    const key = process.env.GOOGLE_PLACES_API_KEY;
    const placeId = process.env.GOOGLE_PLACE_ID;
    if (!key || !placeId) return res.status(503).json({ error: 'Google reviews unavailable.' });

    const url = `https://places.googleapis.com/v1/places/${encodeURIComponent(placeId)}?fields=displayName,rating,userRatingCount,reviews&key=${encodeURIComponent(key)}`;
    const apiRes = await fetch(url);
    if (!apiRes.ok) {
      const body = await apiRes.text();
      console.warn('[/google-reviews] Google API error:', apiRes.status, body.slice(0, 300));
      return res.status(502).json({ error: 'Google reviews fetch failed.' });
    }
    const place = await apiRes.json();
    const reviews = Array.isArray(place.reviews) ? place.reviews : [];
    const payload = {
      source: 'google',
      placeName: place.displayName?.text || 'Flash Clean',
      rating: Number(place.rating || 0),
      userRatingCount: Number(place.userRatingCount || 0),
      reviews: reviews.slice(0, 6).map((r) => ({
        authorName: r.authorAttribution?.displayName || 'Google user',
        rating: Number(r.rating || 5),
        relativeTime: r.relativePublishTimeDescription || '',
        text: r.text?.text || '',
      })),
      updatedAt: new Date().toISOString(),
    };
    googleReviewsCache.data = payload;
    googleReviewsCache.expiresAt = now + (15 * 60 * 1000);
    res.json(payload);
  } catch (err) {
    console.error('[/google-reviews]', err?.message || err);
    res.status(500).json({ error: 'Google reviews unavailable.' });
  }
});

// ════════════════════════════════════════════════════════════
//  POST /create-payment-intent
//  Now: server-side price calculation + booking persistence.
// ════════════════════════════════════════════════════════════
app.post('/create-payment-intent', paymentIntentLimiter, async (req, res) => {
  const { amount, currency, description, receipt_email, metadata, idempotencyKey, pricing, bookingData } = req.body;

  let amountCents;
  let priceBreakdown = null;

  // ── Server-side price calculation ─────────────────────────
  if (pricing) {
    const calc = calculatePriceCents(pricing);
    if (calc.error) {
      console.warn('[/create-payment-intent] Price calc failed:', calc.error);
      return res.status(400).json({ error: 'Invalid booking inputs.' });
    }
    amountCents = calc.totalCents;
    priceBreakdown = calc.breakdown;

    // Cross-check against client-provided amount; warn on mismatch.
    if (Number.isFinite(Number(amount))) {
      const clientCents = Math.round(Number(amount));
      if (clientCents !== amountCents) {
        console.warn(
          `[/create-payment-intent] ⚠️  Client/server price mismatch: client=${clientCents}c server=${amountCents}c ` +
          `(service=${pricing.service}, freq=${pricing.frequency}, beds=${pricing.beds}, baths=${pricing.baths}). ` +
          `Using server price.`
        );
      }
    }
  } else {
    // Backward compat: no pricing object provided.
    if (process.env.STRICT_PRICING === 'true') {
      return res.status(400).json({ error: 'pricing object required.' });
    }
    console.warn('[/create-payment-intent] ⚠️  No pricing object — falling back to client amount. Update frontend ASAP.');
    const n = Number(amount);
    if (!Number.isFinite(n) || !Number.isInteger(n) || n < 50 || n > 500000) {
      return res.status(400).json({ error: 'Invalid amount.' });
    }
    amountCents = n;
  }

  // Final safety bounds (covers both paths).
  if (amountCents < 50 || amountCents > 500000) {
    return res.status(400).json({ error: 'Computed amount out of allowed range.' });
  }

  try {
    const paymentIntent = await stripe.paymentIntents.create(
      {
        amount: amountCents,
        currency: (currency || 'aud').toLowerCase(),
        description: typeof description === 'string' ? description.slice(0, 500) : 'Flash Clean Booking',
        receipt_email: receipt_email || undefined,
        metadata: {
          // Keep small — Stripe metadata limits.
          ...(metadata && typeof metadata === 'object' ? metadata : {}),
          server_calculated: priceBreakdown ? 'true' : 'false',
          backend_version: 'v2',
        },
        capture_method: 'manual',
      },
      { idempotencyKey: typeof idempotencyKey === 'string' ? idempotencyKey : undefined }
    );

    // Persist booking — webhook will look this up to send notifications.
    if (bookingData && typeof bookingData === 'object') {
      try {
        await pool.query(
          `INSERT INTO bookings (payment_intent_id, booking_data, computed_amount_cents, currency)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (payment_intent_id) DO UPDATE
             SET booking_data = EXCLUDED.booking_data,
                 computed_amount_cents = EXCLUDED.computed_amount_cents`,
          [paymentIntent.id, bookingData, amountCents, (currency || 'aud').toLowerCase()]
        );
      } catch (dbErr) {
        // DB failure shouldn't block the payment — but log loudly.
        console.error('[/create-payment-intent] ⚠️  Booking persist failed:', dbErr.message);
      }
    } else {
      console.warn('[/create-payment-intent] ⚠️  No bookingData provided — webhook will have nothing to fulfil.');
    }

    res.json({
      clientSecret: paymentIntent.client_secret,
      // Optional: return server-calculated price so frontend can display authoritative amount.
      ...(priceBreakdown ? { breakdown: priceBreakdown } : {}),
    });
  } catch (err) {
    console.error('[/create-payment-intent]', err.type, err.code, err.message);
    res.status(500).json({ error: 'Payment service unavailable. Please try again.' });
  }
});

// ════════════════════════════════════════════════════════════
//  GOOGLE SHEETS APPEND (used by webhook)
// ════════════════════════════════════════════════════════════
const DEFAULT_GOOGLE_SHEETS_WEB_APP_URL =
  'https://script.google.com/macros/s/AKfycbw_ZMgrew77YklXFUt5TjfiPfNv_t8KDAGaIaIty77y4IhYEeypV6jYzbw3lifoqsaGRg/exec';

async function appendBookingToGoogleSheets(bookingRow) {
  const url = process.env.GOOGLE_SHEETS_WEB_APP_URL || DEFAULT_GOOGLE_SHEETS_WEB_APP_URL;
  try {
    const r = await fetch(url, {
      method: 'POST', redirect: 'follow',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(bookingRow),
    });
    const text = await r.text();
    if (!r.ok) {
      console.warn('[sheets] HTTP', r.status, text.slice(0, 400));
      return false;
    }
    console.log('[sheets] ✅ Row appended:', text.slice(0, 200));
    return true;
  } catch (err) {
    console.error('[sheets] error:', err.message);
    return false;
  }
}

// ════════════════════════════════════════════════════════════
//  FULFILMENT (called from webhook handler — single source of truth)
// ════════════════════════════════════════════════════════════
function buildWhatsAppMessage(b, paid, paymentIntentId, verifiedStatus) {
  return (
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
    '🔑 Access: '    + (b['Home Access'] || '')
  );
}

function buildCustomerEmail(b) {
  return {
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
}

function buildBusinessEmail(b, paid, paymentIntentId, verifiedStatus, verifiedCurrency, verifiedAmountCents) {
  return {
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
}

/**
 * Send all notifications for a booking. Returns results object.
 * Called by the webhook handler. Idempotency is enforced upstream.
 */
async function sendAllNotifications(bookingData, paymentIntentId, paymentIntent) {
  const b = bookingData;
  const verifiedStatus = paymentIntent?.status || 'unknown';
  const paid = ['requires_capture', 'succeeded', 'processing'].includes(verifiedStatus);

  const sheetRow = {
    ...b,
    'Payment Status': paid ? '✅ PAID via Stripe' : 'Pending',
    'Payment ID': paymentIntentId || '',
  };

  const whatsappBody = buildWhatsAppMessage(b, paid, paymentIntentId, verifiedStatus);
  const customerEmail = buildCustomerEmail(b);
  const businessEmail = buildBusinessEmail(
    b, paid, paymentIntentId, verifiedStatus,
    paymentIntent?.currency, paymentIntent?.amount
  );

  // Run all four in parallel — failures don't block each other.
  const [sheets, whatsapp, custEmail, bizEmail] = await Promise.allSettled([
    appendBookingToGoogleSheets(sheetRow),
    twilio.messages.create({ from: process.env.TWILIO_FROM, to: process.env.TWILIO_TO, body: whatsappBody }),
    sendMail(customerEmail),
    sendMail(businessEmail),
  ]);

  const results = {
    sheets:        sheets.status === 'fulfilled' && sheets.value === true,
    whatsapp:      whatsapp.status === 'fulfilled',
    customerEmail: custEmail.status === 'fulfilled',
    businessEmail: bizEmail.status === 'fulfilled',
  };

  if (sheets.status === 'rejected')   console.error('[fulfil] sheets:', sheets.reason?.message);
  if (whatsapp.status === 'rejected') console.error('[fulfil] whatsapp:', whatsapp.reason?.message);
  if (custEmail.status === 'rejected')console.error('[fulfil] customer email:', custEmail.reason?.message);
  if (bizEmail.status === 'rejected') console.error('[fulfil] business email:', bizEmail.reason?.message);

  return results;
}

// ════════════════════════════════════════════════════════════
//  POST /notify  (now: success ping with PI verification)
//  Returns 200 fast; webhook handles fulfilment.
// ════════════════════════════════════════════════════════════
app.post('/notify', async (req, res) => {
  const { paymentIntentId } = req.body;

  // SECURITY: must be a real PI from our Stripe account.
  if (!paymentIntentId || typeof paymentIntentId !== 'string' || !paymentIntentId.startsWith('pi_')) {
    return res.status(400).json({ error: 'paymentIntentId required.' });
  }

  let pi;
  try {
    pi = await stripe.paymentIntents.retrieve(paymentIntentId);
  } catch (err) {
    console.warn('[/notify] PI retrieve failed:', err.message);
    return res.status(400).json({ error: 'Invalid paymentIntentId.' });
  }

  const paid = ['requires_capture', 'succeeded', 'processing'].includes(pi.status);
  if (!paid) {
    return res.status(400).json({ error: `Payment not authorised (status: ${pi.status}).` });
  }

  // Optional fallback: if NOTIFY_FALLBACK_DELAY_MS is set, poll the DB after that
  // delay and run fulfilment if the webhook hasn't yet. Default off (0) so we trust
  // the webhook completely. Set to e.g. 30000 to enable a 30-second safety net.
  const fallbackMs = Number(process.env.NOTIFY_FALLBACK_DELAY_MS || 0);
  if (fallbackMs > 0) {
    setTimeout(async () => {
      try {
        const { rows } = await pool.query(
          'SELECT status, booking_data FROM bookings WHERE payment_intent_id = $1',
          [paymentIntentId]
        );
        if (rows[0] && rows[0].status === 'pending') {
          console.warn(`[/notify] Webhook didn't fulfil ${paymentIntentId} within ${fallbackMs}ms — triggering fallback.`);
          // Re-fetch PI for fresh status.
          const freshPi = await stripe.paymentIntents.retrieve(paymentIntentId);
          await runFulfilment(paymentIntentId, freshPi, `manual_fallback_${paymentIntentId}`);
        }
      } catch (err) {
        console.error('[/notify] Fallback check failed:', err.message);
      }
    }, fallbackMs).unref();
  }

  res.json({ received: true, status: pi.status });
});

// ════════════════════════════════════════════════════════════
//  ADMIN: capture, partial capture, cancel, charge extra
//  (unchanged from v1)
// ════════════════════════════════════════════════════════════
app.post('/capture', sensitiveLimiter, requireAdminKey, async (req, res) => {
  const { paymentIntentId } = req.body;
  if (!paymentIntentId) return res.status(400).json({ error: 'Missing paymentIntentId.' });
  try {
    const pi = await stripe.paymentIntents.capture(paymentIntentId);
    console.log('[/capture] ✅ Captured:', pi.id, '$' + pi.amount / 100);
    res.json({ captured: true, amount: pi.amount / 100, id: pi.id });
  } catch (err) {
    console.error('[/capture]', err.message);
    res.status(500).json({ error: 'Capture failed. ' + err.message });
  }
});

app.post('/capture-with-amount', sensitiveLimiter, requireAdminKey, async (req, res) => {
  const { paymentIntentId, amountCents } = req.body;
  if (!paymentIntentId || !amountCents) return res.status(400).json({ error: 'Missing fields.' });
  try {
    await stripe.paymentIntents.update(paymentIntentId, { amount: Math.round(amountCents) });
    const pi = await stripe.paymentIntents.capture(paymentIntentId);
    console.log('[/capture-with-amount] ✅ Captured:', pi.id, '$' + pi.amount / 100);
    res.json({ captured: true, amount: pi.amount / 100, id: pi.id });
  } catch (err) {
    console.error('[/capture-with-amount]', err.message);
    res.status(500).json({ error: 'Capture failed. ' + err.message });
  }
});

app.post('/cancel-authorization', sensitiveLimiter, requireAdminKey, async (req, res) => {
  const { paymentIntentId } = req.body;
  try {
    const pi = await stripe.paymentIntents.cancel(paymentIntentId);
    console.log('[/cancel-auth] ✅ Cancelled:', pi.id);
    res.json({ cancelled: true, id: pi.id });
  } catch (err) {
    console.error('[/cancel-auth]', err.message);
    res.status(500).json({ error: 'Cancellation failed. ' + err.message });
  }
});

app.post('/charge-extra', sensitiveLimiter, requireAdminKey, async (req, res) => {
  const { originalPaymentIntentId, extraAmountCents, description } = req.body;
  if (!originalPaymentIntentId || !extraAmountCents) return res.status(400).json({ error: 'Missing fields.' });
  try {
    const original = await stripe.paymentIntents.retrieve(originalPaymentIntentId);
    if (!original.payment_method) return res.status(400).json({ error: 'No payment method found.' });
    const extra = await stripe.paymentIntents.create({
      amount: Math.round(extraAmountCents),
      currency: original.currency || 'aud',
      payment_method: original.payment_method,
      description: description || 'Flash Clean — Extra charge',
      receipt_email: original.receipt_email || undefined,
      confirm: true, off_session: true, capture_method: 'automatic',
      metadata: { original_payment_intent: originalPaymentIntentId, type: 'extra_charge' },
    });
    console.log('[/charge-extra] ✅', extra.id, '$' + extra.amount / 100);
    res.json({ charged: true, id: extra.id, amount: extra.amount / 100, status: extra.status });
  } catch (err) {
    console.error('[/charge-extra]', err.message);
    if (err.code === 'authentication_required') return res.status(402).json({ error: 'Card requires authentication.' });
    if (err.code === 'card_declined') return res.status(402).json({ error: 'Card declined.' });
    res.status(500).json({ error: 'Extra charge failed. ' + err.message });
  }
});

// ════════════════════════════════════════════════════════════
//  WEBHOOK — source of truth for fulfilment
// ════════════════════════════════════════════════════════════
async function handleWebhook(req, res) {
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
  } catch (err) {
    console.warn('[/webhook] Signature failed:', err.message);
    return res.status(400).send('Webhook error');
  }

  // Idempotency: check if we've already processed this event.
  try {
    const dup = await pool.query('SELECT id FROM processed_events WHERE id = $1', [event.id]);
    if (dup.rows.length > 0) {
      console.log('[/webhook] Duplicate event ignored:', event.id, event.type);
      return res.json({ received: true, duplicate: true });
    }
  } catch (dbErr) {
    console.error('[/webhook] DB error checking idempotency:', dbErr.message);
    // Fail closed — Stripe will retry.
    return res.status(500).send('Webhook storage error');
  }

  // Process FIRST, then mark as processed only on success.
  try {
    await processWebhookEvent(event);
  } catch (err) {
    console.error('[/webhook] Handler error for', event.id, event.type, ':', err.message);
    // Don't insert into processed_events — Stripe will retry.
    return res.status(500).send('Handler error — will retry');
  }

  // Mark as processed only after successful handling.
  try {
    await pool.query(
      'INSERT INTO processed_events (id, type) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING',
      [event.id, event.type]
    );
  } catch (dbErr) {
    // If we got here, handler succeeded but mark-as-processed failed.
    // Worst case: Stripe retries → idempotency check passes → handler runs again.
    // The downstream sends (Sheets/email/WhatsApp) are individually idempotent at the
    // booking level (status='fulfilled' check inside runFulfilment), so duplicates
    // are still avoided. Log loudly anyway.
    console.error('[/webhook] ⚠️  Handler succeeded but mark-as-processed failed:', dbErr.message);
  }

  res.json({ received: true });
}

async function processWebhookEvent(event) {
  const type = event.type;

  switch (type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      // Flash Clean uses PaymentIntents, not Checkout Sessions.
      // The stub will log a warning. The Supabase backup webhook
      // (separate URL) will handle this event if you ever add a
      // Checkout flow. See processCheckoutSessionCompleted comments.
      await processCheckoutSessionCompleted(session);
      break;
    }
    case 'payment_intent.amount_capturable_updated': {
      const pi = event.data.object;
      console.log('[/webhook] 🔒 Card authorised:', pi.id, '$' + pi.amount / 100);
      // This is the trigger for fulfilment under capture_method=manual.
      await runFulfilment(pi.id, pi, event.id);
      break;
    }
    case 'payment_intent.succeeded': {
      const pi = event.data.object;
      console.log('[/webhook] ✅ Payment captured:', pi.id, '$' + pi.amount / 100);
      // For automatic capture flows or as a backup if amount_capturable_updated was missed.
      await runFulfilment(pi.id, pi, event.id);
      break;
    }
    case 'payment_intent.payment_failed': {
      const pi = event.data.object;
      console.warn('[/webhook] ❌ Payment failed:', pi.id, pi.last_payment_error?.code);
      await pool.query(
        `UPDATE bookings SET status = 'failed' WHERE payment_intent_id = $1 AND status = 'pending'`,
        [pi.id]
      );
      break;
    }
    case 'payment_intent.canceled': {
      const pi = event.data.object;
      console.log('[/webhook] 🚫 Cancelled:', pi.id);
      await pool.query(
        `UPDATE bookings SET status = 'cancelled' WHERE payment_intent_id = $1`,
        [pi.id]
      );
      break;
    }
    case 'charge.dispute.created': {
      const dispute = event.data.object;
      console.warn('[/webhook] ⚠️  DISPUTE CREATED:', dispute.id, dispute.reason, '$' + dispute.amount / 100);
      // Fire WhatsApp alert immediately.
      try {
        await twilio.messages.create({
          from: process.env.TWILIO_FROM, to: process.env.TWILIO_TO,
          body: `⚠️ STRIPE DISPUTE\n\nID: ${dispute.id}\nAmount: $${(dispute.amount / 100).toFixed(2)}\nReason: ${dispute.reason}\nStatus: ${dispute.status}\n\nLog into Stripe dashboard to respond.`,
        });
      } catch (err) {
        console.error('[/webhook] Dispute alert WhatsApp failed:', err.message);
      }
      break;
    }
    default:
      // Unhandled event types are still acknowledged.
      break;
  }
}

/**
 * Runs the actual fulfilment (sheets + emails + WhatsApp) for a booking.
 * Atomically marks the booking as fulfilled so concurrent calls (e.g. webhook
 * + /notify fallback) don't double-send.
 */
async function runFulfilment(paymentIntentId, paymentIntent, eventId) {
  // Atomic claim: only proceed if the booking is currently 'pending'.
  const claim = await pool.query(
    `UPDATE bookings
        SET status = 'fulfilling', fulfilled_at = NOW()
      WHERE payment_intent_id = $1 AND status = 'pending'
      RETURNING booking_data`,
    [paymentIntentId]
  );

  if (claim.rows.length === 0) {
    // Either booking doesn't exist, or already fulfilled/failed/cancelled.
    const existing = await pool.query(
      'SELECT status FROM bookings WHERE payment_intent_id = $1',
      [paymentIntentId]
    );
    if (existing.rows.length === 0) {
      console.warn(`[fulfil] No booking row for ${paymentIntentId} — webhook fired before /create-payment-intent persisted? Skipping.`);
    } else {
      console.log(`[fulfil] Booking ${paymentIntentId} already in status: ${existing.rows[0].status}. Skipping.`);
    }
    return;
  }

  const bookingData = claim.rows[0].booking_data;
  console.log(`[fulfil] Sending notifications for ${paymentIntentId} (event ${eventId})`);

  try {
    const results = await sendAllNotifications(bookingData, paymentIntentId, paymentIntent);
    console.log(`[fulfil] ✅ Done for ${paymentIntentId}:`, results);

    // Mirror to Supabase (jobs + bookings) so the web app shows the new job.
    // Non-fatal: if this fails, the Postgres booking + Sheets/Email/WhatsApp
    // are already done. Supabase backup webhook (if Checkout flow is added
    // later) is independent of this.
    try {
      const mirrorResult = await mirrorBookingToSupabase(bookingData, paymentIntentId, paymentIntent);
      if (!mirrorResult.ok) {
        console.error(`[fulfil] ⚠️  Supabase mirror failed for ${paymentIntentId}:`, mirrorResult.error);
      } else if (mirrorResult.alreadyMirrored) {
        console.log(`[fulfil] Supabase mirror skipped (already done) for ${paymentIntentId}`);
      } else {
        console.log(`[fulfil] ✅ Supabase mirror OK: booking ${mirrorResult.bookingId}, job ${mirrorResult.jobId}`);
      }
    } catch (mirrorErr) {
      console.error(`[fulfil] ⚠️  Supabase mirror exception for ${paymentIntentId}:`, mirrorErr.message);
    }

    await pool.query(
      `UPDATE bookings SET status = 'fulfilled' WHERE payment_intent_id = $1`,
      [paymentIntentId]
    );
  } catch (err) {
    // Roll back the claim so a retry can pick it up.
    await pool.query(
      `UPDATE bookings SET status = 'pending' WHERE payment_intent_id = $1 AND status = 'fulfilling'`,
      [paymentIntentId]
    );
    throw err;
  }
}

// ════════════════════════════════════════════════════════════
//  ERROR HANDLER (catches CORS rejections cleanly)
// ════════════════════════════════════════════════════════════
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err && /CORS/i.test(err.message)) {
    return res.status(403).json({ error: 'Origin not allowed.' });
  }
  console.error('[express] unhandled:', err?.message);
  res.status(500).json({ error: 'Internal server error.' });
});

// ════════════════════════════════════════════════════════════
//  START
// ════════════════════════════════════════════════════════════
(async () => {
  try {
    await initSchema();
    app.listen(PORT, () => {
      console.log(`⚡ Flash Clean backend v2 running on port ${PORT}`);
      console.log(`[config] STRICT_PRICING=${process.env.STRICT_PRICING === 'true'}`);
      console.log(`[config] NOTIFY_FALLBACK_DELAY_MS=${Number(process.env.NOTIFY_FALLBACK_DELAY_MS || 0)}`);
      console.log(`[config] Allowed origins: ${Array.from(allowedOrigins).join(', ')}`);
    });
  } catch (err) {
    console.error('[fatal] Startup failed:', err.message);
    process.exit(1);
  }
})();

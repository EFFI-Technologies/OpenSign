import crypto from 'crypto';
import { normalizeEmail } from './userLookup.js';

export const OTP_SENT_RESPONSE = 'Otp send';
export const OTP_INVALID_RESPONSE = 'Invalid Otp';

const OTP_LENGTH = Number(process.env.OTP_LENGTH || 6);
const OTP_EXPIRY_MS = Number(process.env.OTP_EXPIRY_SECONDS || 5 * 60) * 1000;
const OTP_EMAIL_MIN_INTERVAL_MS =
  Number(process.env.OTP_EMAIL_MIN_INTERVAL_SECONDS || 5 * 60) * 1000;
const OTP_EMAIL_SEND_WINDOW_MS =
  Number(process.env.OTP_EMAIL_SEND_WINDOW_SECONDS || 60 * 60) * 1000;
const OTP_EMAIL_SEND_LIMIT = Number(process.env.OTP_EMAIL_SEND_LIMIT || 6);
const OTP_IP_SEND_WINDOW_MS = Number(process.env.OTP_IP_SEND_WINDOW_SECONDS || 60 * 60) * 1000;
const OTP_IP_SEND_LIMIT = Number(process.env.OTP_IP_SEND_LIMIT || 20);
const OTP_VERIFY_WINDOW_MS = Number(process.env.OTP_VERIFY_WINDOW_SECONDS || 30 * 60) * 1000;
const OTP_VERIFY_LIMIT = Number(process.env.OTP_VERIFY_LIMIT || 5);
const OTP_IP_VERIFY_WINDOW_MS = Number(process.env.OTP_IP_VERIFY_WINDOW_SECONDS || 60 * 60) * 1000;
const OTP_IP_VERIFY_LIMIT = Number(process.env.OTP_IP_VERIFY_LIMIT || 60);

function getOtpSecret() {
  return (
    process.env.OTP_HASH_SECRET || process.env.MASTER_KEY || process.env.APP_ID || 'otp-secret'
  );
}

function hashValue(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function rateLimitKey(kind, value) {
  return `${kind}:${hashValue(value)}`;
}

function asDate(value) {
  if (!value) {
    return null;
  }
  if (value instanceof Date) {
    return value;
  }
  if (value.iso) {
    return new Date(value.iso);
  }
  return new Date(value);
}

function isFuture(value, now = new Date()) {
  const date = asDate(value);
  return Boolean(date && date.getTime() > now.getTime());
}

function restrictedAcl() {
  return new Parse.ACL();
}

export function getRequestIp(request = {}) {
  const forwardedFor = request.headers?.['x-forwarded-for'];
  if (forwardedFor) {
    return forwardedFor.split(',')[0].trim();
  }
  return (
    request.headers?.['x-real-ip'] ||
    request.ip ||
    request.connection?.remoteAddress ||
    request.socket?.remoteAddress ||
    'unknown'
  );
}

export function generateOtp() {
  const min = 10 ** (OTP_LENGTH - 1);
  const max = 10 ** OTP_LENGTH;
  return String(crypto.randomInt(min, max));
}

export function hashOtp(email, otp) {
  return crypto
    .createHmac('sha256', getOtpSecret())
    .update(`${normalizeEmail(email)}:${String(otp || '').trim()}`)
    .digest('hex');
}

function safeCompare(left, right) {
  const leftBuffer = Buffer.from(String(left || ''), 'hex');
  const rightBuffer = Buffer.from(String(right || ''), 'hex');
  if (leftBuffer.length !== rightBuffer.length || leftBuffer.length === 0) {
    return false;
  }
  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

async function getOtpRecord(email) {
  const raw = String(email || '').trim();
  const candidates = [...new Set([normalizeEmail(raw), raw].filter(Boolean))];

  for (const candidate of candidates) {
    const query = new Parse.Query('defaultdata_Otp');
    query.equalTo('Email', candidate);
    const record = await query.first({ useMasterKey: true });
    if (record) {
      return record;
    }
  }

  return null;
}

async function consumeWindowRateLimit(key, limit, windowMs) {
  if (!limit || limit < 1) {
    return true;
  }

  const now = new Date();
  const query = new Parse.Query('defaultdata_OtpRateLimit');
  query.equalTo('Key', key);
  let record = await query.first({ useMasterKey: true });
  const windowStart = asDate(record?.get('WindowStart'));
  const windowExpired = !windowStart || now.getTime() - windowStart.getTime() >= windowMs;

  if (!record || windowExpired) {
    record = record || new Parse.Object('defaultdata_OtpRateLimit');
    record.setACL(restrictedAcl());
    record.set('Key', key);
    record.set('Count', 1);
    record.set('WindowStart', now);
    record.set('ExpiresAt', new Date(now.getTime() + windowMs));
    await record.save(null, { useMasterKey: true });
    return true;
  }

  const count = record.get('Count') || 0;
  if (count >= limit) {
    return false;
  }

  record.increment('Count', 1);
  record.set('ExpiresAt', new Date(windowStart.getTime() + windowMs));
  const saved = await record.save(null, { useMasterKey: true });
  await saved.fetch({ useMasterKey: true });
  if ((saved.get('Count') || 0) > limit) {
    saved.increment('Count', -1);
    await saved.save(null, { useMasterKey: true });
    return false;
  }

  return true;
}

export async function canIssueOtp(email, request) {
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail) {
    return false;
  }

  const now = new Date();
  const existing = await getOtpRecord(normalizedEmail);
  if (isFuture(existing?.get('LockedUntil'), now)) {
    return false;
  }

  const expiresAt = asDate(existing?.get('ExpiresAt'));
  const hasActiveOtp =
    Boolean(existing?.get('OTPHash') || existing?.get('OTP')) &&
    (!expiresAt || expiresAt.getTime() > now.getTime());
  const lastSentAt = asDate(existing?.get('LastSentAt'));
  if (
    hasActiveOtp &&
    lastSentAt &&
    now.getTime() - lastSentAt.getTime() < OTP_EMAIL_MIN_INTERVAL_MS
  ) {
    return false;
  }

  const emailAllowed = await consumeWindowRateLimit(
    rateLimitKey('otp-send-email', normalizedEmail),
    OTP_EMAIL_SEND_LIMIT,
    OTP_EMAIL_SEND_WINDOW_MS
  );
  if (!emailAllowed) {
    return false;
  }

  return consumeWindowRateLimit(
    rateLimitKey('otp-send-ip', getRequestIp(request)),
    OTP_IP_SEND_LIMIT,
    OTP_IP_SEND_WINDOW_MS
  );
}

export async function storeOtp({ email, otp, purpose, docId, tenantId, userId, canLogin = false }) {
  const normalizedEmail = normalizeEmail(email);
  const now = new Date();
  let record = await getOtpRecord(normalizedEmail);

  if (!record) {
    record = new Parse.Object('defaultdata_Otp');
    record.setACL(restrictedAcl());
  }

  record.set('Email', normalizedEmail);
  record.set('OTPHash', hashOtp(normalizedEmail, otp));
  record.unset('OTP');
  record.set('Purpose', purpose || '');
  record.set('DocId', docId || '');
  record.set('CanLogin', Boolean(canLogin));
  record.set('VerifyAttempts', 0);
  record.unset('LockedUntil');
  record.set('ExpiresAt', new Date(now.getTime() + OTP_EXPIRY_MS));
  record.set('LastSentAt', now);
  if (tenantId) {
    record.set('TenantId', tenantId);
  } else {
    record.unset('TenantId');
  }
  if (userId) {
    record.set('UserId', Parse.User.createWithoutData(userId));
  } else {
    record.unset('UserId');
  }

  await record.save(null, { useMasterKey: true });
  return record;
}

async function consumeVerifyRateLimit(email, request) {
  const normalizedEmail = normalizeEmail(email);
  const emailAllowed = await consumeWindowRateLimit(
    rateLimitKey('otp-verify-email', normalizedEmail),
    OTP_VERIFY_LIMIT,
    OTP_VERIFY_WINDOW_MS
  );
  if (!emailAllowed) {
    return false;
  }

  return consumeWindowRateLimit(
    rateLimitKey('otp-verify-ip', getRequestIp(request)),
    OTP_IP_VERIFY_LIMIT,
    OTP_IP_VERIFY_WINDOW_MS
  );
}

export async function verifyOtpForEmail(email, otp, request) {
  const normalizedEmail = normalizeEmail(email);
  const normalizedOtp = String(otp || '').trim();
  if (!normalizedEmail || !normalizedOtp) {
    return { ok: false };
  }

  const verifyAllowed = await consumeVerifyRateLimit(normalizedEmail, request);
  if (!verifyAllowed) {
    return { ok: false };
  }

  const now = new Date();
  const record = await getOtpRecord(normalizedEmail);
  if (!record || isFuture(record.get('LockedUntil'), now)) {
    return { ok: false };
  }

  const recordDocId = String(record.get('DocId') || '').trim();
  const requestDocId = String(request?.params?.docId || request?.params?.documentId || '').trim();
  if (recordDocId && recordDocId !== requestDocId) {
    return { ok: false, record };
  }

  const expiresAt = asDate(record.get('ExpiresAt'));
  const legacyIssuedAt = asDate(record.updatedAt || record.createdAt);
  if (
    (expiresAt && expiresAt.getTime() <= now.getTime()) ||
    (!expiresAt && legacyIssuedAt && now.getTime() - legacyIssuedAt.getTime() > OTP_EXPIRY_MS)
  ) {
    return { ok: false, record };
  }

  const otpHash = record.get('OTPHash');
  const legacyOtp = record.get('OTP');
  const hashMatches = otpHash && safeCompare(otpHash, hashOtp(normalizedEmail, normalizedOtp));
  const legacyMatches = legacyOtp !== undefined && String(legacyOtp) === normalizedOtp;

  if (hashMatches || legacyMatches) {
    record.set('VerifyAttempts', 0);
    record.unset('LockedUntil');
    record.unset('OTPHash');
    record.unset('OTP');
    record.set('LastVerifiedAt', now);
    await record.save(null, { useMasterKey: true });
    return {
      ok: true,
      canLogin: record.get('CanLogin') !== false,
      purpose: record.get('Purpose') || '',
      record,
    };
  }

  const verifyAttempts = (record.get('VerifyAttempts') || 0) + 1;
  record.set('VerifyAttempts', verifyAttempts);
  if (verifyAttempts >= OTP_VERIFY_LIMIT) {
    record.set('LockedUntil', new Date(now.getTime() + OTP_VERIFY_WINDOW_MS));
  }
  await record.save(null, { useMasterKey: true });

  return { ok: false, record };
}

import axios from 'axios';
import crypto from 'node:crypto';

const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const CAPTCHA_ERROR_CODE = 142;
const CAPTCHA_CONTEXT_TOKEN_KEYS = ['captchaToken', 'turnstileToken'];
const CAPTCHA_PROOF_KEY = '_captchaProof';

function captchaError(message) {
  if (globalThis.Parse?.Error) {
    return new Parse.Error(CAPTCHA_ERROR_CODE, message);
  }

  const error = new Error(message);
  error.code = CAPTCHA_ERROR_CODE;
  return error;
}

export function isCaptchaRequired() {
  return process.env.CAPTCHA_REQUIRED === 'true';
}

function getSecretKey() {
  return process.env.CAPTCHA_TURNSTILE_SECRET_KEY || '';
}

function getCaptchaToken(context = {}) {
  for (const key of CAPTCHA_CONTEXT_TOKEN_KEYS) {
    const token = context?.[key];
    if (typeof token === 'string' && token.trim()) {
      return token.trim();
    }
  }

  const nestedToken = context?.captcha?.token;
  return typeof nestedToken === 'string' ? nestedToken.trim() : '';
}

function getRemoteIp({ headers = {}, ip = '' } = {}) {
  const forwardedFor = headers['x-forwarded-for'];
  if (forwardedFor) {
    return forwardedFor.split(',')[0].trim();
  }

  return headers['x-real-ip'] || ip || '';
}

function isLoopbackIp(ip = '') {
  return ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1' || ip.startsWith('127.');
}

function isInternalServerRequest(req) {
  const forwardedFor = req.headers?.['x-forwarded-for'];
  const origin = req.headers?.origin;
  const remoteAddress = req.socket?.remoteAddress || req.ip || '';

  return !forwardedFor && !origin && isLoopbackIp(remoteAddress);
}

function getCaptchaProof(token) {
  const secretKey = getSecretKey();
  if (!secretKey || !token) {
    return '';
  }

  return crypto.createHmac('sha256', secretKey).update(token).digest('hex');
}

function hasVerifiedCaptchaProof(context = {}, token) {
  const proof = context?.[CAPTCHA_PROOF_KEY];
  return Boolean(proof && proof === getCaptchaProof(token));
}

function markCaptchaVerified(context = {}, token) {
  context[CAPTCHA_PROOF_KEY] = getCaptchaProof(token);
  return context;
}

async function verifyTurnstileToken(token, remoteIp) {
  const secretKey = getSecretKey();
  if (!secretKey) {
    throw captchaError('Captcha is not configured.');
  }

  const body = new URLSearchParams();
  body.append('secret', secretKey);
  body.append('response', token);
  if (remoteIp) {
    body.append('remoteip', remoteIp);
  }

  const response = await axios.post(TURNSTILE_VERIFY_URL, body, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    timeout: 5000,
  });

  if (!response?.data?.success) {
    throw captchaError('Captcha verification failed.');
  }
}

export async function requireCaptcha({ context = {}, headers = {}, ip = '', master = false } = {}) {
  if (master || !isCaptchaRequired()) {
    return context;
  }

  const token = getCaptchaToken(context);
  if (!token) {
    throw captchaError('Captcha verification is required.');
  }

  if (hasVerifiedCaptchaProof(context, token)) {
    return context;
  }

  await verifyTurnstileToken(token, getRemoteIp({ headers, ip }));
  return markCaptchaVerified(context, token);
}

export function captchaParseAuthMiddleware() {
  return async function verifyCaptchaForParseAuth(req, res, next) {
    const isProtectedAuthRequest =
      req.method === 'POST' && (req.path === '/login' || req.path === '/users');

    if (!isProtectedAuthRequest || !isCaptchaRequired() || isInternalServerRequest(req)) {
      return next();
    }

    try {
      req.body._context = await requireCaptcha({
        context: req.body?._context || {},
        headers: req.headers,
        ip: req.ip,
      });
      return next();
    } catch (err) {
      return res.status(400).json({
        code: err.code || CAPTCHA_ERROR_CODE,
        error: err.message || 'Captcha verification failed.',
      });
    }
  };
}

export function registerCaptchaTriggers(ParseInstance = Parse) {
  ParseInstance.Cloud.beforeLogin(async request => {
    await requireCaptcha({
      context: request.context,
      headers: request.headers,
      ip: request.ip,
      master: request.master,
    });
  });
}

import { captchaParseAuthMiddleware, requireCaptcha } from '../security/captcha.js';

function restoreEnv(originalEnv) {
  for (const [key, value] of Object.entries(originalEnv)) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
}

describe('captcha security', () => {
  const envKeys = ['CAPTCHA_REQUIRED', 'CAPTCHA_TURNSTILE_SECRET_KEY'];
  let originalEnv;

  beforeEach(() => {
    originalEnv = Object.fromEntries(envKeys.map(key => [key, process.env[key]]));
    for (const key of envKeys) {
      delete process.env[key];
    }
  });

  afterEach(() => {
    restoreEnv(originalEnv);
  });

  it('does not require captcha when disabled', async () => {
    await expectAsync(requireCaptcha({ context: {} })).toBeResolved();
  });

  it('requires a token when captcha is enabled', async () => {
    process.env.CAPTCHA_REQUIRED = 'true';
    process.env.CAPTCHA_TURNSTILE_SECRET_KEY = 'secret';

    await expectAsync(requireCaptcha({ context: {} })).toBeRejectedWithError(
      'Captcha verification is required.'
    );
  });

  it('does not require captcha for master-key internal writes', async () => {
    process.env.CAPTCHA_REQUIRED = 'true';
    process.env.CAPTCHA_TURNSTILE_SECRET_KEY = 'secret';

    await expectAsync(requireCaptcha({ context: {}, master: true })).toBeResolved();
  });

  it('rejects protected Parse auth routes before they reach Parse', async () => {
    process.env.CAPTCHA_REQUIRED = 'true';
    process.env.CAPTCHA_TURNSTILE_SECRET_KEY = 'secret';

    const middleware = captchaParseAuthMiddleware();
    const req = {
      method: 'POST',
      path: '/login',
      body: {},
      headers: { origin: 'https://app.example.com' },
      ip: '127.0.0.1',
    };
    const res = {
      statusCode: null,
      body: null,
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(body) {
        this.body = body;
        return this;
      },
    };
    let nextCalled = false;

    await middleware(req, res, () => {
      nextCalled = true;
    });

    expect(nextCalled).toBe(false);
    expect(res.statusCode).toBe(400);
    expect(res.body.error).toBe('Captcha verification is required.');
  });
});

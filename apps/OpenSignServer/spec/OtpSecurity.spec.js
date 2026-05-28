import getUserId from '../cloud/parsefunction/getUserId.js';
import { storeOtp, verifyOtpForEmail } from '../cloud/parsefunction/otpSecurity.js';

describe('OTP security helpers', () => {
  it('stores hashed OTPs and consumes them after successful verification', async () => {
    const email = `otp-${Date.now()}@example.com`;
    await storeOtp({
      email,
      otp: '1234',
      purpose: 'passwordless-login',
      canLogin: true,
    });

    const query = new Parse.Query('defaultdata_Otp');
    query.equalTo('Email', email);
    const stored = await query.first({ useMasterKey: true });
    expect(stored.get('OTP')).toBeUndefined();
    expect(stored.get('OTPHash')).toBeDefined();

    const badResult = await verifyOtpForEmail(email, '0000', {
      headers: { 'x-real-ip': '127.0.0.2' },
    });
    expect(badResult.ok).toBe(false);

    const goodResult = await verifyOtpForEmail(email, '1234', {
      headers: { 'x-real-ip': '127.0.0.2' },
    });
    expect(goodResult.ok).toBe(true);
    expect(goodResult.canLogin).toBe(true);

    const reuseResult = await verifyOtpForEmail(email, '1234', {
      headers: { 'x-real-ip': '127.0.0.2' },
    });
    expect(reuseResult.ok).toBe(false);
  });

  it('requires an authenticated caller for getUserId', async () => {
    const email = `lookup-${Date.now()}@example.com`;
    const user = new Parse.User();
    user.set('username', email);
    user.set('email', email);
    user.set('password', 'password123');
    const savedUser = await user.save(null, { useMasterKey: true });

    try {
      await getUserId({ params: { email } });
      fail('expected unauthenticated lookup to throw');
    } catch (err) {
      expect(err.code).toBe(Parse.Error.INVALID_SESSION_TOKEN);
    }

    const result = await getUserId({ user: savedUser, params: { email } });
    expect(result.id).toBe(savedUser.id);
  });
});

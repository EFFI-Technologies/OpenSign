import crypto from 'crypto';

export function generateGuestPassword() {
  return crypto.randomBytes(32).toString('hex');
}

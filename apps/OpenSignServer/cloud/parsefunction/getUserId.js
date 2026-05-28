import { requireSessionUser } from '../../security/parseSessionAuth.js';
import { findUserByEmail, normalizeEmail } from './userLookup.js';

async function getUserId(request) {
  try {
    await requireSessionUser(request);

    const username = normalizeEmail(request.params.username);
    const email = normalizeEmail(request.params.email);
    const user = username ? await findUserByEmail(username) : await findUserByEmail(email);

    return user ? { id: user.id } : {};
  } catch (err) {
    throw err;
  }
}
export default getUserId;

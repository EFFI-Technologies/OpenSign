import { requireSessionUser } from '../../security/parseSessionAuth.js';
import { findUserByEmail, normalizeEmail } from './userLookup.js';

async function requireLookupPrivilege(request, requestedEmail) {
  const user = await requireSessionUser(request);
  const currentEmail = normalizeEmail(user.get('email') || user.get('username'));

  if (requestedEmail && requestedEmail === currentEmail) {
    return;
  }

  const extUserQuery = new Parse.Query('contracts_Users');
  extUserQuery.equalTo('UserId', {
    __type: 'Pointer',
    className: '_User',
    objectId: user.id,
  });
  extUserQuery.containedIn('UserRole', ['contracts_Admin', 'contracts_OrgAdmin']);
  extUserQuery.notEqualTo('IsDisabled', true);

  const extUser = await extUserQuery.first({ useMasterKey: true });
  if (!extUser) {
    throw new Parse.Error(Parse.Error.OPERATION_FORBIDDEN, 'Admin privileges are required.');
  }
}

async function getUserId(request) {
  try {
    const username = normalizeEmail(request.params.username);
    const email = normalizeEmail(request.params.email);
    const lookupEmail = username || email;
    await requireLookupPrivilege(request, lookupEmail);

    const user = await findUserByEmail(lookupEmail);

    return user ? { id: user.id } : {};
  } catch (err) {
    throw err;
  }
}
export default getUserId;

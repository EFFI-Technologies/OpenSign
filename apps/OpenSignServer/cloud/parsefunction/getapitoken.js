import { requireSessionUserId } from '../../security/parseSessionAuth.js';

export default async function getapitoken(request) {
  try {
    const userId = await requireSessionUserId(request);
    if (userId) {
      const tokenQuery = new Parse.Query('appToken');
      tokenQuery.equalTo('userId', { __type: 'Pointer', className: '_User', objectId: userId });
      const res = await tokenQuery.first({ useMasterKey: true });
      if (res) {
        return { status: 'success', result: res.get('token') };
      } else {
        return { error: 'api token found.' };
      }
    } else {
      return { error: 'Invalid session token.' };
    }
  } catch (err) {
    console.log('Err in getapitoken', err);
    if (err.code === Parse.Error.INVALID_SESSION_TOKEN) {
      return { error: 'Invalid session token.' };
    } else {
      return { error: "You don't have access." };
    }
  }
}

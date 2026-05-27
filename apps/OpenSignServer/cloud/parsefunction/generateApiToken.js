import { generateApiKey } from 'generate-api-key';
import { requireSessionUserId } from '../../security/parseSessionAuth.js';
export default async function generateApiToken(request) {
  try {
    const userId = await requireSessionUserId(request);
    if (userId) {
      const tokenQuery = new Parse.Query('appToken');
      tokenQuery.equalTo('userId', { __type: 'Pointer', className: '_User', objectId: userId });
      const token = await tokenQuery.first({ useMasterKey: true });
      if (token !== undefined) {
        // return exsiting Token
        console.log('Regenerate API Token');
        const AppToken = Parse.Object.extend('appToken');
        const updateToken = new AppToken();
        updateToken.id = token.id;
        const newToken = generateApiKey({ method: 'base62', prefix: 'effisign' });
        updateToken.set('token', newToken);
        const updatedRes = await updateToken.save(null, { useMasterKey: true });
        return updatedRes;
      } else {
        // Create New Token
        console.log('New API Token Generation');
        const appToken = Parse.Object.extend('appToken');
        const appTokenQuery = new appToken();
        const token = generateApiKey({ method: 'base62', prefix: 'effisign' });
        appTokenQuery.set('token', token);
        appTokenQuery.set('userId', { __type: 'Pointer', className: '_User', objectId: userId });
        const newRes = await appTokenQuery.save(null, { useMasterKey: true });
        return newRes;
      }
    } else {
      return 'User not found!';
    }
  } catch (err) {
    console.log('err ', err);
  }
}

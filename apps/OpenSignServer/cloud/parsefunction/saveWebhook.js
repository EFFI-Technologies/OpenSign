import { requireSessionUserId } from '../../security/parseSessionAuth.js';
export default async function savewebhook(request) {
  try {
    const userId = await requireSessionUserId(request);
    const contractuser = new Parse.Query('contracts_Users');
    contractuser.equalTo('UserId', { __type: 'Pointer', className: '_User', objectId: userId });
    const user = await contractuser.first({ useMasterKey: true });

    if (user) {
      const updateUser = new Parse.Object('contracts_Users');
      updateUser.id = user.id;
      updateUser.set('Webhook', request.params.url);
      const updatedRes = await updateUser.save(null, { useMasterKey: true });
      if (updatedRes) {
        return { code: 200, Webhook: updatedRes.get('Webhook') };
      }
    }
  } catch (err) {
    console.log('update user', err);
    return err;
  }
}

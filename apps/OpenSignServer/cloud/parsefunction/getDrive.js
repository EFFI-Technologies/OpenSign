import axios from 'axios';
import { cloudServerUrl } from '../../Utils.js';
import { requireSessionUserId } from '../../security/parseSessionAuth.js';
export default async function getDrive(request) {
  const serverUrl = cloudServerUrl; //process.env.SERVER_URL;
  const limit = request.params.limit;
  const skip = request.params.skip;
  const classUrl = serverUrl + '/classes/contracts_Document';
  const docId = request.params.docId;
  try {
    const userId = await requireSessionUserId(request);
    if (userId) {
      let url;
      if (docId) {
        url = `${classUrl}?where={"Folder":{"__type":"Pointer","className":"contracts_Document","objectId":"${docId}"},"CreatedBy":{"__type":"Pointer","className":"_User","objectId":"${userId}"},"IsArchive":{"$ne":true}}&include=ExtUserPtr,ExtUserPtr.TenantId,Signers,Folder&order=-updatedAt&skip=${skip}&limit=${limit}`;
      } else {
        url = `${classUrl}?where={"Folder":{"$exists":false},"CreatedBy":{"__type":"Pointer","className":"_User","objectId":"${userId}"},"IsArchive":{"$ne":true}}&include=ExtUserPtr,ExtUserPtr.TenantId,Signers&order=-updatedAt&skip=${skip}&limit=${limit}`;
      }
      try {
        const res = await axios.get(url, {
          headers: {
            'X-Parse-Application-Id': appId,
            'X-Parse-Master-key': process.env.MASTER_KEY,
          },
        });
        // console.log('res.data.results ', res.data.results);
        if (res.data && res.data.results) {
          return res.data.results;
        } else {
          return [];
        }
      } catch (err) {
        console.log('err', err);
        return { error: "You don't have access to drive" };
      }
    } else {
      return { error: 'Please provide required parameter!' };
    }
  } catch (err) {
    console.log('err', err);
    if (err.code === Parse.Error.INVALID_SESSION_TOKEN) {
      return { error: 'Invalid session token' };
    } else {
      return { error: "You don't have access!" };
    }
  }
}

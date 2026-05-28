import { parseJwt } from '../../Utils.js';
import jwt from 'jsonwebtoken';
import { getRequestSessionToken, requireSessionUserId } from '../../security/parseSessionAuth.js';
import { applyPresignedUrlsToRecord } from './getSignedUrl.js';

function getPointerId(pointer) {
  return pointer?.id || pointer?.objectId || pointer?.get?.('objectId') || '';
}

function contactCanReadDocument(document, contactId) {
  if (!contactId) {
    return false;
  }

  const signers = document?.get('Signers') || [];
  const signerIds = signers.map(getPointerId);
  if (signerIds.includes(contactId)) {
    return true;
  }

  const placeholders = document?.get('Placeholders') || [];
  return placeholders.some(placeholder => {
    return (
      placeholder?.signerObjId === contactId || getPointerId(placeholder?.signerPtr) === contactId
    );
  });
}

function serializeDocument(document) {
  const serialized = JSON.parse(JSON.stringify(applyPresignedUrlsToRecord(document)));
  delete serialized?.ExtUserPtr?.TenantId?.FileAdapters;
  delete serialized?.ExtUserPtr?.TenantId?.PfxFile;
  return serialized;
}

export default async function getDocument(request) {
  const docId = request.params.docId;
  const contactId = request.params.contactId || request.params.contactBookId || '';
  const jwttoken = request?.headers?.jwttoken || '';
  const sessiontoken = getRequestSessionToken(request?.headers);
  try {
    if (docId) {
      try {
        const query = new Parse.Query('contracts_Document');
        query.equalTo('objectId', docId);
        query.include('ExtUserPtr');
        query.include('ExtUserPtr.TenantId');
        query.include('CreatedBy');
        query.include('Signers');
        query.include('AuditTrail.UserPtr');
        query.include('Placeholders');
        query.include('DeclineBy');
        query.notEqualTo('IsArchive', true);
        const res = await query.first({ useMasterKey: true, context: { skipPresign: true } });
        if (res) {
          const IsEnableOTP = res?.get('IsEnableOTP') || false;
          if (!IsEnableOTP) {
            let canReadDocument = false;
            if (sessiontoken) {
              try {
                const userId = await requireSessionUserId(request);
                const acl = res.getACL();
                if (userId && acl && acl.getReadAccess(userId)) {
                  canReadDocument = true;
                }
              } catch (err) {
                console.log('err user in not authenticated', err);
              }
            }
            if (!canReadDocument && jwttoken) {
              try {
                const jwtDecode = parseJwt(jwttoken);
                if (jwtDecode?.user_email) {
                  const userCls = new Parse.Query(Parse.User);
                  userCls.equalTo('email', jwtDecode?.user_email);
                  const userRes = await userCls.first({ useMasterKey: true });
                  const userId = userRes?.id;
                  const tokenQuery = new Parse.Query('appToken');
                  tokenQuery.equalTo('userId', {
                    __type: 'Pointer',
                    className: '_User',
                    objectId: userId,
                  });
                  const appRes = await tokenQuery.first({ useMasterKey: true });
                  const decoded = jwt.verify(jwttoken, appRes?.get('token'));
                  const acl = res.getACL();
                  if (decoded?.user_email && userId && acl && acl.getReadAccess(userId)) {
                    canReadDocument = true;
                  }
                }
              } catch (err) {
                console.log('err in jwt', err);
              }
            }
            if (!canReadDocument && contactCanReadDocument(res, contactId)) {
              canReadDocument = true;
            }
            if (canReadDocument) {
              return serializeDocument(res);
            }
            return { error: "You don't have access of this document!" };
          } else {
            if (sessiontoken) {
              try {
                const userId = await requireSessionUserId(request);
                const acl = res.getACL();
                if (userId && acl && acl.getReadAccess(userId)) {
                  return serializeDocument(res);
                } else {
                  return { error: "You don't have access of this document!" };
                }
              } catch (err) {
                console.log('err user in not authenticated', err);
                return { error: "You don't have access of this document!" };
              }
            } else if (jwttoken) {
              try {
                const jwtDecode = parseJwt(jwttoken);
                if (jwtDecode?.user_email) {
                  const userCls = new Parse.Query(Parse.User);
                  userCls.equalTo('email', jwtDecode?.user_email);
                  const userRes = await userCls.first({ useMasterKey: true });
                  const userId = userRes?.id;
                  const tokenQuery = new Parse.Query('appToken');
                  tokenQuery.equalTo('userId', {
                    __type: 'Pointer',
                    className: '_User',
                    objectId: userId,
                  });
                  const appRes = await tokenQuery.first({ useMasterKey: true });
                  const decoded = jwt.verify(jwttoken, appRes?.get('token'));
                  if (decoded?.user_email) {
                    const acl = res.getACL();
                    if (userId && acl && acl.getReadAccess(userId)) {
                      return serializeDocument(res);
                    } else {
                      return { error: "You don't have access of this document!" };
                    }
                  } else {
                    return { status: 'error', result: 'Invalid token!' };
                  }
                }
              } catch (err) {
                console.log('err in jwt', err);
                return { error: "You don't have access of this document!" };
              }
            } else {
              return { error: "You don't have access of this document!" };
            }
          }
        } else {
          return { error: "You don't have access of this document!" };
        }
      } catch (err) {
        console.log('err', err);
        return err;
      }
    } else {
      return { error: 'Please pass required parameters!' };
    }
  } catch (err) {
    console.log('err', err);
    if (err.code === Parse.Error.INVALID_SESSION_TOKEN) {
      return { error: 'Invalid session token' };
    } else {
      return { error: "You don't have access of this document!" };
    }
  }
}

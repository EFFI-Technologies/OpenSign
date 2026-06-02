import axios from 'axios';
import { getRequestSessionToken, requireSessionUserId } from '../../security/parseSessionAuth.js';

function getPointerId(pointer) {
  return pointer?.id || pointer?.objectId || pointer?.get?.('objectId') || '';
}

function contactCanReadDocument(document, contactId) {
  if (!contactId) {
    return false;
  }

  const signers = document?.get('Signers') || [];
  if (signers.map(getPointerId).includes(contactId)) {
    return true;
  }

  const placeholders = document?.get('Placeholders') || [];
  return placeholders.some(placeholder => {
    return (
      placeholder?.signerObjId === contactId || getPointerId(placeholder?.signerPtr) === contactId
    );
  });
}

async function getContactUserId(contactId) {
  if (!contactId) {
    return '';
  }

  const contactQuery = new Parse.Query('contracts_Contactbook');
  const contact = await contactQuery.get(contactId, { useMasterKey: true });
  return getPointerId(contact?.get('UserId'));
}

async function resolveWebhookActorUserId(request, document, contactId) {
  const sessionToken = getRequestSessionToken(request?.headers);
  if (sessionToken) {
    return requireSessionUserId(request);
  }

  if (document?.get('IsEnableOTP') && contactCanReadDocument(document, contactId)) {
    return getContactUserId(contactId);
  }

  if (document?.get('IsEnableOTP')) {
    throw new Parse.Error(Parse.Error.INVALID_SESSION_TOKEN, 'User is not authenticated.');
  }

  return '';
}

async function saveWebhookLog(status, userId) {
  try {
    const webhook = new Parse.Object('contracts_Webhook');
    webhook.set('Log', status);
    if (userId) {
      webhook.set('UserId', {
        __type: 'Pointer',
        className: '_User',
        objectId: userId,
      });
    }
    await webhook.save(null, { useMasterKey: true });
  } catch (err) {
    console.log('err save in contracts_Webhook', err.message);
  }
}

export default async function callWebhook(request) {
  const event = request.params.event;
  const body = request.params.body;
  const docId = body.objectId;
  const contactId = request.params.contactId;
  try {
    const docQuery = new Parse.Query('contracts_Document');
    docQuery.include('ExtUserPtr.TenantId');
    const docRes = await docQuery.get(docId, { useMasterKey: true });
    const isEnableOTP = docRes?.get('IsEnableOTP') || false;
    const userId = await resolveWebhookActorUserId(request, docRes, contactId);
    if (!isEnableOTP || userId) {
      if (event === 'viewed' && contactId) {
        if (docRes) {
          const _docRes = docRes.toJSON();
          const userPtr = {
            __type: 'Pointer',
            className: 'contracts_Contactbook',
            objectId: contactId,
          };
          const date = new Date().toISOString();
          const obj = {
            UserPtr: userPtr,
            SignedUrl: _docRes.SignedUrl,
            Activity: 'Viewed',
            ipAddress: request.headers['x-real-ip'],
            ViewedOn: date,
          };
          const isUserExist = _docRes?.AuditTrail?.some(
            x => x.UserPtr.objectId === contactId && x?.ViewedOn
          );
          if (!isUserExist) {
            const updateDoc = new Parse.Object('contracts_Document');
            updateDoc.id = docRes.id;
            if (_docRes?.AuditTrail && _docRes?.AuditTrail?.length > 0) {
              updateDoc.set('AuditTrail', [..._docRes?.AuditTrail, obj]);
            } else {
              updateDoc.set('AuditTrail', [obj]);
            }
            await updateDoc.save(null, { useMasterKey: true });
          }
        }
      }
      const extendcls = new Parse.Query('contracts_Users');
      extendcls.equalTo('objectId', docRes.get('ExtUserPtr')?.id);
      // extendcls.equalTo('UserId', { __type: 'Pointer', className: '_User', objectId: userId });
      const resExt = await extendcls.first({ useMasterKey: true });
      if (resExt) {
        const extUser = JSON.parse(JSON.stringify(resExt));
        if (extUser?.Webhook) {
          const params = { event: event, ...body };
          await axios
            .post(extUser?.Webhook, params, {
              headers: { 'Content-Type': 'application/json' },
            })
            .then(async res => {
              await saveWebhookLog(res?.status, userId);
            })
            .catch(async err => {
              console.log('Err send data to webhook', err.message);
              await saveWebhookLog(err?.response?.status || err?.status || 500, userId);
            });
        }
        return { message: 'webhook called!' };
      }
    } else {
      return { message: 'User not found!' };
    }
  } catch (err) {
    console.log('Err in callwebhook', err);
    return { message: 'Something went wrong!' };
  }
}

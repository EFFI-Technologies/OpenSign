import { parseJwt } from '../../Utils.js';
import jwt from 'jsonwebtoken';
import { requireCurrentExtUser, requireSessionUser } from '../../security/parseSessionAuth.js';

async function getTenantById(tenantId) {
  if (!tenantId) {
    return null;
  }

  const tenantQuery = new Parse.Query('partners_Tenant');
  tenantQuery.exclude('FileAdapters');
  tenantQuery.exclude('PfxFile');
  return tenantQuery.get(tenantId, { useMasterKey: true });
}

async function getTenantByUserId(userId) {
  if (!userId) {
    return null;
  }

  const extUserQuery = new Parse.Query('contracts_Users');
  extUserQuery.equalTo('UserId', {
    __type: 'Pointer',
    className: '_User',
    objectId: userId,
  });
  const extUser = await extUserQuery.first({ useMasterKey: true });
  const extTenantId = extUser?.get('TenantId')?.id;
  if (extTenantId) {
    return getTenantById(extTenantId);
  }

  const tenantQuery = new Parse.Query('partners_Tenant');
  tenantQuery.equalTo('UserId', {
    __type: 'Pointer',
    className: '_User',
    objectId: userId,
  });
  tenantQuery.exclude('FileAdapters');
  tenantQuery.exclude('PfxFile');
  return tenantQuery.first({ useMasterKey: true });
}

async function hasSenderContactAccess(sessionUserId, requestedUserId) {
  const contactQuery = new Parse.Query('contracts_Contactbook');
  contactQuery.equalTo('UserId', {
    __type: 'Pointer',
    className: '_User',
    objectId: sessionUserId,
  });
  contactQuery.equalTo('CreatedBy', {
    __type: 'Pointer',
    className: '_User',
    objectId: requestedUserId,
  });
  contactQuery.notEqualTo('IsDeleted', true);
  const contact = await contactQuery.first({ useMasterKey: true });
  return Boolean(contact);
}

async function hasDocumentAccess(sessionUserId, requestedUserId, docId) {
  if (!docId) {
    return false;
  }

  const docQuery = new Parse.Query('contracts_Document');
  docQuery.include('ExtUserPtr');
  docQuery.include('ExtUserPtr.UserId');
  const doc = await docQuery.get(docId, { useMasterKey: true });
  const docOwnerId = doc.get('ExtUserPtr')?.get('UserId')?.id || doc.get('CreatedBy')?.id;
  const acl = doc.getACL();

  return docOwnerId === requestedUserId && Boolean(acl?.getReadAccess(sessionUserId));
}

async function canReadTenantForUser(sessionUserId, requestedUserId, docId) {
  if (!requestedUserId || sessionUserId === requestedUserId) {
    return true;
  }

  return (
    (await hasSenderContactAccess(sessionUserId, requestedUserId)) ||
    (await hasDocumentAccess(sessionUserId, requestedUserId, docId))
  );
}

export default async function getTenant(request) {
  const jwttoken = request.headers.jwttoken || '';
  if (jwttoken) {
    const jwtDecode = parseJwt(jwttoken);
    if (jwtDecode?.user_email) {
      const verifyToken = jwttoken;
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
      const decoded = jwt.verify(verifyToken, appRes?.get('token'));
      if (decoded?.user_email) {
        try {
          const res = await getTenantByUserId(userId);
          if (res) {
            return res;
          }
        } catch (e) {
          return 'user does not exist!';
        }
      } else {
        return { status: 'error', result: 'Invalid token!' };
      }
    }
  } else {
    try {
      const requestedUserId = request.params.userId || '';
      if (requestedUserId) {
        const sessionUser = await requireSessionUser(request);
        const canReadTenant = await canReadTenantForUser(
          sessionUser.id,
          requestedUserId,
          request.params.docId
        );
        if (!canReadTenant) {
          return 'user does not exist!';
        }

        const tenant = await getTenantByUserId(requestedUserId);
        return tenant || 'user does not exist!';
      }

      const extUser = await requireCurrentExtUser(request);
      if (extUser) {
        const tenant = await getTenantById(extUser.get('TenantId')?.id);
        return tenant || { objectId: extUser.get('TenantId')?.id };
      }
    } catch (e) {
      if (e?.code === Parse.Error.INVALID_SESSION_TOKEN) {
        return { status: 'error', result: 'Invalid session token!' };
      }
      return 'user does not exist!';
    }
  }
}

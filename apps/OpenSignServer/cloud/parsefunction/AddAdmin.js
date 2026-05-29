import { requireSessionUser } from '../../security/parseSessionAuth.js';
import { findUserByEmail, normalizeEmail } from './userLookup.js';

const ADMIN_ROLE = 'contracts_Admin';

function requireField(value, fieldName) {
  const sanitized = String(value || '').trim();
  if (!sanitized) {
    throw new Parse.Error(Parse.Error.VALIDATION_ERROR, `${fieldName} is required.`);
  }
  return sanitized;
}

function getUserDetails(request) {
  const rawUserDetails = request.params?.userDetails || {};
  return {
    ...rawUserDetails,
    name: requireField(rawUserDetails.name, 'Name'),
    email: normalizeEmail(requireField(rawUserDetails.email, 'Email')),
    company: requireField(rawUserDetails.company, 'Company'),
    phone: rawUserDetails.phone ? String(rawUserDetails.phone).trim() : '',
    jobTitle: rawUserDetails.jobTitle ? String(rawUserDetails.jobTitle).trim() : '',
    password: rawUserDetails.password,
    role: ADMIN_ROLE,
  };
}

async function hasActiveAdmin() {
  const extUserQuery = new Parse.Query('contracts_Users');
  extUserQuery.equalTo('UserRole', ADMIN_ROLE);
  extUserQuery.notEqualTo('IsDisabled', true);
  extUserQuery.exists('OrganizationId');
  const extUser = await extUserQuery.first({ useMasterKey: true });
  return Boolean(extUser);
}

async function requireAdminUser(request, userDetails, requestUser) {
  const user = requestUser || (await requireSessionUser(request));
  const adminExists = await hasActiveAdmin();
  const currentEmail = normalizeEmail(user.get('email') || user.get('username'));

  if (!adminExists) {
    if (!currentEmail || currentEmail !== userDetails.email) {
      throw new Parse.Error(
        Parse.Error.OPERATION_FORBIDDEN,
        'Only the authenticated signup user can create the first admin.'
      );
    }
    return user;
  }

  const extUserQuery = new Parse.Query('contracts_Users');
  extUserQuery.equalTo('UserId', {
    __type: 'Pointer',
    className: '_User',
    objectId: user.id,
  });
  extUserQuery.equalTo('UserRole', ADMIN_ROLE);
  extUserQuery.notEqualTo('IsDisabled', true);
  const extUser = await extUserQuery.first({ useMasterKey: true });

  if (!extUser) {
    throw new Parse.Error(Parse.Error.OPERATION_FORBIDDEN, 'Admin privileges are required.');
  }

  return user;
}

async function addTeamAndOrg(extUser) {
  try {
    const orgCls = new Parse.Object('contracts_Organizations');
    orgCls.set('Name', extUser.Company);
    orgCls.set('IsActive', true);
    orgCls.set('ExtUserId', {
      __type: 'Pointer',
      className: 'contracts_Users',
      objectId: extUser?.objectId,
    });
    orgCls.set('CreatedBy', {
      __type: 'Pointer',
      className: '_User',
      objectId: extUser?.UserId?.objectId,
    });
    orgCls.set('TenantId', {
      __type: 'Pointer',
      className: 'partners_Tenant',
      objectId: extUser?.TenantId?.objectId,
    });

    const orgRes = await orgCls.save(null, { useMasterKey: true });
    const teamCls = new Parse.Object('contracts_Teams');
    teamCls.set('Name', 'All Users');
    teamCls.set('OrganizationId', {
      __type: 'Pointer',
      className: 'contracts_Organizations',
      objectId: orgRes.id,
    });
    teamCls.set('IsActive', true);
    const teamRes = await teamCls.save(null, { useMasterKey: true });
    const updateUser = new Parse.Object('contracts_Users');
    updateUser.id = extUser.objectId;
    updateUser.set('UserRole', ADMIN_ROLE);
    updateUser.set('OrganizationId', {
      __type: 'Pointer',
      className: 'contracts_Organizations',
      objectId: orgRes.id,
    });
    updateUser.set('TeamIds', [
      {
        __type: 'Pointer',
        className: 'contracts_Teams',
        objectId: teamRes.id,
      },
    ]);
    await updateUser.save(null, { useMasterKey: true });
  } catch (err) {
    console.log('err in add team, role, org', err);
    throw err;
  }
}

async function saveUser(userDetails) {
  const userRes = await findUserByEmail(userDetails.email);

  if (userRes) {
    return { id: userRes.id };
  } else {
    if (!userDetails.password) {
      throw new Parse.Error(Parse.Error.VALIDATION_ERROR, 'Password is required.');
    }
    const user = new Parse.User();
    user.set('username', userDetails.email);
    user.set('password', userDetails.password);
    user.set('email', userDetails.email);
    if (userDetails?.phone) {
      user.set('phone', userDetails.phone);
    }
    user.set('name', userDetails.name);

    const res = await user.signUp();
    // console.log("res ", res);
    return { id: res.id };
  }
}
export default async function AddAdmin(request) {
  const requestUser = await requireSessionUser(request);
  const userDetails = getUserDetails(request);
  await requireAdminUser(request, userDetails, requestUser);

  // const subscription = request.params.subscription;
  const user = await saveUser(userDetails);

  try {
    const extQuery = new Parse.Query('contracts_Users');
    extQuery.equalTo('UserId', {
      __type: 'Pointer',
      className: '_User',
      objectId: user.id,
    });
    const extUser = await extQuery.first({ useMasterKey: true });
    if (extUser) {
      return { message: 'User already exist' };
    } else {
      // console.log("role ", role);
      const partnerQuery = new Parse.Object('partners_Tenant');
      partnerQuery.set('UserId', {
        __type: 'Pointer',
        className: '_User',
        objectId: user.id,
      });

      if (userDetails?.phone) {
        partnerQuery.set('ContactNumber', userDetails.phone);
      }
      partnerQuery.set('TenantName', userDetails.company);
      partnerQuery.set('EmailAddress', userDetails.email);
      partnerQuery.set('IsActive', true);
      partnerQuery.set('CreatedBy', {
        __type: 'Pointer',
        className: '_User',
        objectId: user.id,
      });
      if (userDetails && userDetails.pincode) {
        partnerQuery.set('PinCode', userDetails.pincode);
      }
      if (userDetails && userDetails.country) {
        partnerQuery.set('Country', userDetails.country);
      }
      if (userDetails && userDetails.state) {
        partnerQuery.set('State', userDetails.state);
      }
      if (userDetails && userDetails.city) {
        partnerQuery.set('City', userDetails.city);
      }
      if (userDetails && userDetails.address) {
        partnerQuery.set('Address', userDetails.address);
      }
      const tenantRes = await partnerQuery.save(null, { useMasterKey: true });
      // console.log("tenantRes ", tenantRes);
      const newObj = new Parse.Object('contracts_Users');
      newObj.set('UserId', {
        __type: 'Pointer',
        className: '_User',
        objectId: user.id,
      });
      newObj.set('UserRole', ADMIN_ROLE);
      newObj.set('Email', userDetails.email);
      newObj.set('Name', userDetails.name);
      if (userDetails?.phone) {
        newObj.set('Phone', userDetails?.phone);
      }
      newObj.set('TenantId', {
        __type: 'Pointer',
        className: 'partners_Tenant',
        objectId: tenantRes.id,
      });
      if (userDetails && userDetails.company) {
        newObj.set('Company', userDetails.company);
      }
      if (userDetails && userDetails.jobTitle) {
        newObj.set('JobTitle', userDetails.jobTitle);
      }
      const extRes = await newObj.save(null, { useMasterKey: true });
      // if (subscription) {
      const extUser = {
        objectId: extRes.id,
        Name: userDetails.name,
        Email: userDetails.email,
        Phone: userDetails?.phone ? userDetails.phone : '',
        TenantId: { objectId: tenantRes.id },
        UserId: { objectId: user.id },
        UserRole: ADMIN_ROLE,
        Company: userDetails.company,
        JobTitle: userDetails.jobTitle,
      };
      await addTeamAndOrg(extUser);
      // await saveSubscription(extRes.id, user.id, tenantRes.id, subscription);
      // }
      return { message: 'User sign up' };
    }
  } catch (err) {
    console.log('Err ', err);
    const code = err?.code || 400;
    const message = err?.message || 'Something went wrong.';
    throw new Parse.Error(code, message);
  }
}

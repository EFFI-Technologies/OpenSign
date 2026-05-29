import { planCredits } from '../../Utils.js';
import { getRequestSessionToken, requireSessionUser } from '../../security/parseSessionAuth.js';
import { normalizeEmail } from './userLookup.js';

const PUBLIC_SIGNUP_ROLE = 'contracts_User';

function requireField(value, fieldName) {
  const sanitized = String(value || '').trim();
  if (!sanitized) {
    throw new Parse.Error(Parse.Error.VALIDATION_ERROR, `${fieldName} is required.`);
  }
  return sanitized;
}

async function getSignupUser(request, userDetails, sessionUser) {
  const requestUser = sessionUser || (await requireSessionUser(request));
  const requestedEmail = normalizeEmail(userDetails.email);
  const userEmail = normalizeEmail(requestUser.get('email') || requestUser.get('username'));

  if (!requestedEmail || requestedEmail !== userEmail) {
    throw new Parse.Error(
      Parse.Error.INVALID_SESSION_TOKEN,
      'Signup user must match the authenticated session.'
    );
  }

  return {
    id: requestUser.id,
    sessionToken: getRequestSessionToken(request.headers) || requestUser.getSessionToken?.(),
  };
}

export default async function usersignup(request) {
  const sessionUser = await requireSessionUser(request);
  const rawUserDetails = request.params?.userDetails || {};
  const userDetails = {
    ...rawUserDetails,
    name: requireField(rawUserDetails.name, 'Name'),
    email: normalizeEmail(requireField(rawUserDetails.email, 'Email')),
    company: requireField(rawUserDetails.company, 'Company'),
    phone: rawUserDetails.phone ? String(rawUserDetails.phone).trim() : '',
    jobTitle: rawUserDetails.jobTitle ? String(rawUserDetails.jobTitle).trim() : '',
    role: PUBLIC_SIGNUP_ROLE,
  };
  const subscription = request.params?.subscription;
  const user = await getSignupUser(request, userDetails, sessionUser);

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
      const partnerCls = Parse.Object.extend('partners_Tenant');
      const partnerQuery = new partnerCls();
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
      newObj.set('UserRole', userDetails.role);
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
      if (subscription) {
        await saveSubscription(extRes.id, user.id, tenantRes.id, subscription);
      }
      return { message: 'User sign up', sessionToken: user.sessionToken };
    }
  } catch (err) {
    console.log('Err ', err);
    const code = err?.code || 400;
    const message = err?.message || 'Something went wrong.';
    throw new Parse.Error(code, message);
  }
}

async function saveSubscription(extUserId, UserId, tenantId, subscription) {
  const SubscriptionId = subscription?.data?.subscription?.subscription_id || '';
  const Next_billing_date = subscription?.data?.subscription?.next_billing_at || '';
  const planCode = subscription?.data?.subscription?.plan?.plan_code || '';
  const credits = planCredits?.[planCode] || 0;

  try {
    const createSubscription = new Parse.Object('contracts_Subscriptions');
    createSubscription.set('SubscriptionId', SubscriptionId);
    createSubscription.set('SubscriptionDetails', subscription);
    createSubscription.set('ExtUserPtr', {
      __type: 'Pointer',
      className: 'contracts_Users',
      objectId: extUserId,
    });
    createSubscription.set('CreatedBy', {
      __type: 'Pointer',
      className: '_User',
      objectId: UserId,
    });
    createSubscription.set('TenantId', {
      __type: 'Pointer',
      className: 'partners_Tenant',
      objectId: tenantId,
    });
    createSubscription.set('Next_billing_date', new Date(Next_billing_date));
    createSubscription.set('PlanCode', planCode);
    if (credits > 0) {
      createSubscription.set('AllowedCredits', credits);
      createSubscription.set('PlanCredits', credits);
    }
    await createSubscription.save(null, { useMasterKey: true });
  } catch (err) {
    console.log('err in save subscription pgsignup', err);
  }
}

import axios from 'axios';
import { appName, updateMailCount } from '../../Utils.js';
import { cloudServerUrl } from '../../Utils.js';
import { requireCaptcha } from '../../security/captcha.js';
import { getRequestUser } from '../../security/parseSessionAuth.js';
import { normalizeEmail } from './userLookup.js';
import { canIssueOtp, generateOtp, OTP_SENT_RESPONSE, storeOtp } from './otpSecurity.js';

function collectEmails(value, emails = new Set()) {
  if (!value) {
    return emails;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      collectEmails(item, emails);
    }
    return emails;
  }

  if (typeof value === 'object') {
    for (const [key, fieldValue] of Object.entries(value)) {
      const normalizedKey = key.toLowerCase();
      if (
        typeof fieldValue === 'string' &&
        (normalizedKey === 'email' || normalizedKey === 'useremail')
      ) {
        const normalized = normalizeEmail(fieldValue);
        if (normalized) {
          emails.add(normalized);
        }
      } else if (Array.isArray(fieldValue) || typeof fieldValue === 'object') {
        collectEmails(fieldValue, emails);
      }
    }
  }

  return emails;
}

async function getDocumentOtpContext(docId, email) {
  try {
    const query = new Parse.Query('contracts_Document');
    query.equalTo('objectId', docId);
    query.include('ExtUserPtr');
    query.include('CreatedBy');
    query.include('Signers');
    query.include('AuditTrail.UserPtr');
    query.include('ExtUserPtr.TenantId');
    query.include('Placeholders');
    query.notEqualTo('IsArchive', true);
    const res = await query.first({ useMasterKey: true });
    if (!res) {
      return { allowed: false };
    }

    const _res = res.toJSON();
    const allowedEmails = new Set();
    collectEmails(_res?.Signers, allowedEmails);
    collectEmails(_res?.Placeholders, allowedEmails);
    collectEmails(_res?.Recipients, allowedEmails);

    return {
      allowed: allowedEmails.has(normalizeEmail(email)),
      extUserId: _res?.ExtUserPtr?.objectId,
      purpose: 'guest-doc',
    };
  } catch (err) {
    console.log('err ', err);
    return { allowed: false };
  }
}

async function getRequestUserSafe(request) {
  try {
    return await getRequestUser(request);
  } catch (err) {
    return null;
  }
}

async function getOtpContext(request, email) {
  const docId = request.params?.docId || '';
  if (docId) {
    return getDocumentOtpContext(docId, email);
  }

  const requestUser = await getRequestUserSafe(request);
  if (requestUser && normalizeEmail(requestUser.get('email')) === normalizeEmail(email)) {
    return {
      allowed: true,
      purpose: 'email-verify',
      userId: requestUser.id,
      canLogin: false,
    };
  }

  return { allowed: false };
}

async function requireOtpCaptcha(request, requestUser) {
  const isCurrentUserEmailVerification = !request.params?.docId && requestUser;
  if (isCurrentUserEmailVerification) {
    return;
  }

  await requireCaptcha({
    context: request.context,
    headers: request.headers,
    ip: request.ip,
    master: request.master,
  });
}

async function sendMailOTPv1(request) {
  try {
    //--for elearning app side
    const code = generateOtp();
    const email = normalizeEmail(request.params.email);
    const tenantId = request.params.TenantId ? request.params.TenantId : undefined;

    if (email) {
      const requestUser = await getRequestUserSafe(request);
      await requireOtpCaptcha(request, requestUser);

      const context = await getOtpContext(request, email);
      if (!context.allowed) {
        return OTP_SENT_RESPONSE;
      }

      const canSend = await canIssueOtp(email, request);
      if (!canSend) {
        return OTP_SENT_RESPONSE;
      }

      const recipient = email;
      try {
        let url = `${cloudServerUrl}/functions/sendmailv3/`;
        const headers = {
          'Content-Type': 'application/json',
          'X-Parse-Application-Id': process.env.APP_ID,
          'X-Parse-Master-Key': process.env.MASTER_KEY,
        };
        let params = {
          recipient: recipient,
          subject: `Your ${appName} OTP`,
          from: 'no-reply@esign.com.au',
          html:
            `<html><head><meta http-equiv='Content-Type' content='text/html; charset=UTF-8' /></head><body><div style='background-color:#f5f5f5;padding:20px'><div style='box-shadow: rgba(0, 0, 0, 0.1) 0px 4px 12px;background-color:white;'><div style='background-color:red;padding:2px;font-family:system-ui; background-color:#47a3ad;'>    <p style='font-size:20px;font-weight:400;color:white;padding-left:20px',>OTP Verification</p></div><div style='padding:20px'><p style='font-family:system-ui;font-size:14px'>Your OTP for ${appName} verification is:</p><p style=' text-decoration: none; font-weight: bolder; color:blue;font-size:45px;margin:20px'>` +
            code +
            '</p></div> </div> </div></body></html>',
          extUserId: context.extUserId,
        };
        await axios.post(url, params, { headers: headers });
        if (request.params?.docId) {
          if (context.extUserId) {
            updateMailCount(context.extUserId);
          }
        }
      } catch (err) {
        console.log('error in send OTP mail', err);
      }

      await storeOtp({
        email,
        otp: code,
        purpose: context.purpose,
        docId: request.params?.docId,
        tenantId,
        userId: context.userId,
        canLogin: context.canLogin !== false,
      });

      return OTP_SENT_RESPONSE;
    } else {
      return 'Please Enter valid email';
    }
  } catch (err) {
    console.log('err in sendMailOTPv1');
    console.log(err);
    if (err?.code === 142) {
      throw err;
    }
    return err;
  }
}
export default sendMailOTPv1;

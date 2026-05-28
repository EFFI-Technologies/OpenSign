import axios from 'axios';
import { cloudServerUrl } from '../../Utils.js';
import { findUserByEmail, normalizeEmail } from './userLookup.js';
import { OTP_INVALID_RESPONSE, verifyOtpForEmail } from './otpSecurity.js';

async function getToken(user) {
  const serverUrl = cloudServerUrl; //process.env.SERVER_URL;
  const APPID = process.env.APP_ID;
  const masterKEY = process.env.MASTER_KEY;

  const res = await axios({
    method: 'POST',
    url: `${serverUrl}/loginAs`,
    headers: {
      'Content-Type': 'application/json;charset=utf-8',
      'X-Parse-Application-Id': APPID,
      'X-Parse-Master-Key': masterKEY,
    },
    params: {
      userId: user.id,
    },
  });

  return res.data || null;
}

async function AuthLoginAsMail(request) {
  try {
    const otp = request.params.otp;
    const email = normalizeEmail(request.params.email);

    const otpResult = await verifyOtpForEmail(email, otp, request);
    if (!otpResult.ok || !otpResult.canLogin || otpResult.purpose !== 'guest-doc') {
      return OTP_INVALID_RESPONSE;
    }

    const user = await findUserByEmail(email);
    if (!user) {
      return OTP_INVALID_RESPONSE;
    }

    const result = await getToken(user);
    if (result && !result?.emailVerified) {
      const userQuery = new Parse.Query(Parse.User);
      const parseUser = await userQuery.get(result?.objectId, {
        sessionToken: result.sessionToken,
      });
      // Update the emailVerified field to true
      parseUser.set('emailVerified', true);
      // Save the user object
      const res = await parseUser.save(null, { useMasterKey: true });
      if (res) {
        return result;
      }
      return OTP_INVALID_RESPONSE;
    } else {
      return result;
    }
  } catch (err) {
    console.log('err in Auth');
    console.log(err);
    return OTP_INVALID_RESPONSE;
  }
}
export default AuthLoginAsMail;

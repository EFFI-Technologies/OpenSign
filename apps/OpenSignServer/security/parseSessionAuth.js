export function getRequestSessionToken(headers = {}) {
  return headers['x-parse-session-token'] || headers.sessiontoken || headers.sessionToken || '';
}

export function normalizeParseSessionHeaders(req, _res, next) {
  const sessionToken = getRequestSessionToken(req.headers);

  if (sessionToken) {
    req.headers['x-parse-session-token'] = sessionToken;
    req.headers.sessiontoken = sessionToken;
  }

  next();
}

export async function getRequestUser(request) {
  if (request?.user?.id) {
    return request.user;
  }

  const sessionToken = getRequestSessionToken(request?.headers);
  if (!sessionToken) {
    return null;
  }

  const sessionQuery = new Parse.Query(Parse.Session);
  sessionQuery.equalTo('sessionToken', sessionToken);
  sessionQuery.include('user');

  const session = await sessionQuery.first({ useMasterKey: true });
  const user = session?.get('user');
  const expiresAt = session?.get('expiresAt');

  if (!user || (expiresAt && new Date(expiresAt) <= new Date())) {
    throw new Parse.Error(Parse.Error.INVALID_SESSION_TOKEN, 'Invalid session token.');
  }

  request.user = user;
  return user;
}

export async function requireSessionUser(request) {
  const user = await getRequestUser(request);

  if (!user) {
    throw new Parse.Error(Parse.Error.INVALID_SESSION_TOKEN, 'User is not authenticated.');
  }

  return user;
}

export async function requireSessionUserId(request) {
  const user = await requireSessionUser(request);
  return user.id;
}

export async function requireSessionUserEmail(request) {
  const user = await requireSessionUser(request);
  return user.get('email');
}

export async function requireCurrentExtUser(request) {
  const userId = await requireSessionUserId(request);
  const extUserQuery = new Parse.Query('contracts_Users');
  extUserQuery.equalTo('UserId', {
    __type: 'Pointer',
    className: '_User',
    objectId: userId,
  });

  const extUser = await extUserQuery.first({ useMasterKey: true });

  if (!extUser) {
    throw new Parse.Error(Parse.Error.OBJECT_NOT_FOUND, 'User not found.');
  }

  return extUser;
}

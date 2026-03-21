export default async function upsertContact(request, response) {
  const name = request.body.name;
  const phone = request.body?.phone;
  const email = request.body.email;
  const reqToken = request.headers['x-api-token'];
  if (!reqToken) {
    return response.status(400).json({ error: 'Please Provide API Token' });
  }
  try {
    const tokenQuery = new Parse.Query('appToken');
    tokenQuery.equalTo('token', reqToken);
    tokenQuery.include('userId');
    const token = await tokenQuery.first({ useMasterKey: true });
    if (token === undefined) {
      return response.status(405).json({ error: 'Invalid API Token!' });
    }

    const parseUser = JSON.parse(JSON.stringify(token));
    const userPtr = {
      __type: 'Pointer',
      className: '_User',
      objectId: parseUser.userId.objectId,
    };

    const contactbook = new Parse.Query('contracts_Contactbook');
    contactbook.equalTo('Email', email);
    contactbook.equalTo('CreatedBy', userPtr);
    contactbook.notEqualTo('IsDeleted', true);
    const existing = await contactbook.first({ useMasterKey: true });

    if (existing) {
      if (name) existing.set('Name', name);
      if (phone !== undefined) existing.set('Phone', phone);
      const saved = await existing.save(null, { useMasterKey: true });
      const parsed = JSON.parse(JSON.stringify(saved));
      return response.json({
        objectId: parsed.objectId,
        name: parsed.Name,
        email: parsed.Email,
        phone: parsed?.Phone || '',
        createdAt: parsed.createdAt,
        updatedAt: parsed.updatedAt,
      });
    }

    // Contact does not exist — create it
    const Tenant = new Parse.Query('partners_Tenant');
    Tenant.equalTo('UserId', userPtr);
    const tenantRes = await Tenant.first({ useMasterKey: true });

    const contactQuery = new Parse.Object('contracts_Contactbook');
    contactQuery.set('Name', name);
    if (phone) {
      contactQuery.set('Phone', phone);
    }
    contactQuery.set('Email', email);
    contactQuery.set('UserRole', 'contracts_Guest');
    if (tenantRes && tenantRes.id) {
      contactQuery.set('TenantId', {
        __type: 'Pointer',
        className: 'partners_Tenant',
        objectId: tenantRes.id,
      });
    }

    let userId;
    try {
      const _users = Parse.Object.extend('User');
      const _user = new _users();
      _user.set('name', name);
      _user.set('username', email);
      _user.set('email', email);
      _user.set('password', email);
      if (phone) {
        _user.set('phone', phone);
      }
      const user = await _user.save();
      userId = user.id;
    } catch (err) {
      if (err.code === 202) {
        // Username already taken — look up existing _User
        const userRes = await Parse.Cloud.run('getUserId', { email });
        userId = userRes.id;
      } else {
        throw err;
      }
    }

    contactQuery.set('CreatedBy', userPtr);
    contactQuery.set('UserId', {
      __type: 'Pointer',
      className: '_User',
      objectId: userId,
    });

    const acl = new Parse.ACL();
    acl.setReadAccess(userPtr.objectId, true);
    acl.setWriteAccess(userPtr.objectId, true);
    acl.setReadAccess(userId, true);
    acl.setWriteAccess(userId, true);
    contactQuery.setACL(acl);

    const contactRes = await contactQuery.save(null, { useMasterKey: true });
    const parseRes = JSON.parse(JSON.stringify(contactRes));
    return response.json({
      objectId: parseRes.objectId,
      name: parseRes.Name,
      email: parseRes.Email,
      phone: parseRes?.Phone || '',
      createdAt: parseRes.createdAt,
      updatedAt: parseRes.updatedAt,
    });
  } catch (err) {
    console.log('err in upsertContact', err);
    return response.status(400).json({ error: 'Something went wrong, please try again later!' });
  }
}

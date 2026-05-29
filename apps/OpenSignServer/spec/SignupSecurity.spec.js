async function createUser(email) {
  const user = new Parse.User();
  user.set('username', email);
  user.set('email', email);
  user.set('password', 'Password123!');
  user.set('name', 'Signup Test');
  return user.save(null, { useMasterKey: true });
}

async function createExtUser(user, role = 'contracts_User') {
  const tenant = new Parse.Object('partners_Tenant');
  tenant.set('TenantName', 'Security Test Tenant');
  tenant.set('UserId', user);
  const savedTenant = await tenant.save(null, { useMasterKey: true });

  const org = new Parse.Object('contracts_Organizations');
  org.set('Name', 'Security Test Org');
  org.set('TenantId', savedTenant);
  const savedOrg = await org.save(null, { useMasterKey: true });

  const extUser = new Parse.Object('contracts_Users');
  extUser.set('UserId', user);
  extUser.set('UserRole', role);
  extUser.set('Email', user.get('email'));
  extUser.set('Name', user.get('name'));
  extUser.set('TenantId', savedTenant);
  extUser.set('OrganizationId', savedOrg);
  return extUser.save(null, { useMasterKey: true });
}

async function disableActiveAdmins() {
  const query = new Parse.Query('contracts_Users');
  query.equalTo('UserRole', 'contracts_Admin');
  const admins = await query.find({ useMasterKey: true });
  for (const admin of admins) {
    admin.set('IsDisabled', true);
  }
  if (admins.length > 0) {
    await Parse.Object.saveAll(admins, { useMasterKey: true });
  }
}

describe('signup security', () => {
  let AddAdmin;
  let usersignup;

  beforeAll(async () => {
    ({ default: AddAdmin } = await import('../cloud/parsefunction/AddAdmin.js'));
    ({ default: usersignup } = await import('../cloud/parsefunction/usersignup.js'));
  });

  it('requires a logged-in user for public usersignup', async () => {
    try {
      await usersignup({ params: {} });
      fail('expected anonymous empty signup finalization to throw');
    } catch (err) {
      expect(err.code).toBe(Parse.Error.INVALID_SESSION_TOKEN);
    }

    try {
      await usersignup({
        params: {
          userDetails: {
            name: 'Anonymous',
            email: 'anonymous@example.com',
            company: 'Example Co',
            role: 'contracts_Admin',
          },
        },
      });
      fail('expected anonymous signup finalization to throw');
    } catch (err) {
      expect(err.code).toBe(Parse.Error.INVALID_SESSION_TOKEN);
    }
  });

  it('requires usersignup email to match the authenticated session', async () => {
    const user = await createUser(`owner-${Date.now()}@example.com`);

    try {
      await usersignup({
        user,
        params: {
          userDetails: {
            name: 'Wrong User',
            email: `other-${Date.now()}@example.com`,
            company: 'Example Co',
            role: 'contracts_User',
          },
        },
      });
      fail('expected mismatched signup finalization to throw');
    } catch (err) {
      expect(err.code).toBe(Parse.Error.INVALID_SESSION_TOKEN);
    }
  });

  it('finalizes public usersignup only for the authenticated user record', async () => {
    const email = `signup-${Date.now()}@example.com`;
    const user = await createUser(email);

    const result = await usersignup({
      user,
      headers: { 'x-parse-session-token': 'test-session-token' },
      params: {
        userDetails: {
          name: 'Signup User',
          email,
          phone: '0400000000',
          company: 'Example Co',
          jobTitle: 'Broker',
          role: 'contracts_OrgAdmin',
        },
      },
    });

    expect(result.sessionToken).toBe('test-session-token');

    const extQuery = new Parse.Query('contracts_Users');
    extQuery.equalTo('UserId', user);
    const extUser = await extQuery.first({ useMasterKey: true });
    expect(extUser.get('UserRole')).not.toBe('contracts_OrgAdmin');
    expect(extUser.get('Email')).toBe(email);
    expect(extUser.get('TenantId')).toBeDefined();
  });

  it('bootstraps the first admin only for the matching authenticated signup user', async () => {
    await disableActiveAdmins();
    const email = `bootstrap-admin-${Date.now()}@example.com`;
    const user = await createUser(email);

    const result = await AddAdmin({
      user,
      params: {
        userDetails: {
          name: 'Bootstrap Admin',
          email,
          company: 'Example Co',
          role: 'contracts_OrgAdmin',
        },
      },
    });

    expect(result.message).toBe('User sign up');
    expect(result.sessionToken).toBeUndefined();

    const extQuery = new Parse.Query('contracts_Users');
    extQuery.equalTo('UserId', user);
    const extUser = await extQuery.first({ useMasterKey: true });
    expect(extUser.get('UserRole')).toBe('contracts_Admin');
    expect(extUser.get('OrganizationId')).toBeDefined();
  });

  it('requires an authenticated admin for addadmin', async () => {
    try {
      await AddAdmin({ params: {} });
      fail('expected anonymous empty addadmin to throw');
    } catch (err) {
      expect(err.code).toBe(Parse.Error.INVALID_SESSION_TOKEN);
    }

    try {
      await AddAdmin({
        params: {
          userDetails: {
            name: 'Admin',
            email: `admin-${Date.now()}@example.com`,
            company: 'Example Co',
            role: 'contracts_Admin',
          },
        },
      });
      fail('expected anonymous addadmin to throw');
    } catch (err) {
      expect(err.code).toBe(Parse.Error.INVALID_SESSION_TOKEN);
    }

    const user = await createUser(`non-admin-${Date.now()}@example.com`);
    try {
      await AddAdmin({
        user,
        params: {
          userDetails: {
            name: 'Admin',
            email: `admin-${Date.now()}@example.com`,
            company: 'Example Co',
            role: 'contracts_Admin',
          },
        },
      });
      fail('expected non-admin addadmin to throw');
    } catch (err) {
      expect(err.code).toBe(Parse.Error.OPERATION_FORBIDDEN);
    }
  });

  it('does not allow org admins to create top-level admins', async () => {
    const orgAdmin = await createUser(`org-admin-${Date.now()}@example.com`);
    await createExtUser(orgAdmin, 'contracts_OrgAdmin');

    try {
      await AddAdmin({
        user: orgAdmin,
        params: {
          userDetails: {
            name: 'Target Admin',
            email: `target-admin-${Date.now()}@example.com`,
            company: 'Example Co',
            role: 'contracts_Admin',
          },
        },
      });
      fail('expected org admin addadmin to throw');
    } catch (err) {
      expect(err.code).toBe(Parse.Error.OPERATION_FORBIDDEN);
    }
  });

  it('forces addadmin-created users to the admin role without returning their session token', async () => {
    const caller = await createUser(`caller-admin-${Date.now()}@example.com`);
    await createExtUser(caller, 'contracts_Admin');
    const target = await createUser(`created-admin-${Date.now()}@example.com`);

    const result = await AddAdmin({
      user: caller,
      params: {
        userDetails: {
          name: 'Created Admin',
          email: target.get('email'),
          company: 'Example Co',
          role: 'contracts_OrgAdmin',
        },
      },
    });

    expect(result.message).toBe('User sign up');
    expect(result.sessionToken).toBeUndefined();

    const extQuery = new Parse.Query('contracts_Users');
    extQuery.equalTo('UserId', target);
    const extUser = await extQuery.first({ useMasterKey: true });
    expect(extUser.get('UserRole')).toBe('contracts_Admin');
  });
});

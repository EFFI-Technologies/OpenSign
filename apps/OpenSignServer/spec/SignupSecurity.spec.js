async function createUser(email) {
  const user = new Parse.User();
  user.set('username', email);
  user.set('email', email);
  user.set('password', 'Password123!');
  user.set('name', 'Signup Test');
  return user.save(null, { useMasterKey: true });
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

  it('requires an authenticated admin for addadmin', async () => {
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
});

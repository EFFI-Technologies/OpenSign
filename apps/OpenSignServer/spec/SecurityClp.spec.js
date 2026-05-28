import security from '../security/parseClassLevelPermissions.cjs';

const { classLevelPermissions } = security;

describe('security class-level permissions', () => {
  const exposedClasses = [
    'partners_Tenant',
    'contracts_Contactbook',
    'contracts_Webhook',
    'contracts_Signature',
    'defaultdata_Otp',
    'defaultdata_OtpRateLimit',
  ];

  it('does not allow public wildcard access on the reported exposed classes', () => {
    for (const className of exposedClasses) {
      const clp = classLevelPermissions[className];
      for (const operation of ['get', 'find', 'count', 'create', 'update', 'delete', 'addField']) {
        expect(clp[operation]?.['*']).not.toBe(true);
      }
    }
  });

  it('locks tenant and webhook data to master-key access', () => {
    expect(classLevelPermissions.partners_Tenant.find).toEqual({});
    expect(classLevelPermissions.partners_Tenant.update).toEqual({});
    expect(classLevelPermissions.contracts_Webhook.find).toEqual({});
    expect(classLevelPermissions.contracts_Webhook.delete).toEqual({});
  });

  it('scopes contacts and signatures to their user pointer fields', () => {
    expect(classLevelPermissions.contracts_Contactbook.readUserFields).toEqual([
      'CreatedBy',
      'UserId',
    ]);
    expect(classLevelPermissions.contracts_Contactbook.writeUserFields).toEqual([
      'CreatedBy',
      'UserId',
    ]);
    expect(classLevelPermissions.contracts_Signature.readUserFields).toEqual(['UserId']);
    expect(classLevelPermissions.contracts_Signature.writeUserFields).toEqual(['UserId']);
  });
});

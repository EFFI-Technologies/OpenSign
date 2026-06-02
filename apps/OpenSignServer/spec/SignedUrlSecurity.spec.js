import { getSignedUrl } from '../cloud/parsefunction/getSignedUrl.js';
import getDocument from '../cloud/parsefunction/getDocument.js';
import GetTemplate from '../cloud/parsefunction/GetTemplate.js';

const signingEnv = {
  DO_ACCESS_KEY_ID: 'test-access-key',
  DO_SECRET_ACCESS_KEY: 'test-secret-key',
  DO_REGION: 'us-east-1',
  DO_SPACE: 'test-bucket',
  DO_ENDPOINT: 'https://s3.amazonaws.com',
};

async function createUser(prefix) {
  const email = `${prefix}-${Date.now()}@example.com`;
  const user = new Parse.User();
  user.set('username', email);
  user.set('email', email);
  user.set('password', 'password123');
  return user.save(null, { useMasterKey: true });
}

async function createExtUser(user, prefix) {
  const tenant = new Parse.Object('partners_Tenant');
  tenant.set('Name', `${prefix} tenant`);
  tenant.set('UserId', user);
  const savedTenant = await tenant.save(null, { useMasterKey: true });

  const extUser = new Parse.Object('contracts_Users');
  extUser.set('Name', prefix);
  extUser.set('Email', user.get('email'));
  extUser.set('UserId', user);
  extUser.set('TenantId', savedTenant);
  return extUser.save(null, { useMasterKey: true });
}

async function createDocument({ owner, extUser, url, isEnableOTP }) {
  const document = new Parse.Object('contracts_Document');
  document.set('Name', 'Signed URL security test');
  document.set('URL', url);
  document.set('CreatedBy', owner);
  document.set('ExtUserPtr', extUser);
  document.set('IsEnableOTP', isEnableOTP);
  document.set('IsArchive', false);

  const acl = new Parse.ACL();
  acl.setReadAccess(owner.id, true);
  acl.setWriteAccess(owner.id, true);
  document.setACL(acl);

  return document.save(null, { useMasterKey: true });
}

async function createTemplate({ owner, extUser, url, isPublic }) {
  const template = new Parse.Object('contracts_Template');
  template.set('Name', 'Signed URL template test');
  template.set('URL', url);
  template.set('CreatedBy', owner);
  template.set('ExtUserPtr', extUser);
  template.set('IsPublic', isPublic);

  const acl = new Parse.ACL();
  acl.setReadAccess(owner.id, true);
  acl.setWriteAccess(owner.id, true);
  template.setACL(acl);

  return template.save(null, { useMasterKey: true });
}

async function createContact({ owner, signer, email }) {
  const contact = new Parse.Object('contracts_Contactbook');
  contact.set('Name', 'Signer');
  contact.set('Email', email);
  contact.set('CreatedBy', owner);
  contact.set('UserId', signer);

  const acl = new Parse.ACL();
  acl.setReadAccess(owner.id, true);
  acl.setWriteAccess(owner.id, true);
  acl.setReadAccess(signer.id, true);
  contact.setACL(acl);

  return contact.save(null, { useMasterKey: true });
}

describe('signed URL authorization', () => {
  const originalEnv = {};

  beforeAll(() => {
    for (const key of Object.keys(signingEnv)) {
      originalEnv[key] = process.env[key];
      process.env[key] = signingEnv[key];
    }
  });

  afterAll(() => {
    for (const key of Object.keys(signingEnv)) {
      if (originalEnv[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = originalEnv[key];
      }
    }
  });

  it('does not mint a URL for an object key that is not stored on the document', async () => {
    const owner = await createUser('signed-url-owner');
    const extUser = await createExtUser(owner, 'Owner');
    const document = await createDocument({
      owner,
      extUser,
      url: 'https://test-bucket.s3.amazonaws.com/original.pdf',
      isEnableOTP: false,
    });

    try {
      await getSignedUrl({
        params: {
          docId: document.id,
          url: 'https://test-bucket.s3.amazonaws.com/other.pdf',
        },
        headers: {},
      });
      fail('expected mismatched object key to be rejected');
    } catch (err) {
      expect(err.code).toBe(Parse.Error.OPERATION_FORBIDDEN);
    }
  });

  it('keeps the non-OTP public signing flow working for the document URL', async () => {
    const owner = await createUser('signed-url-public');
    const extUser = await createExtUser(owner, 'Owner');
    const document = await createDocument({
      owner,
      extUser,
      url: 'https://test-bucket.s3.amazonaws.com/public-flow.pdf',
      isEnableOTP: false,
    });

    const signedUrl = await getSignedUrl({
      params: {
        docId: document.id,
        url: 'https://test-bucket.s3.amazonaws.com/public-flow.pdf',
      },
      headers: {},
    });

    expect(signedUrl).toContain('public-flow.pdf');
  });

  it('requires read access for OTP-protected document URLs', async () => {
    const owner = await createUser('signed-url-private-owner');
    const otherUser = await createUser('signed-url-private-other');
    const extUser = await createExtUser(owner, 'Owner');
    const document = await createDocument({
      owner,
      extUser,
      url: 'https://test-bucket.s3.amazonaws.com/private-flow.pdf',
      isEnableOTP: true,
    });

    try {
      await getSignedUrl({
        user: otherUser,
        params: {
          docId: document.id,
          url: 'https://test-bucket.s3.amazonaws.com/private-flow.pdf',
        },
        headers: {},
      });
      fail('expected non-reader to be rejected');
    } catch (err) {
      expect(err.code).toBe(Parse.Error.OPERATION_FORBIDDEN);
    }

    const signedUrl = await getSignedUrl({
      user: owner,
      params: {
        docId: document.id,
        url: 'https://test-bucket.s3.amazonaws.com/private-flow.pdf',
      },
      headers: {},
    });

    expect(signedUrl).toContain('private-flow.pdf');
  });

  it('requires the signer contact id for unauthenticated non-OTP document reads', async () => {
    const owner = await createUser('document-public-owner');
    const signer = await createUser('document-public-signer');
    const extUser = await createExtUser(owner, 'Owner');
    const contact = await createContact({
      owner,
      signer,
      email: signer.get('email'),
    });
    const document = await createDocument({
      owner,
      extUser,
      url: 'https://test-bucket.s3.amazonaws.com/contact-flow.pdf',
      isEnableOTP: false,
    });
    document.set('Signers', [contact]);
    document.set('Placeholders', [{ signerObjId: contact.id }]);
    await document.save(null, { useMasterKey: true });

    const denied = await getDocument({
      params: { docId: document.id },
      headers: {},
    });
    expect(denied.error).toBe("You don't have access of this document!");

    const allowed = await getDocument({
      params: { docId: document.id, contactId: contact.id },
      headers: {},
    });
    expect(allowed.objectId).toBe(document.id);
    expect(allowed.URL).toContain('contact-flow.pdf');
  });

  it('does not return private template URLs through the public template path', async () => {
    const owner = await createUser('template-private-owner');
    const extUser = await createExtUser(owner, 'Owner');
    const template = await createTemplate({
      owner,
      extUser,
      url: 'https://test-bucket.s3.amazonaws.com/private-template.pdf',
      isPublic: false,
    });

    const denied = await GetTemplate({
      params: { templateId: template.id, ispublic: true },
      headers: {},
    });

    expect(denied.error).toBe("You don't have access of this document!");
    expect(denied.URL).toBeUndefined();
  });
});

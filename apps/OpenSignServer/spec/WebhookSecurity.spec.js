import axios from 'axios';
import callWebhook from '../cloud/parsefunction/callWebhook.js';

async function createUser(prefix) {
  const email = `${prefix}-${Date.now()}@example.com`;
  const user = new Parse.User();
  user.set('username', email);
  user.set('email', email);
  user.set('password', 'password123');
  return user.save(null, { useMasterKey: true });
}

async function createExtUser(owner, webhookUrl) {
  const tenant = new Parse.Object('partners_Tenant');
  tenant.set('Name', 'Webhook Tenant');
  tenant.set('UserId', owner);
  const savedTenant = await tenant.save(null, { useMasterKey: true });

  const extUser = new Parse.Object('contracts_Users');
  extUser.set('Name', 'Webhook Owner');
  extUser.set('Email', owner.get('email'));
  extUser.set('UserId', owner);
  extUser.set('TenantId', savedTenant);
  extUser.set('Webhook', webhookUrl);
  return extUser.save(null, { useMasterKey: true });
}

async function createContact({ owner, signer }) {
  const contact = new Parse.Object('contracts_Contactbook');
  contact.set('Name', 'Webhook Signer');
  contact.set('Email', signer.get('email'));
  contact.set('CreatedBy', owner);
  contact.set('UserId', signer);
  return contact.save(null, { useMasterKey: true });
}

async function createDocument({ owner, extUser, contact }) {
  const document = new Parse.Object('contracts_Document');
  document.set('Name', 'Webhook Test');
  document.set('URL', 'https://example.com/document.pdf');
  document.set('CreatedBy', owner);
  document.set('ExtUserPtr', extUser);
  document.set('IsEnableOTP', true);
  document.set('Signers', [contact]);
  document.set('IsArchive', false);

  const acl = new Parse.ACL();
  acl.setReadAccess(owner.id, true);
  acl.setWriteAccess(owner.id, true);
  document.setACL(acl);

  return document.save(null, { useMasterKey: true });
}

describe('webhook delivery', () => {
  it('allows an OTP document signer contact to trigger the viewed webhook', async () => {
    const webhookUrl = 'https://webhook.example.test/events';
    const owner = await createUser('webhook-owner');
    const signer = await createUser('webhook-signer');
    const extUser = await createExtUser(owner, webhookUrl);
    const contact = await createContact({ owner, signer });
    const document = await createDocument({ owner, extUser, contact });
    spyOn(axios, 'post').and.resolveTo({ status: 204 });

    const result = await callWebhook({
      params: {
        event: 'viewed',
        contactId: contact.id,
        body: {
          objectId: document.id,
          file: 'https://example.com/document.pdf',
          name: 'Webhook Test',
        },
      },
      headers: { 'x-real-ip': '127.0.0.4' },
    });

    expect(result.message).toBe('webhook called!');
    expect(axios.post).toHaveBeenCalledWith(
      webhookUrl,
      jasmine.objectContaining({ event: 'viewed', objectId: document.id }),
      { headers: { 'Content-Type': 'application/json' } }
    );

    const logQuery = new Parse.Query('contracts_Webhook');
    const log = await logQuery.first({ useMasterKey: true });
    expect(log.get('Log')).toBe(204);
    expect(log.get('UserId').id).toBe(signer.id);
  });
});

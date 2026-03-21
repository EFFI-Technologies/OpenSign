import axios from 'axios';

const BASE_URL = 'http://127.0.0.1:30001/v1/upsertcontact';
const headers = token => ({
  'Content-Type': 'application/json',
  'x-api-token': token,
});

describe('upsertContact', () => {
  let apiToken;

  beforeAll(async () => {
    const email = `upsert-test-${Date.now()}@example.com`;
    const user = new Parse.User();
    user.set('username', email);
    user.set('password', 'password123');
    user.set('email', email);
    const savedUser = await user.save(null, { useMasterKey: true });

    apiToken = `test-token-${Date.now()}`;
    const token = new Parse.Object('appToken');
    token.set('token', apiToken);
    token.set('userId', savedUser);
    await token.save(null, { useMasterKey: true });
  });

  it('returns 400 when API token is missing', async () => {
    try {
      await axios.post(BASE_URL, { name: 'Test', email: 'test@example.com' });
      fail('expected request to throw');
    } catch (err) {
      expect(err.response.status).toBe(400);
      expect(err.response.data.error).toBe('Please Provide API Token');
    }
  });

  it('returns 405 when API token is invalid', async () => {
    try {
      await axios.post(
        BASE_URL,
        { name: 'Test', email: 'test@example.com' },
        { headers: headers('not-a-real-token') }
      );
      fail('expected request to throw');
    } catch (err) {
      expect(err.response.status).toBe(405);
      expect(err.response.data.error).toBe('Invalid API Token!');
    }
  });

  it('creates a new contact and returns its data', async () => {
    const email = `create-${Date.now()}@example.com`;
    const res = await axios.post(
      BASE_URL,
      { name: 'New Contact', email, phone: '0400000001' },
      { headers: headers(apiToken) }
    );

    expect(res.status).toBe(200);
    expect(res.data.objectId).toBeDefined();
    expect(res.data.email).toBe(email);
    expect(res.data.name).toBe('New Contact');
    expect(res.data.phone).toBe('0400000001');
  });

  it('updates an existing contact and returns the same objectId', async () => {
    const email = `upsert-${Date.now()}@example.com`;

    const first = await axios.post(
      BASE_URL,
      { name: 'Original Name', email, phone: '0400000002' },
      { headers: headers(apiToken) }
    );
    expect(first.status).toBe(200);

    const second = await axios.post(
      BASE_URL,
      { name: 'Updated Name', email, phone: '0499999999' },
      { headers: headers(apiToken) }
    );
    expect(second.status).toBe(200);
    expect(second.data.objectId).toBe(first.data.objectId);
    expect(second.data.name).toBe('Updated Name');
    expect(second.data.phone).toBe('0499999999');
  });

  it('does not create duplicate contacts for the same email', async () => {
    const email = `dedup-${Date.now()}@example.com`;

    await axios.post(BASE_URL, { name: 'First Call', email }, { headers: headers(apiToken) });
    await axios.post(BASE_URL, { name: 'Second Call', email }, { headers: headers(apiToken) });

    const query = new Parse.Query('contracts_Contactbook');
    query.equalTo('Email', email);
    const results = await query.find({ useMasterKey: true });
    expect(results.length).toBe(1);
  });

  it('creates a second contact for the same email under a different user', async () => {
    const email = `shared-${Date.now()}@example.com`;

    // Create a second user + token
    const email2 = `owner2-${Date.now()}@example.com`;
    const user2 = new Parse.User();
    user2.set('username', email2);
    user2.set('password', 'password123');
    user2.set('email', email2);
    const savedUser2 = await user2.save(null, { useMasterKey: true });

    const token2 = `token2-${Date.now()}`;
    const tokenObj = new Parse.Object('appToken');
    tokenObj.set('token', token2);
    tokenObj.set('userId', savedUser2);
    await tokenObj.save(null, { useMasterKey: true });

    await axios.post(BASE_URL, { name: 'User One', email }, { headers: headers(apiToken) });
    await axios.post(BASE_URL, { name: 'User Two', email }, { headers: headers(token2) });

    const query = new Parse.Query('contracts_Contactbook');
    query.equalTo('Email', email);
    const results = await query.find({ useMasterKey: true });
    expect(results.length).toBe(2);
  });
});

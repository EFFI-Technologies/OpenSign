import { startParseServer, stopParseServer, dropDB } from './utils/test-runner.js';
beforeAll(
  async () => {
    await startParseServer();
  },
  1000 * 60 * 2
);

afterAll(async () => {
  await dropDB();
  await stopParseServer();
});

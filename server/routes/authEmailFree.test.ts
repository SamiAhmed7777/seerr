import assert from 'node:assert/strict';
import { before, beforeEach, describe, it } from 'node:test';

import { UserType } from '@server/constants/user';
import { getRepository } from '@server/datasource';
import { User } from '@server/entity/User';
import { getSettings } from '@server/lib/settings';
import { checkUser } from '@server/middleware/auth';
import { setupTestDb } from '@server/test/db';
import type { Express } from 'express';
import express from 'express';
import session from 'express-session';
import request from 'supertest';
import authRoutes from './auth';

let app: Express;

function createApp() {
  const app = express();
  app.use(express.json());
  app.use(
    session({
      secret: 'test-secret',
      resave: false,
      saveUninitialized: false,
    })
  );
  app.use(checkUser);
  app.use('/auth', authRoutes);
  // Error handler matching how next({ status, message }) calls are handled
  app.use(
    (
      err: { status?: number; message?: string },
      _req: express.Request,
      res: express.Response,
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      _next: express.NextFunction
    ) => {
      res
        .status(err.status ?? 500)
        .json({ status: err.status ?? 500, message: err.message });
    }
  );
  return app;
}

before(async () => {
  app = createApp();
});

setupTestDb();

describe('POST /auth/register (email-free signup)', () => {
  beforeEach(() => {
    getSettings().main.localLogin = true;
  });

  it('creates a LOCAL account from username + password only', async () => {
    const res = await request(app)
      .post('/auth/register')
      .send({ username: 'newviewer', password: 'password123' });

    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.body.username, 'newviewer');
    assert.ok('id' in res.body);
    assert.ok(!('email' in res.body));
    assert.ok(!('password' in res.body));
  });

  it('stores the username in the identity column, lowercased', async () => {
    await request(app)
      .post('/auth/register')
      .send({ username: 'MixedCase', password: 'password123' });

    const repo = getRepository(User);
    const user = await repo.findOne({
      where: { email: 'mixedcase' },
      select: ['id', 'email', 'username', 'userType'],
    });

    assert.ok(user);
    assert.strictEqual(user.email, 'mixedcase');
    assert.strictEqual(user.username, 'mixedcase');
    assert.strictEqual(user.userType, UserType.LOCAL);
  });

  it('rejects a duplicate username with 409', async () => {
    const first = await request(app)
      .post('/auth/register')
      .send({ username: 'dupe', password: 'password123' });
    assert.strictEqual(first.status, 201);

    const second = await request(app)
      .post('/auth/register')
      .send({ username: 'dupe', password: 'password456' });
    assert.strictEqual(second.status, 409);
  });

  it('rejects a username colliding with an existing username', async () => {
    // Seed data: friend@seerr.dev has username 'friend'
    const res = await request(app)
      .post('/auth/register')
      .send({ username: 'friend', password: 'password123' });

    assert.strictEqual(res.status, 409);
  });

  it('rejects usernames containing @', async () => {
    const res = await request(app)
      .post('/auth/register')
      .send({ username: 'admin@seerr.dev', password: 'password123' });

    assert.strictEqual(res.status, 400);
  });

  it('rejects an invalid username with 400', async () => {
    const res = await request(app)
      .post('/auth/register')
      .send({ username: 'bad username!@', password: 'password123' });

    assert.strictEqual(res.status, 400);
  });

  it('rejects a short password with 400', async () => {
    const res = await request(app)
      .post('/auth/register')
      .send({ username: 'shortpw', password: 'short' });

    assert.strictEqual(res.status, 400);
  });

  it('returns 403 when localLogin is disabled', async () => {
    getSettings().main.localLogin = false;

    const res = await request(app)
      .post('/auth/register')
      .send({ username: 'disabled', password: 'password123' });

    assert.strictEqual(res.status, 403);
  });

  it('starts a session after signup', async () => {
    const agent = request.agent(app);
    const res = await agent
      .post('/auth/register')
      .send({ username: 'sessuser', password: 'password123' });

    assert.strictEqual(res.status, 201);

    const me = await agent.get('/auth/me');
    assert.strictEqual(me.status, 200);
    assert.strictEqual(me.body.username, 'sessuser');
  });
});

describe('POST /auth/username-login (email-free sign-in)', () => {
  beforeEach(() => {
    getSettings().main.localLogin = true;
  });

  it('logs in an email-free account by username', async () => {
    await request(app)
      .post('/auth/register')
      .send({ username: 'loginuser', password: 'password123' });

    const res = await request(app)
      .post('/auth/username-login')
      .send({ username: 'loginuser', password: 'password123' });

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.username, 'loginuser');
    assert.ok(!('password' in res.body));
  });

  it('is case-insensitive for usernames', async () => {
    await request(app)
      .post('/auth/register')
      .send({ username: 'cases', password: 'password123' });

    const res = await request(app)
      .post('/auth/username-login')
      .send({ username: 'CASES', password: 'password123' });

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.username, 'cases');
  });

  it('returns 403 on wrong password', async () => {
    await request(app)
      .post('/auth/register')
      .send({ username: 'wrongpw', password: 'password123' });

    const res = await request(app)
      .post('/auth/username-login')
      .send({ username: 'wrongpw', password: 'wrongpassword' });

    assert.strictEqual(res.status, 403);
    assert.strictEqual(res.body.message, 'Access denied.');
  });

  it('returns 403 for a nonexistent username', async () => {
    const res = await request(app)
      .post('/auth/username-login')
      .send({ username: 'ghost', password: 'password123' });

    assert.strictEqual(res.status, 403);
  });

  it('can sign in an upstream local account by username', async () => {
    // Seed data: friend@seerr.dev / username 'friend' / password test1234
    const res = await request(app)
      .post('/auth/username-login')
      .send({ username: 'friend', password: 'test1234' });

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.username, 'friend');
  });

  it('can sign in a pre-fork local account by its email address', async () => {
    // Legacy compat: LOCAL accounts created before this fork sign in with
    // their real email address (contains @, outside the signup pattern).
    const res = await request(app)
      .post('/auth/username-login')
      .send({ username: 'friend@seerr.dev', password: 'test1234' });

    assert.strictEqual(res.status, 200);
    assert.ok('id' in res.body);
  });

  it('accepts passwords longer than 128 characters for legacy accounts', async () => {
    // Upstream /auth/local has no password length cap at sign-in; accounts
    // may hold long hashes from before this fork. Sign-in must accept them.
    const repo = getRepository(User);
    const longPwUser = new User({
      email: 'longpw@example.com',
      username: 'longpw',
      permissions: 0,
      plexToken: '',
      userType: UserType.LOCAL,
    });
    longPwUser.avatar = '/avatarproxy/none';
    const longPassword = 'x'.repeat(200);
    await longPwUser.setPassword(longPassword);
    await repo.save(longPwUser);

    const res = await request(app)
      .post('/auth/username-login')
      .send({ username: 'longpw', password: longPassword });

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.username, 'longpw');
  });

  it('tries every colliding candidate so the password is the sole gate', async () => {
    // Real identifier collision: a username-only account and a legacy
    // email-bearing LOCAL account BOTH match the identifier 'shared-id'
    // (one by email, one by username). Both have passwords. Each valid
    // password must authenticate its own account; with equal passwords
    // the email-free account wins by priority.
    const repo = getRepository(User);

    const emailFree = new User({
      email: 'shared-id',
      username: 'shared-id',
      permissions: 0,
      plexToken: '',
      userType: UserType.LOCAL,
    });
    emailFree.avatar = '/avatarproxy/none';
    await emailFree.setPassword('freepassword');
    await repo.save(emailFree);

    const legacy = new User({
      email: 'legacy@example.com',
      username: 'shared-id',
      permissions: 0,
      plexToken: '',
      userType: UserType.LOCAL,
    });
    legacy.avatar = '/avatarproxy/none';
    await legacy.setPassword('legacysecret');
    await repo.save(legacy);

    // Legacy password authenticates the legacy account even though the
    // email-free account matches the identifier and sorts first.
    const asLegacy = await request(app)
      .post('/auth/username-login')
      .send({ username: 'shared-id', password: 'legacysecret' });
    assert.strictEqual(asLegacy.status, 200);
    assert.strictEqual(asLegacy.body.username, 'shared-id');
    assert.strictEqual(asLegacy.body.id, legacy.id);

    // Email-free password authenticates the email-free account.
    const asFree = await request(app)
      .post('/auth/username-login')
      .send({ username: 'shared-id', password: 'freepassword' });
    assert.strictEqual(asFree.status, 200);
    assert.strictEqual(asFree.body.id, emailFree.id);

    // A password belonging to neither candidate is 403.
    const wrong = await request(app)
      .post('/auth/username-login')
      .send({ username: 'shared-id', password: 'neitherpassword' });
    assert.strictEqual(wrong.status, 403);
  });

  it('never matches a Plex-linked account that has no password', async () => {
    // Seed data: plex-linked account has no local password. Create one
    // manually: email identity is an email, username matches, no password.
    const repo = getRepository(User);
    const plexUser = new User({
      email: 'plexonly@example.com',
      username: 'plexonly',
      permissions: 0,
      plexToken: 'fake-token',
      userType: UserType.PLEX,
    });
    plexUser.avatar = '/avatarproxy/none';
    await repo.save(plexUser);

    const res = await request(app)
      .post('/auth/username-login')
      .send({ username: 'plexonly', password: 'password123' });

    assert.strictEqual(res.status, 403);
  });

  it('returns 500 when username or password is missing', async () => {
    const res = await request(app)
      .post('/auth/username-login')
      .send({ password: 'password123' });

    assert.strictEqual(res.status, 500);
    assert.match(res.body.error, /username and a password/);
  });

  it('returns 500 when localLogin is disabled', async () => {
    getSettings().main.localLogin = false;

    const res = await request(app)
      .post('/auth/username-login')
      .send({ username: 'friend', password: 'test1234' });

    assert.strictEqual(res.status, 500);
    assert.strictEqual(res.body.error, 'Password sign-in is disabled.');
  });

  it('sets a session on successful login', async () => {
    await request(app)
      .post('/auth/register')
      .send({ username: 'sesslogin', password: 'password123' });

    const agent = request.agent(app);
    const res = await agent
      .post('/auth/username-login')
      .send({ username: 'sesslogin', password: 'password123' });
    assert.strictEqual(res.status, 200);

    const me = await agent.get('/auth/me');
    assert.strictEqual(me.status, 200);
    assert.strictEqual(me.body.username, 'sesslogin');
  });

  it('keeps the stock email login working for existing accounts', async () => {
    // Back-compat: upstream /auth/local still authenticates by email.
    const res = await request(app)
      .post('/auth/local')
      .send({ email: 'friend@seerr.dev', password: 'test1234' });

    assert.strictEqual(res.status, 200);
    assert.ok('id' in res.body);
  });

  it('never triggers the userEmailRequired warning for email-free accounts', async () => {
    getSettings().notifications.agents.email.options.userEmailRequired = true;

    await request(app)
      .post('/auth/register')
      .send({ username: 'nowarn', password: 'password123' });

    const agent = request.agent(app);
    const login = await agent
      .post('/auth/username-login')
      .send({ username: 'nowarn', password: 'password123' });
    assert.strictEqual(login.status, 200);

    const me = await agent.get('/auth/me');
    assert.strictEqual(me.status, 200);
    assert.deepStrictEqual(me.body.warnings, []);
  });

  it('password reset for an email-free account mints no reset link', async () => {
    await request(app)
      .post('/auth/register')
      .send({ username: 'noreset', password: 'password123' });

    const res = await request(app)
      .post('/auth/reset-password')
      .send({ email: 'noreset' });

    // Same response as any other address: no enumeration.
    assert.strictEqual(res.status, 200);

    const repo = getRepository(User);
    const user = await repo.findOneOrFail({ where: { email: 'noreset' } });
    assert.ok(!user.resetPasswordGuid);
    assert.ok(!user.recoveryLinkExpirationDate);
  });
});

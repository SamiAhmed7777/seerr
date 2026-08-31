import { UserType } from '@server/constants/user';
import { getRepository } from '@server/datasource';
import { User } from '@server/entity/User';
import { getSettings } from '@server/lib/settings';
import logger from '@server/logger';
import bcrypt from 'bcrypt';
import type { Request } from 'express';
import rateLimit from 'express-rate-limit';
import { Router } from 'express';

/**
 * Email-free local accounts (sami-flix fork).
 *
 * Accounts are username + password only. The upstream `email` column is
 * reused as the account identity column and stores the bare username
 * (lowercased), so every upstream lookup (`WHERE user.email = :email`)
 * keeps working without schema changes. No email is validated, required,
 * or stored anywhere in this flow. Email-oriented upstream surfaces are
 * guarded: /auth/me email warnings skip these accounts, and password
 * reset never generates a "link" for them.
 */

const USERNAME_PATTERN = /^[a-zA-Z0-9._-]{1,40}$/;
const MAX_PASSWORD_LENGTH = 128;

export function normalizeUsername(raw: string): string {
  return raw.trim().toLowerCase();
}

export function isValidUsername(raw: string): boolean {
  return USERNAME_PATTERN.test(raw);
}

/**
 * Rate limit for the public auth endpoints: 10 attempts per IP per 15
 * minutes. The key is the raw socket address, deliberately NOT req.ip:
 * forwarded headers can never influence the bucket, regardless of the
 * app's trust proxy setting.
 */
export const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Try again later.' },
  keyGenerator: (req) => req.socket.remoteAddress ?? req.ip ?? 'unknown',
  // The node:test suite exercises these endpoints heavily from one IP;
  // the test runner sets NODE_ENV=test.
  skip: () => process.env.NODE_ENV === 'test',
});

// Hash computed once at module load so a failed lookup costs the same
// bcrypt work as a found user (timing equalization on login).
const DUMMY_HASH = bcrypt.hashSync('timing-equalizer', 12);

function publicUser(user: User) {
  return {
    id: user.id,
    username: user.username ?? user.email,
    displayName: user.displayName,
    permissions: user.permissions,
    avatar: user.avatar,
  };
}

/**
 * Regenerate the session and set the authenticated user id, preventing
 * session fixation on login/signup.
 */
function loginSession(req: Request, userId: number): Promise<void> {
  return new Promise((resolve, reject) => {
    if (!req.session) {
      return resolve();
    }
    req.session.regenerate((err) => {
      if (err) {
        return reject(err);
      }
      if (req.session) {
        req.session.userId = userId;
      }
      return resolve();
    });
  });
}

/** True when a user row was created before this fork (has a real email). */
function hasRealEmail(user: Pick<User, 'email'>): boolean {
  return user.email.includes('@');
}

export function registerEmailFreeRoutes(authRoutes: Router): void {
  /**
   * POST /auth/register — username-only signup.
   * Body: { username, password }
   */
  authRoutes.post('/register', authRateLimiter, async (req, res, next) => {
    const settings = getSettings();

    if (!settings.main.localLogin) {
      return res.status(403).json({ error: 'Account creation is disabled.' });
    }

    const body = req.body as { username?: string; password?: string };
    const username = normalizeUsername(String(body.username ?? ''));
    const password = String(body.password ?? '');

    if (!username || !isValidUsername(username)) {
      return res.status(400).json({
        error: 'Username must be 1-40 characters (letters, numbers, . _ -).',
      });
    }
    if (password.length < 8 || password.length > MAX_PASSWORD_LENGTH) {
      return res.status(400).json({
        error: 'Password must be between 8 and 128 characters.',
      });
    }

    try {
      const userRepository = getRepository(User);

      // The identity column stores the username; one unique index covers
      // both lookup paths.
      const existing = await userRepository.findOne({
        where: [{ email: username }, { username }],
      });
      if (existing) {
        return res.status(409).json({ error: 'Username already taken.' });
      }

      const user = new User({
        email: username,
        username,
        permissions: settings.main.defaultPermissions,
        plexToken: '',
        userType: UserType.LOCAL,
      });
      user.avatar = '/logo_stacked.svg';
      await user.setPassword(password);
      try {
        await userRepository.save(user);
      } catch (e) {
        // Concurrent registrations can pass the preflight check above;
        // the unique index is the source of truth. Surface 409, not 500.
        // The identity column is the only unique constraint on this table
        // path, so a violation here is a username collision.
        const err = e as { message?: string; code?: string };
        const msg = err.message ?? '';
        const code = String(err.code ?? '');
        const isUniqueViolation =
          /(unique constraint|duplicate key)/i.test(msg) ||
          code === 'SQLITE_CONSTRAINT_UNIQUE';
        if (isUniqueViolation) {
          return res.status(409).json({ error: 'Username already taken.' });
        }
        throw e;
      }

      logger.info('Email-free account registered', {
        label: 'Auth',
        ip: req.ip,
        userId: user.id,
        username,
      });

      await loginSession(req, user.id);
      return res.status(201).json(publicUser(user));
    } catch (e) {
      logger.error('Email-free registration failed', {
        label: 'Auth',
        errorMessage: e.message,
        ip: req.ip,
      });
      return next({
        status: 500,
        message: 'Unable to create the account.',
      });
    }
  });

  /**
   * POST /auth/username-login — username-only sign-in.
   * Body: { username, password }
   *
   * Matches the identity column for LOCAL accounts, or the username
   * column for older accounts that have a password. Never authenticates
   * an account without a password, so Plex-only accounts fail closed.
   */
  authRoutes.post(
    '/username-login',
    authRateLimiter,
    async (req, res, next) => {
      const settings = getSettings();

      if (!settings.main.localLogin) {
        return res
          .status(500)
          .json({ error: 'Password sign-in is disabled.' });
      }

      const body = req.body as { username?: string; password?: string };
      const username = normalizeUsername(String(body.username ?? ''));
      const password = String(body.password ?? '');

      if (!username || !password) {
        return res
          .status(500)
          .json({ error: 'You must provide both a username and a password.' });
      }

      // Signup shape rules apply to NEW accounts; sign-in accepts anything
      // non-empty so legacy identities still work: pre-fork LOCAL accounts
      // sign in by their email address, old usernames may predate the new
      // character rules, and password length is uncapped exactly like
      // upstream /auth/local (bcrypt compares identically to how the hash
      // was made). Bounded only to keep the query and logs sane.
      const shapeValid = username.length <= 254;

      try {
        let authenticated: User | undefined;

        if (shapeValid) {
          const userRepository = getRepository(User);
          const matches = await userRepository
            .createQueryBuilder('user')
            .select([
              'user.id',
              'user.email',
              'user.username',
              'user.password',
              'user.plexId',
              'user.userType',
            ])
            .where('(user.email = :email OR user.username = :username)', {
              email: username,
              username,
            })
            .getMany();

          // Password is the sole gate (same as upstream /auth/local).
          // Candidate priority for identifier collisions: email-free LOCAL
          // accounts (username-only) first, then LOCAL accounts with real
          // emails, then every other password-bearing account. Every
          // candidate's password is tried, so a valid password is never
          // shadowed; priority only orders equal-password outcomes.
          // Accounts without a password (Plex-only) can never authenticate.
          const isEmailFree = (u: User): boolean =>
            u.userType === UserType.LOCAL && !u.email.includes('@');
          const candidates = [
            ...matches.filter((u) => isEmailFree(u) && !!u.password),
            ...matches.filter(
              (u) => !isEmailFree(u) && !!u.password
            ),
          ];

          for (const candidate of candidates) {
            if (await candidate.passwordMatch(password)) {
              authenticated = candidate;
              break;
            }
          }
        }

        if (!authenticated) {
          // Timing equalization: do the same bcrypt work as a real user.
          await bcrypt.compare(password, DUMMY_HASH);
        }

        if (!authenticated) {
          logger.warn('Failed email-free sign-in attempt', {
            label: 'Auth',
            ip: req.ip,
            username,
          });
          return next({
            status: 403,
            message: 'Access denied.',
          });
        }

        await loginSession(req, authenticated.id);
        return res.status(200).json(publicUser(authenticated));
      } catch (e) {
        logger.error('Email-free sign-in failed', {
          label: 'Auth',
          errorMessage: e.message,
          ip: req.ip,
        });
        return next({
          status: 500,
          message: 'Unable to authenticate.',
        });
      }
    }
  );
}

export { hasRealEmail };

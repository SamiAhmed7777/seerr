import Button from '@app/components/Common/Button';
import SensitiveInput from '@app/components/Common/SensitiveInput';
import useSettings from '@app/hooks/useSettings';
import defineMessages from '@app/utils/defineMessages';
import { ArrowLeftOnRectangleIcon } from '@heroicons/react/24/outline';
import { MediaServerType } from '@server/constants/server';
import axios from 'axios';
import { Field, Form, Formik } from 'formik';
import Link from 'next/link';
import { useState } from 'react';
import { useIntl } from 'react-intl';
import * as Yup from 'yup';

const messages = defineMessages('components.Login', {
  loginwithapp: 'Login with {appName}',
  username: 'Username',
  password: 'Password',
  validationusernamerequiredlocal: 'You must provide a username',
  validationusernameformat: 'Use 1-40 letters, numbers, dots, dashes or underscores',
  validationpasswordrequired: 'You must provide a password',
  validationpasswordshort: 'Password must be at least 8 characters',
  validationpasswordlong: 'Password must be at most 128 characters',
  jellyfinLocalLoginHint:
    "If you haven't set a username in your profile, use your {mediaServerName} username instead.",
  loginerror: 'Something went wrong while trying to sign in.',
  credentialerror: 'The username or password is incorrect.',
  registeringerror: 'Something went wrong while creating the account.',
  signingin: 'Signing In…',
  signin: 'Sign In',
  signup: 'Sign Up',
  creatingaccount: 'Creating Account…',
  noaccount: 'No account? Sign up',
  haveaccount: 'Already have an account? Sign in',
  forgotpassword: 'Forgot Password?',
});

interface LocalLoginProps {
  revalidate: () => void;
}

const LocalLogin = ({ revalidate }: LocalLoginProps) => {
  const intl = useIntl();
  const settings = useSettings();
  const [formError, setFormError] = useState<string | null>(null);
  const [isRegister, setIsRegister] = useState(false);

  const LoginSchema = Yup.object().shape({
    // Sign-in accepts anything non-empty: legacy local accounts can sign in
    // with their email address, and pre-existing usernames may predate the
    // new character rules. The server decides what matches. Sign-up mode
    // enforces the username rules client-side too.
    username: isRegister
      ? Yup.string()
          .required(
            intl.formatMessage(messages.validationusernamerequiredlocal)
          )
          .matches(
            /^[a-zA-Z0-9._-]{1,40}$/,
            intl.formatMessage(messages.validationusernameformat)
          )
      : Yup.string().required(
          intl.formatMessage(messages.validationusernamerequiredlocal)
        ),
    password: isRegister
      ? Yup.string()
          .required(intl.formatMessage(messages.validationpasswordrequired))
          .min(8, intl.formatMessage(messages.validationpasswordshort))
          .max(128, intl.formatMessage(messages.validationpasswordlong))
      : Yup.string().required(
          intl.formatMessage(messages.validationpasswordrequired)
        ),
  });

  const passwordResetEnabled =
    settings.currentSettings.applicationUrl &&
    settings.currentSettings.emailEnabled;

  return (
    <Formik
      initialValues={{
        username: '',
        password: '',
      }}
      validationSchema={LoginSchema}
      validateOnBlur={false}
      onSubmit={async (values) => {
        setFormError(null);
        try {
          if (isRegister) {
            await axios.post('/api/v1/auth/register', {
              username: values.username,
              password: values.password,
            });
          } else {
            try {
              await axios.post('/api/v1/auth/username-login', {
                username: values.username,
                password: values.password,
              });
            } catch (e) {
              // Older backend without the email-free endpoints: fall back
              // to the stock local login using the username as identity.
              if (axios.isAxiosError(e) && e.response?.status === 404) {
                await axios.post('/api/v1/auth/local', {
                  email: values.username,
                  password: values.password,
                });
              } else {
                throw e;
              }
            }
          }
        } catch (e) {
          if (axios.isAxiosError(e)) {
            const srvError =
              e.response?.data?.error || e.response?.data?.message;
            if (e.response?.status === 403) {
              setFormError(intl.formatMessage(messages.credentialerror));
            } else if (srvError) {
              setFormError(String(srvError));
            } else {
              setFormError(
                intl.formatMessage(
                  isRegister ? messages.registeringerror : messages.loginerror
                )
              );
            }
          } else {
            setFormError(
              intl.formatMessage(
                isRegister ? messages.registeringerror : messages.loginerror
              )
            );
          }
        } finally {
          revalidate();
        }
      }}
    >
      {({
        errors,
        touched,
        values,
        isSubmitting,
        isValid,
        resetForm,
      }) => {
        return (
          <>
            <Form data-form-type="login">
              <div>
                <h2 className="-mt-1 mb-6 text-center text-lg font-bold text-neutral-200">
                  {intl.formatMessage(messages.loginwithapp, {
                    appName: settings.currentSettings.applicationTitle,
                  })}
                </h2>

                <div className="mb-4 mt-1">
                  <div className="form-input-field">
                    <Field
                      id="username"
                      name="username"
                      placeholder={intl.formatMessage(messages.username)}
                      type="text"
                      autoCapitalize="none"
                      autoComplete="username"
                      data-testid="username"
                      data-form-type="username"
                      data-1pignore="false"
                      data-lpignore="false"
                      className="!bg-gray-700/80 placeholder:text-gray-400"
                    />
                  </div>
                  {errors.username &&
                    touched.username &&
                    typeof errors.username === 'string' && (
                      <div className="error">{errors.username}</div>
                    )}
                  {(settings.currentSettings.mediaServerType ===
                    MediaServerType.JELLYFIN ||
                    settings.currentSettings.mediaServerType ===
                      MediaServerType.EMBY) &&
                    !isRegister && (
                      <div className="mt-1 text-xs text-gray-400">
                        {intl.formatMessage(messages.jellyfinLocalLoginHint, {
                          mediaServerName:
                            settings.currentSettings.mediaServerType ===
                            MediaServerType.JELLYFIN
                              ? 'Jellyfin'
                              : 'Emby',
                        })}
                      </div>
                    )}
                </div>
                <div className="mb-2 mt-1">
                  <div className="form-input-field">
                    <SensitiveInput
                      as="field"
                      id="password"
                      name="password"
                      type="password"
                      placeholder={intl.formatMessage(messages.password)}
                      autoComplete={
                        isRegister ? 'new-password' : 'current-password'
                      }
                      data-testid="password"
                      data-form-type="password"
                      className="!bg-gray-700/80 placeholder:text-gray-400"
                      data-1pignore="false"
                      data-lpignore="false"
                    />
                  </div>
                  <div className="flex">
                    {errors.password &&
                      touched.password &&
                      typeof errors.password === 'string' && (
                        <div className="error">{errors.password}</div>
                      )}
                    <div className="flex-grow" />
                    {!isRegister && passwordResetEnabled && (
                      <Link
                        href="/resetpassword"
                        className="pt-2 text-sm text-indigo-500 hover:text-indigo-400"
                      >
                        {intl.formatMessage(messages.forgotpassword)}
                      </Link>
                    )}
                  </div>
                </div>
                {formError && (
                  <div className="mb-2 mt-1 sm:col-span-2 sm:mt-0">
                    <div className="error">{formError}</div>
                  </div>
                )}
              </div>

              <Button
                buttonType="primary"
                type="submit"
                disabled={isSubmitting || !isValid}
                data-testid={isRegister ? 'local-signup-button' : 'local-signin-button'}
                className="mt-2 w-full shadow-sm"
              >
                <ArrowLeftOnRectangleIcon />
                <span>
                  {isSubmitting
                    ? intl.formatMessage(
                        isRegister ? messages.creatingaccount : messages.signingin
                      )
                    : intl.formatMessage(
                        isRegister ? messages.signup : messages.signin
                      )}
                </span>
              </Button>

              {settings.currentSettings.localLogin && (
                <div className="mt-4 text-center">
                  <button
                    type="button"
                    data-testid="toggle-register"
                    className="text-sm text-indigo-500 hover:text-indigo-400"
                    onClick={() => {
                      resetForm();
                      setFormError(null);
                      setIsRegister(!isRegister);
                    }}
                  >
                    {intl.formatMessage(
                      isRegister ? messages.haveaccount : messages.noaccount
                    )}
                  </button>
                </div>
              )}
            </Form>
          </>
        );
      }}
    </Formik>
  );
};

export default LocalLogin;

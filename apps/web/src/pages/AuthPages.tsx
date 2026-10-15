import { zodResolver } from '@hookform/resolvers/zod';
import { Check } from 'lucide-react';
import { loginSchema, registerSchema, resetPasswordSchema } from '@seap/shared';
import { useId, useState, type ReactNode } from 'react';
import { useForm, type UseFormRegisterReturn } from 'react-hook-form';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import type { z } from 'zod';
import { Button, Field, inputClass } from '../components/ui';
import { api, ensureCsrf, setCsrf } from '../lib/api';
import { useAuth, type SessionUser } from '../lib/auth';

const passwordRules = [
  { label: '12 characters', test: (value: string) => value.length >= 12 },
  { label: 'Uppercase letter', test: (value: string) => /[A-Z]/.test(value) },
  { label: 'Lowercase letter', test: (value: string) => /[a-z]/.test(value) },
  { label: 'Number', test: (value: string) => /[0-9]/.test(value) },
  { label: 'Symbol', test: (value: string) => /[^A-Za-z0-9]/.test(value) },
];

function AuthShell({ title, description, children }: { title: string; description: string; children: ReactNode }) {
  return (
    <div className="min-h-screen bg-ink text-slate-900 dark:text-slate-100">
      <header className="sticky top-0 z-20 border-b border-line bg-panel/95 backdrop-blur-sm">
        <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-4 md:px-8">
          <Link to="/" className="font-mono text-xs tracking-[0.22em] text-accent">SEAP</Link>
          <nav className="flex items-center gap-2">
            <Link to="/how-it-works" className="inline-flex min-h-9 items-center rounded-md px-3 text-sm text-mute hover:text-slate-900 dark:hover:text-slate-100">How it works</Link>
            <Link to="/login" className="inline-flex min-h-9 items-center rounded-md px-3 text-sm text-mute hover:text-slate-900 dark:hover:text-slate-100">Sign in</Link>
            <Link to="/register" className="inline-flex min-h-9 items-center rounded-md bg-accent px-3 text-sm font-medium text-white hover:bg-accent/90">Create organization</Link>
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-lg px-4 py-12 md:px-8">
        <section className="rounded-lg border border-line bg-panel p-6 md:p-8">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Account</p>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight">{title}</h1>
          <p className="mt-2 text-sm text-mute">{description}</p>
          <div className="mt-6">{children}</div>
        </section>
      </main>
    </div>
  );
}

function Notice({ children }: { children: string }) {
  return <p className="rounded-md border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-500" role="alert">{children}</p>;
}

function PasswordField({ label, registration, autoComplete }: { label: string; registration: UseFormRegisterReturn; autoComplete: string }) {
  const id = useId();
  const [visible, setVisible] = useState(false);
  return (
    <div className="block text-sm">
      <label htmlFor={id} className="mb-1 block text-mute">{label}</label>
      <div className="relative">
        <input id={id} type={visible ? 'text' : 'password'} autoComplete={autoComplete} className={`${inputClass} pr-16`} {...registration} />
        <button type="button" aria-pressed={visible} className="absolute right-2 top-1/2 -translate-y-1/2 rounded px-2 py-1 text-xs text-mute hover:text-slate-900 dark:hover:text-slate-100" onClick={() => setVisible((value) => !value)}>
          {visible ? 'Hide' : 'Show'}
        </button>
      </div>
    </div>
  );
}

function PasswordRules({ value }: { value: string }) {
  const metCount = passwordRules.filter((rule) => rule.test(value)).length;
  return (
    <div>
      <p className="text-xs text-mute">{metCount} of {passwordRules.length} rules met</p>
      <ul className="mt-2 flex flex-wrap gap-1.5" aria-label="Password requirements">
        {passwordRules.map((rule) => {
          const met = rule.test(value);
          return (
            <li key={rule.label} className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs ${met ? 'border-accent/50 bg-accent/10 text-accent' : 'border-line bg-ink text-mute'}`}>
              {met ? <Check size={12} aria-hidden="true" /> : <span className="h-1.5 w-1.5 rounded-full bg-current opacity-50" aria-hidden="true" />}
              {rule.label}
              <span className="sr-only">{met ? ', met' : ', still needed'}</span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

export function LoginPage() {
  const navigate = useNavigate();
  const { setUser } = useAuth();
  const [mfaRequired, setMfaRequired] = useState(false);
  const form = useForm<z.infer<typeof loginSchema>>({ resolver: zodResolver(loginSchema) });
  return (
    <AuthShell title="Sign in" description="Use the work email for your organization. A code is requested only when multi-factor authentication is on.">
      <form className="space-y-4" onSubmit={form.handleSubmit(async (values) => {
        try {
          form.clearErrors();
          await ensureCsrf();
          const result = await api.post<{ user?: SessionUser; csrfToken?: string; mfaRequired?: boolean }>('/api/auth/login', values);
          if (result.mfaRequired) {
            setMfaRequired(true);
            form.setError('mfaCode', { message: 'Enter the six-digit authentication code' });
            return;
          }
          if (result.csrfToken) setCsrf(result.csrfToken);
          if (result.user) setUser(result.user);
          navigate('/dashboard');
        } catch (error) {
          form.setError('root', { message: error instanceof Error ? error.message : 'Sign in failed' });
        }
      })}>
        <Field label="Email">
          <input autoComplete="username" className={inputClass} {...form.register('email')} />
          {form.formState.errors.email && <p className="mt-1 text-sm text-rose-500">{form.formState.errors.email.message}</p>}
        </Field>
        <PasswordField label="Password" autoComplete="current-password" registration={form.register('password')} />
        <details className="rounded-md border border-line px-3 py-2">
          <summary className="cursor-pointer text-sm text-mute">I belong to more than one organization</summary>
          <div className="mt-3">
            <Field label="Organization slug">
              <input autoComplete="organization" className={inputClass} {...form.register('organizationSlug')} />
            </Field>
          </div>
        </details>
        {mfaRequired && (
          <Field label="Authentication code">
            <input autoFocus inputMode="numeric" autoComplete="one-time-code" className={inputClass} {...form.register('mfaCode')} />
            {form.formState.errors.mfaCode && <p className="mt-1 text-sm text-rose-500">{form.formState.errors.mfaCode.message}</p>}
          </Field>
        )}
        {form.formState.errors.root?.message && <Notice>{form.formState.errors.root.message}</Notice>}
        <Button type="submit" className="w-full" loading={form.formState.isSubmitting}>Sign in</Button>
      </form>
      <p className="mt-4 text-sm text-mute">
        <Link className="text-accent" to="/forgot-password">Forgot password</Link>
        <span> · </span>
        <Link className="text-accent" to="/register">Create an organization</Link>
      </p>
    </AuthShell>
  );
}

export function RegisterPage() {
  const navigate = useNavigate();
  const { setUser } = useAuth();
  const form = useForm<z.infer<typeof registerSchema>>({ resolver: zodResolver(registerSchema) });
  const password = form.watch('password') ?? '';
  return (
    <AuthShell title="Create an organization" description="You become the security admin for a new tenant. The password rules are checked before the account is created.">
      <form className="space-y-4" onSubmit={form.handleSubmit(async (values) => {
        try {
          form.clearErrors();
          await ensureCsrf();
          const result = await api.post<{ user: SessionUser; csrfToken: string }>('/api/auth/register', values);
          setCsrf(result.csrfToken);
          setUser(result.user);
          navigate('/dashboard');
        } catch (error) {
          form.setError('root', { message: error instanceof Error ? error.message : 'Could not create the organization' });
        }
      })}>
        <Field label="Name">
          <input autoComplete="name" className={inputClass} {...form.register('name')} />
          {form.formState.errors.name && <p className="mt-1 text-sm text-rose-500">{form.formState.errors.name.message}</p>}
        </Field>
        <Field label="Work email">
          <input autoComplete="email" className={inputClass} {...form.register('email')} />
          {form.formState.errors.email && <p className="mt-1 text-sm text-rose-500">{form.formState.errors.email.message}</p>}
        </Field>
        <Field label="Organization">
          <input autoComplete="organization" className={inputClass} {...form.register('organizationName')} />
          {form.formState.errors.organizationName && <p className="mt-1 text-sm text-rose-500">{form.formState.errors.organizationName.message}</p>}
        </Field>
        <PasswordField label="Password" autoComplete="new-password" registration={form.register('password')} />
        <PasswordRules value={password} />
        {form.formState.errors.password && <p className="text-sm text-rose-500">{form.formState.errors.password.message}</p>}
        {form.formState.errors.root?.message && <Notice>{form.formState.errors.root.message}</Notice>}
        <Button type="submit" className="w-full" loading={form.formState.isSubmitting}>Create organization</Button>
      </form>
      <p className="mt-4 text-sm text-mute">Already have an account? <Link className="text-accent" to="/login">Sign in</Link></p>
    </AuthShell>
  );
}

export function ForgotPage() {
  const form = useForm<{ email: string }>();
  const [sent, setSent] = useState(false);
  return (
    <AuthShell title="Reset password" description="If an account exists for this email, a one-hour reset link is sent. The response is the same either way.">
      {sent ? (
        <div className="space-y-4">
          <p className="rounded-md border border-line bg-ink px-3 py-3 text-sm">If the account exists, a reset message was issued.</p>
          <Link to="/login" className="inline-flex min-h-9 items-center text-sm text-accent">Return to sign in</Link>
        </div>
      ) : (
        <form className="space-y-4" onSubmit={form.handleSubmit(async (values) => {
          try {
            form.clearErrors();
            await ensureCsrf();
            await api.post('/api/auth/forgot-password', values);
            setSent(true);
          } catch (error) {
            form.setError('root', { message: error instanceof Error ? error.message : 'Could not send the reset message' });
          }
        })}>
          <Field label="Email">
            <input autoComplete="email" className={inputClass} {...form.register('email', { required: 'Enter the account email' })} />
            {form.formState.errors.email && <p className="mt-1 text-sm text-rose-500">{form.formState.errors.email.message}</p>}
          </Field>
          {form.formState.errors.root?.message && <Notice>{form.formState.errors.root.message}</Notice>}
          <Button type="submit" className="w-full" loading={form.formState.isSubmitting}>Send reset link</Button>
        </form>
      )}
      {!sent && <p className="mt-4 text-sm text-mute"><Link className="text-accent" to="/login">Return to sign in</Link></p>}
    </AuthShell>
  );
}

export function ResetPage() {
  const [params] = useSearchParams();
  const tokenFromLink = params.get('token') ?? '';
  const form = useForm<z.infer<typeof resetPasswordSchema>>({ resolver: zodResolver(resetPasswordSchema), defaultValues: { token: tokenFromLink } });
  const [updated, setUpdated] = useState(false);
  const password = form.watch('password') ?? '';
  return (
    <AuthShell title="Choose a new password" description="Reset links expire after one hour and work once.">
      {updated ? (
        <div className="space-y-4">
          <p className="rounded-md border border-line bg-ink px-3 py-3 text-sm">Password updated. Sign in with the new password.</p>
          <Link to="/login" className="inline-flex min-h-9 items-center rounded-md bg-accent px-3 text-sm font-medium text-white">Sign in</Link>
        </div>
      ) : (
        <form className="space-y-4" onSubmit={form.handleSubmit(async (values) => {
          try {
            form.clearErrors();
            await ensureCsrf();
            await api.post('/api/auth/reset-password', values);
            setUpdated(true);
          } catch (error) {
            form.setError('root', { message: error instanceof Error ? error.message : 'Could not update the password' });
          }
        })}>
          {tokenFromLink ? (
            <p className="text-sm text-mute">Reset link recognized.</p>
          ) : (
            <Field label="Reset token">
              <input className={inputClass} {...form.register('token')} />
              {form.formState.errors.token && <p className="mt-1 text-sm text-rose-500">{form.formState.errors.token.message}</p>}
            </Field>
          )}
          <PasswordField label="New password" autoComplete="new-password" registration={form.register('password')} />
          <PasswordRules value={password} />
          {form.formState.errors.password && <p className="text-sm text-rose-500">{form.formState.errors.password.message}</p>}
          {form.formState.errors.root?.message && <Notice>{form.formState.errors.root.message}</Notice>}
          <Button type="submit" className="w-full" loading={form.formState.isSubmitting}>Update password</Button>
        </form>
      )}
    </AuthShell>
  );
}

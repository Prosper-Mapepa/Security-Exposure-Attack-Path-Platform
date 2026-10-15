process.env.DATABASE_URL ??= 'postgresql://seap:seap@localhost:5432/seap?schema=public';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_ACCESS_SECRET ??= 'test-access-secret-value';
process.env.MFA_ENCRYPTION_KEY ??= 'test-mfa-key';
process.env.NODE_ENV ??= 'test';
process.env.EXPOSE_RESET_TOKEN ??= 'false';

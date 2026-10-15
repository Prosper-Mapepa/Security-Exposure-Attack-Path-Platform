/** @type {import('jest').Config} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  rootDir: 'test',
  testMatch: ['**/*.e2e-spec.ts'],
  testTimeout: 60000,
  setupFiles: ['<rootDir>/setup.ts'],
};

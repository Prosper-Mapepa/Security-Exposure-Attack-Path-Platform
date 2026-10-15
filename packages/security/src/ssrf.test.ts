import { isBlockedIp, ipInCidrs } from './ssrf';

describe('ssrf address checks', () => {
  it('blocks link-local and loopback addresses', () => {
    expect(isBlockedIp('169.254.169.254')).toBe(true);
    expect(isBlockedIp('127.0.0.1')).toBe(true);
    expect(isBlockedIp('10.1.2.3')).toBe(true);
    expect(isBlockedIp('8.8.8.8')).toBe(false);
  });

  it('matches lab CIDRs', () => {
    expect(ipInCidrs('127.0.0.1', ['127.0.0.1/32'])).toBe(true);
    expect(ipInCidrs('8.8.8.8', ['127.0.0.1/32'])).toBe(false);
  });
});

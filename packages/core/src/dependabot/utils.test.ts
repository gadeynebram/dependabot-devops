import type { SecurityVulnerability } from '../github';
import { describe, expect, it } from 'vitest';
import type { DependabotDependency, DependabotPersistedPr } from './job';
import { getPullRequestDescription, shouldSupersede } from './utils';

describe('getPullRequestDescription', () => {
  it('should include CVE information when security vulnerabilities are provided', () => {
    const dependencies: DependabotDependency[] = [
      {
        name: 'test-package',
        version: '2.0.0',
        'previous-version': '1.0.0',
        requirements: [],
        removed: false,
      },
    ];

    const securityVulnerabilities: SecurityVulnerability[] = [
      {
        package: { name: 'test-package', version: '1.0.0' },
        advisory: {
          identifiers: [
            { type: 'CVE', value: 'CVE-2023-1234' },
            { type: 'GHSA', value: 'GHSA-xxxx-yyyy-zzzz' },
          ],
          severity: 'HIGH',
          summary: 'Test vulnerability',
          description: 'Test description',
          references: [],
          cvss: null,
          epss: null,
          cwes: null,
          publishedAt: null,
          updatedAt: null,
          withdrawnAt: null,
          permalink: null,
        },
        vulnerableVersionRange: '<2.0.0',
        firstPatchedVersion: { identifier: '2.0.0' },
      },
    ];

    const description = getPullRequestDescription({
      packageManager: 'npm',
      body: 'Test body',
      dependencies,
      securityVulnerabilities,
    });

    expect(description).toContain('🔒 Security Vulnerabilities');
    expect(description).toContain('CVE-2023-1234');
    expect(description).toContain('GHSA-xxxx-yyyy-zzzz');
    expect(description).toContain('test-package');
    expect(description).toContain('1.0.0 → 2.0.0');
  });

  it('should not include CVE section when no vulnerabilities are provided', () => {
    const dependencies: DependabotDependency[] = [
      {
        name: 'test-package',
        version: '2.0.0',
        'previous-version': '1.0.0',
        requirements: [],
        removed: false,
      },
    ];

    const description = getPullRequestDescription({
      packageManager: 'npm',
      body: 'Test body',
      dependencies,
    });

    expect(description).not.toContain('🔒 Security Vulnerabilities');
    expect(description).toContain('Test body');
  });

  it('should not include CVE section when vulnerabilities do not match dependencies', () => {
    const dependencies: DependabotDependency[] = [
      {
        name: 'test-package',
        version: '2.0.0',
        'previous-version': '1.0.0',
        requirements: [],
        removed: false,
      },
    ];

    const securityVulnerabilities: SecurityVulnerability[] = [
      {
        package: { name: 'other-package', version: '1.0.0' },
        advisory: {
          identifiers: [{ type: 'CVE', value: 'CVE-2023-1234' }],
          severity: 'HIGH',
          summary: 'Test vulnerability',
          description: null,
          references: [],
          cvss: null,
          epss: null,
          cwes: null,
          publishedAt: null,
          updatedAt: null,
          withdrawnAt: null,
          permalink: null,
        },
        vulnerableVersionRange: '<2.0.0',
        firstPatchedVersion: { identifier: '2.0.0' },
      },
    ];

    const description = getPullRequestDescription({
      packageManager: 'npm',
      body: 'Test body',
      dependencies,
      securityVulnerabilities,
    });

    expect(description).not.toContain('🔒 Security Vulnerabilities');
    expect(description).toContain('Test body');
  });

  it('should handle multiple dependencies with multiple CVEs', () => {
    const dependencies: DependabotDependency[] = [
      {
        name: 'package-one',
        version: '2.0.0',
        'previous-version': '1.0.0',
        requirements: [],
        removed: false,
      },
      {
        name: 'package-two',
        version: '3.0.0',
        'previous-version': '2.0.0',
        requirements: [],
        removed: false,
      },
    ];

    const securityVulnerabilities: SecurityVulnerability[] = [
      {
        package: { name: 'package-one', version: '1.0.0' },
        advisory: {
          identifiers: [{ type: 'CVE', value: 'CVE-2023-1111' }],
          severity: 'HIGH',
          summary: 'Test vulnerability 1',
          description: null,
          references: [],
          cvss: null,
          epss: null,
          cwes: null,
          publishedAt: null,
          updatedAt: null,
          withdrawnAt: null,
          permalink: null,
        },
        vulnerableVersionRange: '<2.0.0',
        firstPatchedVersion: { identifier: '2.0.0' },
      },
      {
        package: { name: 'package-two', version: '2.0.0' },
        advisory: {
          identifiers: [
            { type: 'CVE', value: 'CVE-2023-2222' },
            { type: 'CVE', value: 'CVE-2023-3333' },
          ],
          severity: 'CRITICAL',
          summary: 'Test vulnerability 2',
          description: null,
          references: [],
          cvss: null,
          epss: null,
          cwes: null,
          publishedAt: null,
          updatedAt: null,
          withdrawnAt: null,
          permalink: null,
        },
        vulnerableVersionRange: '<3.0.0',
        firstPatchedVersion: { identifier: '3.0.0' },
      },
    ];

    const description = getPullRequestDescription({
      packageManager: 'npm',
      body: 'Test body',
      dependencies,
      securityVulnerabilities,
    });

    expect(description).toContain('🔒 Security Vulnerabilities');
    expect(description).toContain('CVE-2023-1111');
    expect(description).toContain('CVE-2023-2222');
    expect(description).toContain('CVE-2023-3333');
    expect(description).toContain('package-one');
    expect(description).toContain('package-two');
  });

  it('should include compatibility score badge for single dependency', () => {
    const dependencies: DependabotDependency[] = [
      {
        name: 'test-package',
        version: '2.0.0',
        'previous-version': '1.0.0',
        requirements: [],
        removed: false,
      },
    ];

    const description = getPullRequestDescription({
      packageManager: 'npm',
      body: 'Test body',
      dependencies,
    });

    expect(description).toContain('Dependabot compatibility score');
    expect(description).toContain('dependency-name=test-package');
    expect(description).toContain('previous-version=1.0.0');
    expect(description).toContain('new-version=2.0.0');
  });
});

describe('shouldSupersede', () => {
  it('returns false when there are no overlapping dependencies', () => {
    const oldPr: DependabotPersistedPr = {
      'dependency-group-name': null,
      dependencies: [
        { 'dependency-name': 'lodash', 'dependency-version': '4.17.20' },
        { 'dependency-name': 'express', 'dependency-version': '4.18.0' },
      ],
    };

    const newPr: DependabotPersistedPr = {
      'dependency-group-name': null,
      dependencies: [
        { 'dependency-name': 'react', 'dependency-version': '18.0.0' },
        { 'dependency-name': 'vue', 'dependency-version': '3.0.0' },
      ],
    };

    expect(shouldSupersede(oldPr, newPr)).toBe(false);
  });

  it('returns false when overlapping dependencies have the same version (rebase scenario)', () => {
    const oldPr: DependabotPersistedPr = {
      'dependency-group-name': null,
      dependencies: [
        { 'dependency-name': 'lodash', 'dependency-version': '4.17.21' },
        { 'dependency-name': 'express', 'dependency-version': '4.18.0' },
      ],
    };

    const newPr: DependabotPersistedPr = {
      'dependency-group-name': null,
      dependencies: [
        { 'dependency-name': 'lodash', 'dependency-version': '4.17.21' },
        { 'dependency-name': 'react', 'dependency-version': '18.0.0' },
      ],
    };

    expect(shouldSupersede(oldPr, newPr)).toBe(false);
  });

  it('returns true when overlapping dependencies have different versions', () => {
    const oldPr: DependabotPersistedPr = {
      'dependency-group-name': 'one',
      dependencies: [
        { 'dependency-name': 'lodash', 'dependency-version': '4.17.20' },
        { 'dependency-name': 'express', 'dependency-version': '4.18.0' },
      ],
    };

    const newPr: DependabotPersistedPr = {
      'dependency-group-name': 'one',
      dependencies: [
        { 'dependency-name': 'lodash', 'dependency-version': '4.17.21' },
        { 'dependency-name': 'express', 'dependency-version': '4.18.0' },
      ],
    };

    expect(shouldSupersede(oldPr, newPr)).toBe(true);
  });

  it('returns false when dependency sets differ (different scope)', () => {
    // Old PR: lodash + express
    // New PR: lodash + react
    // Even though lodash version changed, they're different scopes
    const oldPr: DependabotPersistedPr = {
      'dependency-group-name': null,
      dependencies: [
        { 'dependency-name': 'lodash', 'dependency-version': '4.17.20' },
        { 'dependency-name': 'express', 'dependency-version': '4.18.0' },
      ],
    };

    const newPr: DependabotPersistedPr = {
      'dependency-group-name': null,
      dependencies: [
        { 'dependency-name': 'lodash', 'dependency-version': '4.17.21' },
        { 'dependency-name': 'react', 'dependency-version': '18.0.0' },
      ],
    };

    expect(shouldSupersede(oldPr, newPr)).toBe(false);
  });

  it('returns true when multiple overlapping dependencies have at least one version change', () => {
    const oldPr: DependabotPersistedPr = {
      'dependency-group-name': null,
      dependencies: [
        { 'dependency-name': 'lodash', 'dependency-version': '4.17.20' },
        { 'dependency-name': 'express', 'dependency-version': '4.18.0' },
        { 'dependency-name': 'react', 'dependency-version': '18.0.0' },
      ],
    };

    const newPr: DependabotPersistedPr = {
      'dependency-group-name': null,
      dependencies: [
        { 'dependency-name': 'lodash', 'dependency-version': '4.17.21' },
        { 'dependency-name': 'express', 'dependency-version': '4.18.0' },
        { 'dependency-name': 'react', 'dependency-version': '18.0.0' },
      ],
    };

    expect(shouldSupersede(oldPr, newPr)).toBe(true);
  });

  it('returns false when all overlapping dependencies have the same versions', () => {
    const oldPr: DependabotPersistedPr = {
      'dependency-group-name': null,
      dependencies: [
        { 'dependency-name': 'lodash', 'dependency-version': '4.17.21' },
        { 'dependency-name': 'express', 'dependency-version': '4.18.0' },
        { 'dependency-name': 'react', 'dependency-version': '18.0.0' },
      ],
    };

    const newPr: DependabotPersistedPr = {
      'dependency-group-name': null,
      dependencies: [
        { 'dependency-name': 'lodash', 'dependency-version': '4.17.21' },
        { 'dependency-name': 'express', 'dependency-version': '4.18.0' },
        { 'dependency-name': 'react', 'dependency-version': '18.0.0' },
      ],
    };

    expect(shouldSupersede(oldPr, newPr)).toBe(false);
  });

  it('returns true for dependency group PRs with version changes', () => {
    const oldPr: DependabotPersistedPr = {
      'dependency-group-name': 'production',
      dependencies: [
        { 'dependency-name': 'lodash', 'dependency-version': '4.17.20' },
        { 'dependency-name': 'express', 'dependency-version': '4.18.0' },
      ],
    };

    const newPr: DependabotPersistedPr = {
      'dependency-group-name': 'production',
      dependencies: [
        { 'dependency-name': 'lodash', 'dependency-version': '4.17.21' },
        { 'dependency-name': 'express', 'dependency-version': '4.18.1' },
      ],
    };

    expect(shouldSupersede(oldPr, newPr)).toBe(true);
  });

  it('handles dependencies without version information', () => {
    const oldPr: DependabotPersistedPr = {
      'dependency-group-name': null,
      dependencies: [{ 'dependency-name': 'lodash', 'dependency-version': null }],
    };

    const newPr: DependabotPersistedPr = {
      'dependency-group-name': null,
      dependencies: [{ 'dependency-name': 'lodash', 'dependency-version': '4.17.21' }],
    };

    expect(shouldSupersede(oldPr, newPr)).toBe(true);
  });

  it('returns false when both PRs have empty dependency lists', () => {
    const oldPr: DependabotPersistedPr = {
      'dependency-group-name': null,
      dependencies: [],
    };

    const newPr: DependabotPersistedPr = {
      'dependency-group-name': null,
      dependencies: [],
    };

    expect(shouldSupersede(oldPr, newPr)).toBe(false);
  });

  it('returns false when old PR has dependencies but new PR is empty', () => {
    const oldPr: DependabotPersistedPr = {
      'dependency-group-name': null,
      dependencies: [{ 'dependency-name': 'lodash', 'dependency-version': '4.17.21' }],
    };

    const newPr: DependabotPersistedPr = {
      'dependency-group-name': null,
      dependencies: [],
    };

    expect(shouldSupersede(oldPr, newPr)).toBe(false);
  });

  it('handles dependencies with directory field', () => {
    // Different dependency sets - shouldn't supersede even with version change
    const oldPr: DependabotPersistedPr = {
      'dependency-group-name': null,
      dependencies: [
        { 'dependency-name': 'lodash', 'dependency-version': '4.17.20', directory: '/frontend' },
        { 'dependency-name': 'express', 'dependency-version': '4.18.0', directory: '/backend' },
      ],
    };

    const newPr: DependabotPersistedPr = {
      'dependency-group-name': null,
      dependencies: [
        { 'dependency-name': 'lodash', 'dependency-version': '4.17.21', directory: '/frontend' },
        { 'dependency-name': 'react', 'dependency-version': '18.0.0', directory: '/frontend' },
      ],
    };

    expect(shouldSupersede(oldPr, newPr)).toBe(false);
  });

  it('returns true when version changes from a value to null', () => {
    const oldPr: DependabotPersistedPr = {
      'dependency-group-name': null,
      dependencies: [{ 'dependency-name': 'lodash', 'dependency-version': '4.17.20' }],
    };

    const newPr: DependabotPersistedPr = {
      'dependency-group-name': null,
      dependencies: [{ 'dependency-name': 'lodash', 'dependency-version': null }],
    };

    expect(shouldSupersede(oldPr, newPr)).toBe(true);
  });

  it('returns true when version changes from null to a value', () => {
    const oldPr: DependabotPersistedPr = {
      'dependency-group-name': null,
      dependencies: [{ 'dependency-name': 'lodash', 'dependency-version': null }],
    };

    const newPr: DependabotPersistedPr = {
      'dependency-group-name': null,
      dependencies: [{ 'dependency-name': 'lodash', 'dependency-version': '4.17.21' }],
    };

    expect(shouldSupersede(oldPr, newPr)).toBe(true);
  });

  it('returns true when same group has version changes even with different dependency sets', () => {
    const oldPr: DependabotPersistedPr = {
      'dependency-group-name': 'production',
      dependencies: [
        { 'dependency-name': 'lodash', 'dependency-version': '4.17.20' },
        { 'dependency-name': 'express', 'dependency-version': '4.18.0' },
      ],
    };

    const newPr: DependabotPersistedPr = {
      'dependency-group-name': 'production',
      dependencies: [
        { 'dependency-name': 'lodash', 'dependency-version': '4.17.21' },
        { 'dependency-name': 'react', 'dependency-version': '18.0.0' },
      ],
    };

    expect(shouldSupersede(oldPr, newPr)).toBe(true);
  });

  it('returns false when different groups even with overlapping dependencies', () => {
    const oldPr: DependabotPersistedPr = {
      'dependency-group-name': 'production',
      dependencies: [{ 'dependency-name': 'lodash', 'dependency-version': '4.17.20' }],
    };

    const newPr: DependabotPersistedPr = {
      'dependency-group-name': 'development',
      dependencies: [{ 'dependency-name': 'lodash', 'dependency-version': '4.17.21' }],
    };

    expect(shouldSupersede(oldPr, newPr)).toBe(false);
  });

  it('returns false when one has group and one does not', () => {
    const oldPr: DependabotPersistedPr = {
      'dependency-group-name': 'production',
      dependencies: [{ 'dependency-name': 'lodash', 'dependency-version': '4.17.20' }],
    };

    const newPr: DependabotPersistedPr = {
      'dependency-group-name': null,
      dependencies: [{ 'dependency-name': 'lodash', 'dependency-version': '4.17.21' }],
    };

    expect(shouldSupersede(oldPr, newPr)).toBe(false);
  });
});

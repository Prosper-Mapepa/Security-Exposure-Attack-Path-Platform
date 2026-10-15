import { z } from 'zod';

export const passwordSchema = z
  .string()
  .min(12, 'Password must be at least 12 characters')
  .max(128)
  .regex(/[a-z]/, 'Password must include a lowercase letter')
  .regex(/[A-Z]/, 'Password must include an uppercase letter')
  .regex(/[0-9]/, 'Password must include a number')
  .regex(/[^A-Za-z0-9]/, 'Password must include a symbol');

export const registerSchema = z.object({
  email: z.string().email().max(320),
  password: passwordSchema,
  name: z.string().min(2).max(120),
  organizationName: z.string().min(2).max(160),
});

export const loginSchema = z.object({
  email: z.string().email().max(320),
  password: z.string().min(1).max(128),
  organizationSlug: z.union([z.string().min(2).max(80), z.literal('')]).optional(),
  mfaCode: z.union([z.string().regex(/^\d{6}$/), z.literal('')]).optional(),
});

export const refreshSchema = z.object({}).passthrough();

export const forgotPasswordSchema = z.object({
  email: z.string().email().max(320),
});

export const resetPasswordSchema = z.object({
  token: z.string().min(20).max(512),
  password: passwordSchema,
});

export const mfaCodeSchema = z.object({
  code: z.string().regex(/^\d{6}$/),
});

export const switchOrgSchema = z.object({
  organizationId: z.string().min(1).max(64),
});

export const paginationSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
  q: z.string().max(200).optional(),
});

export const assetTypes = [
  'APPLICATION',
  'API',
  'DOMAIN',
  'IP_ADDRESS',
  'REPOSITORY',
  'CLOUD_ACCOUNT',
  'CLOUD_RESOURCE',
  'CONTAINER',
  'CONTAINER_IMAGE',
  'KUBERNETES_CLUSTER',
  'KUBERNETES_WORKLOAD',
  'ENDPOINT',
  'IDENTITY',
  'SERVICE_ACCOUNT',
  'IAM_ROLE',
  'DATABASE',
  'SERVER',
  'NETWORK_NODE',
] as const;

export const environments = ['PRODUCTION', 'STAGING', 'DEVELOPMENT', 'TEST', 'UNKNOWN'] as const;
export const criticalities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;
export const exposures = ['PUBLIC', 'INTERNAL', 'PRIVATE', 'UNKNOWN'] as const;
export const sensitivities = ['RESTRICTED', 'CONFIDENTIAL', 'INTERNAL', 'PUBLIC', 'UNKNOWN'] as const;
export const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
export const findingStatuses = [
  'OPEN',
  'ACKNOWLEDGED',
  'IN_PROGRESS',
  'MITIGATED',
  'RESOLVED',
  'FALSE_POSITIVE',
  'ACCEPTED_RISK',
  'REOPENED',
] as const;

export const clientFindingStatuses = [
  'OPEN',
  'ACKNOWLEDGED',
  'IN_PROGRESS',
  'MITIGATED',
  'FALSE_POSITIVE',
  'ACCEPTED_RISK',
  'REOPENED',
] as const;

export const createAssetSchema = z.object({
  name: z.string().min(1).max(200),
  type: z.enum(assetTypes),
  description: z.string().max(4000).optional(),
  environment: z.enum(environments).default('UNKNOWN'),
  criticality: z.enum(criticalities).default('MEDIUM'),
  exposure: z.enum(exposures).default('UNKNOWN'),
  dataSensitivity: z.enum(sensitivities).default('UNKNOWN'),
  technology: z.string().max(200).optional(),
  businessService: z.string().max(200).optional(),
  ownerId: z.string().max(64).optional(),
  teamId: z.string().max(64).optional(),
  authRequired: z.boolean().optional(),
  privilegeRequired: z.enum(['NONE', 'LOW', 'HIGH', 'UNKNOWN']).optional(),
  internetFacing: z.boolean().optional(),
  tags: z.array(z.string().min(1).max(40)).max(20).optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
  detail: z.record(z.string(), z.unknown()).optional(),
});

export const updateAssetSchema = createAssetSchema.partial();

export const createEndpointSchema = z.object({
  method: z.string().min(1).max(12),
  path: z.string().min(1).max(500),
  authRequired: z.boolean().default(true),
});

export const relationshipSchema = z.object({
  sourceAssetId: z.string().min(1),
  targetAssetId: z.string().min(1),
  type: z.enum([
    'CONNECTS_TO',
    'CAN_ACCESS',
    'RUNS_ON',
    'AUTHENTICATES_TO',
    'ASSUMES_ROLE',
    'CONTAINS',
    'EXPOSES',
    'DEPENDS_ON',
  ]),
});

export const createScanSchema = z
  .object({
    name: z.string().min(1, 'Enter a scan name').max(200),
    scanner: z.enum(['SEMGREP', 'TRIVY', 'ZAP', 'GITLEAKS']),
    assetId: z.string().min(1, 'Select an asset'),
    targetType: z.enum(['PATH', 'GIT', 'URL', 'IMAGE']),
    location: z.string().min(1, 'Enter a scan location').max(2000),
    metadata: z.record(z.string(), z.unknown()).optional(),
  })
  .superRefine((value, ctx) => {
    const location = value.location.trim();
    const isHttp = /^https?:\/\//i.test(location);
    if (value.targetType === 'PATH' && isHttp) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['location'],
        message: 'A PATH target is a local directory. For a website, choose the ZAP scanner and target type URL. For a repository, choose target type GIT.',
      });
    }
    if (value.targetType === 'URL' && value.scanner !== 'ZAP') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['scanner'],
        message: 'URL targets are scanned with ZAP.',
      });
    }
    if (value.scanner === 'ZAP' && value.targetType !== 'URL') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['targetType'],
        message: 'ZAP scans a website or API URL. Set the target type to URL.',
      });
    }
    if ((value.scanner === 'SEMGREP' || value.scanner === 'GITLEAKS') && value.targetType !== 'PATH' && value.targetType !== 'GIT') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['targetType'],
        message: 'Semgrep and Gitleaks scan a local directory or a git repository.',
      });
    }
    if (value.scanner === 'TRIVY' && value.targetType !== 'PATH' && value.targetType !== 'IMAGE') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['targetType'],
        message: 'Trivy scans a local filesystem path or a container image reference.',
      });
    }
    if (value.targetType === 'GIT' && !isHttp) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['location'],
        message: 'A GIT target must be an http or https repository URL.',
      });
    }
    if (value.targetType === 'URL' && !isHttp) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['location'],
        message: 'A URL target must start with http:// or https://.',
      });
    }
  });

export const updateFindingStatusSchema = z.object({
  status: z.enum(clientFindingStatuses),
  note: z.string().max(2000).optional(),
});

export const createIncidentSchema = z.object({
  title: z.string().min(3).max(200),
  summary: z.string().max(8000).optional(),
  severity: z.enum(severities),
  assigneeId: z.string().optional(),
  assetIds: z.array(z.string()).max(50).optional(),
  vulnerabilityIds: z.array(z.string()).max(50).optional(),
  eventIds: z.array(z.string()).max(50).optional(),
  attackPathIds: z.array(z.string()).max(20).optional(),
});

export const updateIncidentSchema = z.object({
  title: z.string().min(3).max(200).optional(),
  summary: z.string().max(8000).optional(),
  severity: z.enum(severities).optional(),
  status: z.enum(['OPEN', 'INVESTIGATING', 'CONTAINED', 'REMEDIATION', 'RESOLVED', 'CLOSED']).optional(),
  assigneeId: z.string().nullable().optional(),
});

export const incidentNoteSchema = z.object({
  body: z.string().min(1).max(8000),
});

export const createRemediationSchema = z.object({
  vulnerabilityId: z.string().min(1),
  assigneeId: z.string().optional(),
  dueAt: z.string().datetime().optional(),
  notes: z.string().max(8000).optional(),
  taskTitle: z.string().min(1).max(200).optional(),
});

export const updateRemediationSchema = z.object({
  assigneeId: z.string().nullable().optional(),
  dueAt: z.string().datetime().nullable().optional(),
  notes: z.string().max(8000).optional(),
  status: z
    .enum(['OPEN', 'ASSIGNED', 'IN_PROGRESS', 'PENDING_VALIDATION', 'REOPENED', 'CLOSED'])
    .optional(),
});

export const commentSchema = z.object({
  body: z.string().min(1).max(8000),
});

export const taskSchema = z.object({
  title: z.string().min(1).max(200),
  description: z.string().max(4000).optional(),
  assigneeId: z.string().optional(),
  dueAt: z.string().datetime().optional(),
});

export const ingestEventSchema = z.object({
  timestamp: z.string().datetime(),
  source: z.string().min(1).max(120),
  eventType: z.string().min(1).max(120),
  severity: z.enum(severities),
  sourceIp: z.string().max(64).optional(),
  destinationIp: z.string().max(64).optional(),
  actor: z.string().max(200).optional(),
  assetId: z.string().optional(),
  rawEvent: z.record(z.string(), z.unknown()),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

export const eventQuerySchema = paginationSchema.extend({
  severity: z.enum(severities).optional(),
  assetId: z.string().optional(),
  actor: z.string().max(200).optional(),
  eventType: z.string().max(120).optional(),
  source: z.string().max(120).optional(),
  from: z.string().datetime().optional(),
  to: z.string().datetime().optional(),
});

export const riskWeightsSchema = z.object({
  technical: z.number().min(0).max(1),
  exploitability: z.number().min(0).max(1),
  business: z.number().min(0).max(1),
  exposure: z.number().min(0).max(1),
  authentication: z.number().min(0).max(1),
  privilege: z.number().min(0).max(1),
  data: z.number().min(0).max(1),
  age: z.number().min(0).max(1),
  attackPath: z.number().min(0).max(1),
  controls: z.number().min(0).max(1),
});

export const policyRuleSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('MAX_OPEN_SEVERITY'),
    severity: z.enum(severities),
    exposure: z.enum(exposures).optional(),
    environment: z.enum(environments).optional(),
  }),
  z.object({
    type: z.literal('REQUIRE_OWNER'),
    assetTypes: z.array(z.enum(assetTypes)).min(1),
  }),
  z.object({
    type: z.literal('MAX_RISK_SCORE'),
    max: z.number().min(0).max(100),
  }),
]);

export const createPolicySchema = z.object({
  name: z.string().min(2).max(160),
  description: z.string().min(2).max(2000),
  rule: policyRuleSchema,
  enabled: z.boolean().default(true),
});

export const createUserSchema = z.object({
  email: z.string().email().max(320),
  name: z.string().min(2).max(120),
  password: passwordSchema,
  role: z.enum(['SECURITY_ADMIN', 'SECURITY_ANALYST', 'ENGINEER', 'VIEWER']),
});

export const updateMemberSchema = z.object({
  role: z.enum(['SECURITY_ADMIN', 'SECURITY_ANALYST', 'ENGINEER', 'VIEWER']),
});

export const createTeamSchema = z.object({
  name: z.string().min(2).max(120),
});

export const createThreatSchema = z.object({
  name: z.string().min(2).max(160),
  description: z.string().min(2).max(4000),
  mitreId: z.string().max(40).optional(),
});

export const createDetectionSchema = z.object({
  name: z.string().min(2).max(160),
  eventType: z.string().min(1).max(120),
  minSeverity: z.enum(severities).default('MEDIUM'),
  threatId: z.string().optional(),
  enabled: z.boolean().default(true),
});

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type CreateAssetInput = z.infer<typeof createAssetSchema>;
export type CreateScanInput = z.infer<typeof createScanSchema>;
export type RiskWeights = z.infer<typeof riskWeightsSchema>;

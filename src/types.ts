/**
 * 插件内部共享的数据模型。
 *
 * 这些结构同时是各工具的 canonical JSON 值，会被回放、被 Code/PTC 模式
 * 程序化读取，因此字段名保持 camelCase、不携带任何内部引用。
 *
 * 全部使用 `type` 别名而非 `interface`：`tool` 的 `output.schema` 若声明为
 * `{ type: 'json' }`，其推导类型是 `JsonValue`（带索引签名），而 TypeScript
 * 只给对象字面量类型别名隐式索引签名。用别名可以省掉边界处的强制转换。
 */

/** 技术栈组件。 */
export type TechComponent = {
  name: string
  version: string | null
  category: string
  confidence: number
}

/** 目标情报采集状态。 */
export type ScanStatus = 'complete' | 'partial' | 'failed'

/** 目标情报。 */
export type TargetIntel = {
  targetUrl: string
  server: string | null
  framework: string | null
  techStack: TechComponent[]
  wafDetected: boolean
  wafVendor: string | null
  lastScanned: string
  scanStatus: ScanStatus
  scanDurationMs: number
  /** OPTIONS 探测得到的 Allow 方法列表（可能为空）。 */
  allowedMethods: string[]
  /** 随机路径 404 页面的特征片段，用于判断 SPA/框架错误页。 */
  errorPageSignature: string | null
}

/** 归一化后的受影响产品条目（NVD 与 GitHub Advisory 统一到同一形状）。 */
export type AffectedProduct = {
  /** 归一化后的组件名，例如 http_server、fastjson、jackson-databind。 */
  component: string
  versionStart: string | null
  versionEnd: string | null
  /** true 表示 versionEnd 为闭区间（<=），false 表示开区间（<）。 */
  versionEndInclusive: boolean
  /** 原始 CPE 或生态标识，保留用于取证。 */
  criteria: string | null
  ecosystem: string | null
}

/** CVE 详情。 */
export type CveInfo = {
  cveId: string
  description: string
  cvssScore: number | null
  severity: string | null
  affectedProducts: AffectedProduct[]
  references: string[]
  source: string
  error?: string
}

/** 单条公开 PoC。 */
export type PocEntry = {
  source: string
  name: string
  url: string
  description: string
  stars?: number
  language?: string | null
  updated?: string
}

/** PoC 搜索结果。 */
export type PocResult = {
  cveId: string
  pocCount: number
  pocs: PocEntry[]
  message?: string
  error?: string
}

/** 复测判定结论。 */
export type Verdict = 'VULNERABLE' | 'NOT_VULNERABLE' | 'UNCERTAIN'

/** 情报预判结论。 */
export type Applicability = 'yes' | 'no' | 'uncertain'

export type VersionRange = {
  start: string | null
  end: string | null
  endInclusive: boolean
}

/** 情报判读结果。 */
export type Judgment = {
  cveId: string
  applicable: Applicability
  reason: string
  skipRecon: boolean
  matchedComponent: string | null
  targetVersion: string | null
  range: VersionRange | null
}

/** 单次被动探测的证据。 */
export type ProbeEvidence = {
  url: string
  method: string
  statusCode: number
  server: string | null
  poweredBy: string | null
  allowedMethods: string[]
  interestingHeaders: Record<string, string>
  note: string
}

/** 单个 CVE 的复测结果（canonical JSON）。 */
export type RetestResult = {
  cveId: string
  targetUrl: string
  verdict: Verdict
  applicable: Applicability
  confidence: number
  reason: string
  /** 可复现性：high 表示有公开 PoC 可参照，low 表示仅有版本推断。 */
  reproducibility: 'high' | 'medium' | 'low'
  component: { name: string; version: string | null } | null
  affectedRange: VersionRange | null
  cvss: { score: number | null; severity: string | null }
  poc: { count: number; top: PocEntry[] }
  intel: {
    cacheHit: boolean
    lastScanned: string
    server: string | null
    waf: string | null
  }
  evidence: ProbeEvidence[]
  pentest: PentestSummary | null
  limitations: string[]
  generatedAt: string
}

/** 复测结果中内嵌的渗透测试摘要。 */
export type PentestSummary = {
  executed: boolean
  success: boolean
  stepsTotal: number
  stepsSuccess: number
  stepsSkipped: number
  summary: string
  reasons: string[]
}

/** 批量复测结果。 */
export type BatchRetestResult = {
  targetUrl: string
  total: number
  stats: {
    vulnerable: number
    notVulnerable: number
    uncertain: number
    probed: number
    skippedByIntel: number
  }
  results: RetestResult[]
  report: string
  reportPath: string | null
  reportJsonPath: string | null
  generatedAt: string
}

/** 复现步骤。 */
export type ReproStep = {
  stepId: number
  description: string
  httpMethod: string
  endpoint: string
  headers: Record<string, string>
  body: string | null
  expectedIndicators: string[]
  isDestructive: boolean
}

/** 复现文档。 */
export type ReproDoc = {
  cveId: string
  title: string
  description: string
  affectedComponent: string
  affectedVersions: string
  severity: string
  references: string[]
  steps: ReproStep[]
}

/** 载荷安全化结果。 */
export type SafePayload = {
  original: string
  safeVersion: string
  payloadType: string
  isSafe: boolean
  reason: string
}

/** 单个复现步骤的执行结果。 */
export type PentestStepResult = {
  stepId: number
  success: boolean
  evidence: string
  requestUrl: string
  responseCode: number
  responsePreview: string
  executionMs: number
  error: string
}

/** 非破坏性复现报告。 */
export type PentestReport = {
  cveId: string
  targetUrl: string
  overallSuccess: boolean
  stepsTotal: number
  stepsSuccess: number
  stepsSkipped: number
  summary: string
  recommendations: string[]
  results: PentestStepResult[]
}

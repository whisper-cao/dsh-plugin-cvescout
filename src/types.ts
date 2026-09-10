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

/** 对端证书事实（仅记录，不做信任判定）。 */
export type TlsCertificateIntel = {
  subject: string | null
  issuer: string | null
  validFrom: string | null
  validTo: string | null
  /** 距过期天数；已过期为负数。 */
  daysUntilExpiry: number | null
  altNames: string[]
  /** 公钥长度（RSA 位数 / EC 曲线位数），拿不到为 null。 */
  keyBits: number | null
  serialNumber: string | null
  fingerprint256: string | null
}

/**
 * TLS 握手探测结果。
 *
 * `http2` 是最关键的一位：由 ALPN 是否协商出 `h2` 决定，用于排除
 * 「仅 HTTP/2 可触发」的一类 CVE。
 */
export type TlsIntel = {
  /** 握手是否成功完成。 */
  ok: boolean
  error: string | null
  /** 协商出的 TLS 版本，如 TLSv1.3。 */
  protocol: string | null
  cipher: string | null
  /** ALPN 协商结果：'h2' / 'http/1.1'；服务器未选中任何协议时为 null。 */
  alpnProtocol: string | null
  alpnNegotiated: boolean
  /** HTTP/2 over TLS 是否可用。 */
  http2: boolean
  /** 得出 http2 结论的依据，直接写进报告。 */
  http2Evidence: string
  certificate: TlsCertificateIntel | null
  /** 证书链是否被本机信任（自签/内网 CA 为 false，本身不代表漏洞）。 */
  certTrusted: boolean | null
  elapsedMs: number
}

/** 与协议能力相关的 HTTP 层线索。 */
export type ProtocolHints = {
  /** `Alt-Svc` 响应头原文。 */
  altSvc: string | null
  /** `Alt-Svc` 是否广告了 h2 服务。 */
  http2Advertised: boolean
  /** `Via` 响应头，提示前置代理。 */
  viaProxy: string | null
}

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
  /**
   * TLS / ALPN 探测结果。旧版本写入的情报缓存里没有这个字段，因此可空，
   * 判读时必须容忍 `undefined`（视为「协议能力未知」而不是「不支持」）。
   */
  tls?: TlsIntel | null
  /** HTTP 层协议线索（Alt-Svc / Via）。同样兼容旧缓存。 */
  protocolHints?: ProtocolHints | null
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
  /**
   * 给出 `applicable: 'no'` 时的依据来源：
   *  - `version`：目标组件版本明确落在受影响区间之外；
   *  - `protocol`：版本可能命中，但目标不满足该 CVE 的协议前置条件（如未启用 HTTP/2）。
   * 其余情况为 null。
   */
  exclusionBasis?: 'version' | 'protocol' | null
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
    /** 目标的 TLS / 协议能力事实，便于人工复核「前置条件是否成立」。 */
    tls: TlsIntel | null
    protocolHints: ProtocolHints | null
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

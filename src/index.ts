/**
 * CVEScout DeepSeek Harness 插件。
 *
 * 这是能力插件，不接管编排：Harness 已有 agent loop 与提示词组装，本插件只把
 * 「确定性能力」注册成面向模型的工具：
 *
 *   原子能力   target_scope / cve_lookup / cve_poc_search / http_probe /
 *              fingerprint / intel_cache / safety_audit
 *   编排能力   cve_retest / cve_batch_retest / cve_repro_parse / pentest_repro
 *
 * 使用方式：用户在对话里说「<站点> 涉及 <CVE>，帮我排查」即可，无需记工具名。
 * 目标写法很宽松（完整 URL / 裸域名 / host:port / targetAliases 里的系统名）。
 *
 * 安全红线（全部内建在护栏里，不依赖提示词）：
 *   - 只做被动探测，不投递攻击载荷，不向目标写入任何内容；
 *   - 所有探测必须命中授权域名白名单（按主机名精确/后缀匹配，而非子串包含）；
 *   - 速率与总量双限，全量审计且落库前脱敏；
 *   - 非幂等方法默认关闭，需显式开启配置；
 *   - 复现文档中的破坏性步骤一律跳过，载荷先做无害化替换。
 *
 * 用法（cordis.yml / patch）：
 *   - insert:
 *       - id: cvescout
 *         name: '/absolute/path/to/dsh-plugin-cvescout/src/index.ts'
 *         config:
 *           allowedDomains: ['example.com']                   # 已获授权测试的目标
 *           targetAliases:
 *             内部管理系统: erp.example.com                    # 用户可能只说系统名
 *           defaultScheme: https
 *
 * 加载后即可用自然语言触发，例如「portal.example.com 涉及 CVE-2021-44228，帮我排查」。
 * 自动路由由三部分保证：本模块注册的系统提示词指引段（见 prompt.ts）、
 * 工具 description 里的触发话术、以及 target_scope 的别名解析。
 */
import type { Context } from '@deepseek-ai/cordis'
import { Config, resolveConfig } from './config.ts'
import type { CvescoutConfig } from './config.ts'
import { IntelCache, resolveCachePath } from './core/cache.ts'
import { IntelJudge } from './core/judge.ts'
import { SafetyGuard } from './core/safety.ts'
import type { CvescoutRuntime } from './core/runtime.ts'
import { registerPromptSection } from './prompt.ts'
import { TOOL_NAMES, registerAllTools } from './tools/index.ts'

/** 插件名。 */
export const name = 'cvescout'

/** 依赖工具注册表：Cordis 会等 ctx.tools 就绪后再调用 apply。 */
export const inject = ['tools']

/** 导出配置 schema，cordis.yml 中的 config 由它校验并补默认值。 */
export { Config }

/** 构造运行期依赖集合。 */
export function createRuntime(config?: Partial<CvescoutConfig> | null): CvescoutRuntime {
  const cfg = resolveConfig(config)
  return {
    cfg,
    safety: new SafetyGuard(cfg),
    cache: new IntelCache(resolveCachePath(cfg), cfg.cacheTtlHours),
    judge: new IntelJudge(),
  }
}

export function apply(ctx: Context, config?: CvescoutConfig): void {
  const runtime = createRuntime(config)
  registerAllTools(ctx, runtime)
  // 常驻系统提示词指引：把「什么话术该走本插件」教给模型，仅靠工具描述不够可靠。
  registerPromptSection(ctx, runtime)

  const scope =
    runtime.cfg.allowedDomains.length > 0
      ? `授权域名 ${runtime.cfg.allowedDomains.join(', ')}`
      : '未设置授权域名白名单（不限制目标，仅建议离线验证时使用）'
  const aliasCount = Object.keys(runtime.cfg.targetAliases).length

  console.log(
    `[cvescout] 已注册 ${TOOL_NAMES.length} 个工具 + 1 段系统提示词指引；${scope}；` +
      `别名 ${aliasCount} 条；默认 ${runtime.cfg.defaultScheme}` +
      `${runtime.cfg.allowSchemeFallback ? '（连接失败自动换协议）' : ''}；` +
      `限速 ${runtime.cfg.maxRequestsPerMinute}/min、总量 ${runtime.cfg.maxTotalRequests}；` +
      `情报缓存 ${runtime.cache.path}`,
  )
}

/**
 * 插件运行期依赖集合。各工具与流水线只依赖这个接口，便于单测时替换。
 */
import type { CvescoutConfig } from '../config.ts'
import type { IntelCache } from './cache.ts'
import type { IntelJudge } from './judge.ts'
import type { SafetyGuard } from './safety.ts'
import { resolveTargetInput } from './url.ts'

export interface CvescoutRuntime {
  cfg: CvescoutConfig
  safety: SafetyGuard
  cache: IntelCache
  judge: IntelJudge
}

/**
 * 把工具入参里的目标解析成绝对 URL。
 *
 * 用户/模型给的往往是裸域名（`portal.example.com`）或配置里的系统别名，所有工具都必须
 * 在**安全护栏校验之前**调用它，否则合法目标会因为解析失败被误判成越权。
 */
export function resolveTarget(runtime: CvescoutRuntime, raw: string): string {
  return resolveTargetInput(raw, {
    defaultScheme: runtime.cfg.defaultScheme,
    aliases: runtime.cfg.targetAliases,
  })
}

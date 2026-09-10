/**
 * 工具注册入口：把原子工具与编排工具一次性挂到 ctx.tools 上。
 */
import type { Context } from '@deepseek-ai/cordis'
import type { CvescoutRuntime } from '../core/runtime.ts'
import { registerAtomicTools } from './atomic.ts'
import { registerPipelineTools } from './pipeline.ts'

/** 本插件对外暴露的全部工具名（顺序即推荐调用顺序）。 */
export const TOOL_NAMES: readonly string[] = [
  'target_scope',
  'cve_lookup',
  'cve_poc_search',
  'http_probe',
  'fingerprint',
  'intel_cache',
  'safety_audit',
  'cve_retest',
  'cve_batch_retest',
  'cve_repro_parse',
  'pentest_repro',
]

export function registerAllTools(ctx: Context, runtime: CvescoutRuntime): void {
  registerAtomicTools(ctx, runtime)
  registerPipelineTools(ctx, runtime)
}

import { registerAtomicTools } from "./atomic.js";
import { registerPipelineTools } from "./pipeline.js";
/** 本插件对外暴露的全部工具名（顺序即推荐调用顺序）。 */
export const TOOL_NAMES = [
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
];
export function registerAllTools(ctx, runtime) {
    registerAtomicTools(ctx, runtime);
    registerPipelineTools(ctx, runtime);
}

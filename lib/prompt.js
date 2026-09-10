/** 段落注册名。 */
export const PROMPT_SECTION_NAME = 'plugin:cvescout:guidance';
/** 段落顺序。约定：工具指引使用 100–199。 */
export const PROMPT_SECTION_ORDER = 120;
/** 生成指引文本。每次组装提示词时求值，因此配置改动会立即生效。 */
export function buildGuidanceText(runtime) {
    const { cfg, safety } = runtime;
    const aliasEntries = Object.entries(cfg.targetAliases);
    const scopeLine = cfg.allowedDomains.length > 0
        ? `已授权目标域名：${cfg.allowedDomains.join('、')}。此范围之外的目标会被工具直接拒绝。`
        : '当前未配置授权域名白名单（`allowedDomains` 为空），不限制目标——建议尽快在 `cordis.yml` 里填入已获授权测试的域名。';
    const aliasLine = aliasEntries.length > 0
        ? `已配置系统别名（用户可能只说名字）：${aliasEntries.map(([key, value]) => `${key} → ${value}`).join('；')}。`
        : '未配置系统别名（`targetAliases`）。';
    return [
        '### CVE 复测与漏洞影响面验证（CVEScout 插件）',
        '',
        '当用户提到「某个站点/系统/域名 + 某个 CVE」并要求排查、验证、复测、确认是否受影响时，' +
            '必须调用本插件的工具取实证，不要凭自身知识或版本猜测直接下结论：',
        '',
        '1. 目标不是标准域名（用户只给了系统名或简称），或不确定该目标是否已获授权 → 先调 `target_scope` 解析别名并确认授权范围。',
        '2. 单个 CVE → 调 `cve_retest`（传域名即可，会自动补协议）。同一目标有多个 CVE → 调 `cve_batch_retest`。',
        '3. 结论为 `UNCERTAIN`、又有公开 PoC、且用户希望进一步实锤 → 先 `cve_repro_parse` 看清步骤，再用 `pentest_repro` 执行非破坏性步骤（建议先 `dry_run: true` 预览）。',
        '4. 汇报结论时必须同时给出：verdict、confidence、结论依据、以及 limitations。不要把 `UNCERTAIN` 说成「应该没问题」或「大概率安全」。',
        '5. 目标被安全护栏拦截时，如实告知用户该域名不在授权范围，并提示把域名加入 `allowedDomains`（或给系统名配 `targetAliases`）；不要尝试绕过校验。',
        '',
        '边界：本插件只做被动探测与非破坏性复现，不投递攻击载荷、不写入目标数据，' +
            '因此 `VULNERABLE` 只在拿到复现正向证据时才成立。',
        '',
        `${scopeLine}${aliasLine}`,
    ].join('\n');
}
/** 注册指引段。服务就绪后 Cordis 才会执行回调，回调内的注册随插件卸载自动清理。 */
export function registerPromptSection(ctx, runtime) {
    ctx.inject(['systemPrompt'], (scoped) => {
        scoped.systemPrompt.section({
            name: PROMPT_SECTION_NAME,
            order: PROMPT_SECTION_ORDER,
            text: () => buildGuidanceText(runtime),
        });
    });
}

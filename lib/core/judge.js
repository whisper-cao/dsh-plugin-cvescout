/** 版本号切段：先按分隔符切，再在段内切出数字/字母块。 */
function segments(version) {
    const cleaned = String(version ?? '').trim().replace(/^[vV]/, '');
    if (!cleaned)
        return [];
    return cleaned
        .split(/[.\-_+~:]/)
        .filter((segment) => segment.length > 0)
        .map((segment) => {
        const chunks = [];
        const re = /(\d+)|([A-Za-z]+)/g;
        let match;
        while ((match = re.exec(segment)) !== null) {
            chunks.push(match[1] !== undefined ? Number(match[1]) : match[2].toLowerCase());
        }
        return chunks;
    });
}
function compareChunk(a, b) {
    if (a === undefined && b === undefined)
        return 0;
    if (a === undefined)
        return typeof b === 'number' ? -1 : 1;
    if (b === undefined)
        return typeof a === 'number' ? 1 : -1;
    if (typeof a === 'number' && typeof b === 'number')
        return a === b ? 0 : a > b ? 1 : -1;
    if (typeof a === 'string' && typeof b === 'string') {
        if (a === b)
            return 0;
        return a > b ? 1 : -1;
    }
    // 数字块 > 字母块：1.2.0 > 1.2.0-rc1，符合常见语义化版本直觉。
    return typeof a === 'number' ? 1 : -1;
}
/** best-effort 版本比较。返回 -1 / 0 / 1。无法比较时按字符串比较兜底。 */
export function compareVersions(a, b) {
    const sa = segments(a);
    const sb = segments(b);
    if (sa.length === 0 || sb.length === 0) {
        return a === b ? 0 : a > b ? 1 : -1;
    }
    const length = Math.max(sa.length, sb.length);
    for (let i = 0; i < length; i += 1) {
        const ca = sa[i] ?? [];
        const cb = sb[i] ?? [];
        const chunkLength = Math.max(ca.length, cb.length);
        for (let j = 0; j < chunkLength; j += 1) {
            const result = compareChunk(ca[j], cb[j]);
            if (result !== 0)
                return result;
        }
    }
    return 0;
}
/** 判断版本是否落在受影响区间内。区间信息缺失的一侧视为无穷。 */
export function isVersionInRange(version, range) {
    if (range.start) {
        const lower = compareVersions(version, range.start);
        if (lower < 0)
            return false;
    }
    if (range.end) {
        const upper = compareVersions(version, range.end);
        if (range.endInclusive ? upper > 0 : upper >= 0)
            return false;
    }
    return true;
}
/** 归一化组件名：去掉大小写、分隔符与常见后缀噪声。 */
export function normalizeComponentName(name) {
    return String(name ?? '')
        .toLowerCase()
        .replace(/^cpe:2\.3:[aho*]:[^:]*:/, '')
        .replace(/\.(js|py|java|net|rb|php|go)$/, '')
        .replace(/[^a-z0-9]/g, '');
}
/** 组件名别名表：CPE 里的写法 → 指纹里常见的写法。 */
const COMPONENT_ALIASES = {
    httpserver: ['apache', 'httpd', 'apachehttpserver'],
    apache: ['apache', 'httpd', 'httpserver'],
    nginx: ['nginx'],
    tomcat: ['tomcat', 'apachetomcat', 'coyote'],
    springboot: ['springboot', 'spring'],
    springframework: ['spring', 'springframework'],
    fastjson: ['fastjson'],
    jackson: ['jackson', 'jacksondatabind'],
    log4j: ['log4j', 'log4j2'],
    struts: ['struts', 'struts2'],
    mchangecommonsjava: ['mchangecommonsjava', 'mchange'],
};
/** 子串匹配的最小长度：短名（如 CPE 里的 nx / ip / vm）极易误命中，必须排除。 */
const MIN_SUBSTRING_LENGTH = 5;
/** 在情报里查找与 CPE 组件名对应的条目。 */
export function findIntelComponent(intel, componentName) {
    const normalized = normalizeComponentName(componentName);
    if (!normalized)
        return null;
    const candidates = new Set([normalized, ...(COMPONENT_ALIASES[normalized] ?? [])]);
    for (const component of intel.techStack) {
        const stackName = normalizeComponentName(component.name);
        if (!stackName)
            continue;
        for (const candidate of candidates) {
            if (matchesName(stackName, candidate)) {
                return { name: component.name, version: component.version ?? null };
            }
        }
    }
    const haystacks = [intel.server, intel.framework].filter((value) => Boolean(value));
    for (const haystack of haystacks) {
        const normalizedHaystack = normalizeComponentName(haystack);
        for (const candidate of candidates) {
            if (candidate.length >= MIN_SUBSTRING_LENGTH && normalizedHaystack.includes(candidate)) {
                const versionMatch = haystack.match(/(\d+(?:\.\d+)+)/);
                return { name: componentName, version: versionMatch ? versionMatch[1] : null };
            }
        }
    }
    return null;
}
/**
 * 组件名匹配规则：先精确，再允许长名子串。
 *
 * 这里刻意不做「短名子串」匹配——CPE 里 `nx`（Siemens NX）会被 `nginx` 包含，
 * 早先的宽松匹配会把 log4j 的 CVE 判到 nginx 目标上。
 */
function matchesName(stackName, candidate) {
    if (stackName === candidate)
        return true;
    const shortest = Math.min(stackName.length, candidate.length);
    if (shortest < MIN_SUBSTRING_LENGTH)
        return false;
    return stackName.includes(candidate) || candidate.includes(stackName);
}
export class IntelJudge {
    /**
     * 预判 CVE 对目标是否适用。
     *
     * `skipRecon: true` 表示证据已经足够（例如版本明确不在受影响区间），
     * 调用方可以直接给 NOT_VULNERABLE，无需再做主动探测。
     */
    judge(cveInfo, intel) {
        const cveId = cveInfo.cveId;
        const products = cveInfo.affectedProducts ?? [];
        if (products.length === 0) {
            return {
                cveId,
                applicable: 'uncertain',
                reason: cveInfo.error
                    ? `CVE 情报不可用（${cveInfo.error}），无法判读`
                    : 'CVE 信息中缺少受影响产品数据',
                skipRecon: false,
                matchedComponent: null,
                targetVersion: null,
                range: null,
            };
        }
        const notes = [];
        for (const product of products) {
            const matched = findIntelComponent(intel, product.component);
            if (!matched)
                continue;
            const range = {
                start: product.versionStart,
                end: product.versionEnd,
                endInclusive: product.versionEndInclusive,
            };
            if (!matched.version) {
                notes.push(`目标存在 ${matched.name} 但未能取到版本号，无法与 ${product.component} 区间比对`);
                continue;
            }
            if (isVersionInRange(matched.version, range)) {
                return {
                    cveId,
                    applicable: 'yes',
                    reason: `目标运行 ${matched.name} ${matched.version}，落在受影响区间 ${formatRange(range)} 内`,
                    skipRecon: false,
                    matchedComponent: matched.name,
                    targetVersion: matched.version,
                    range,
                };
            }
            return {
                cveId,
                applicable: 'no',
                reason: `目标运行 ${matched.name} ${matched.version}，不在受影响区间 ${formatRange(range)} 内`,
                skipRecon: true,
                matchedComponent: matched.name,
                targetVersion: matched.version,
                range,
            };
        }
        return {
            cveId,
            applicable: 'uncertain',
            reason: notes.length > 0
                ? notes.join('；')
                : `目标指纹中未识别到 CVE 涉及组件（${distinctComponents(products).slice(0, 4).join(', ')}），需人工核查`,
            skipRecon: false,
            matchedComponent: null,
            targetVersion: null,
            range: null,
        };
    }
    /** 批量判读。 */
    batchJudge(cveList, intel) {
        const judgments = cveList.map((cve) => this.judge(cve, intel));
        return {
            judgments,
            summary: {
                total: judgments.length,
                applicable: judgments.filter((item) => item.applicable === 'yes').length,
                notApplicable: judgments.filter((item) => item.applicable === 'no').length,
                uncertain: judgments.filter((item) => item.applicable === 'uncertain').length,
                canSkipRecon: judgments.filter((item) => item.skipRecon).length,
            },
        };
    }
}
/** 生成人类可读的区间描述。 */
export function formatRange(range) {
    const start = range.start ? `>= ${range.start}` : '任意低版本';
    const end = range.end ? `${range.endInclusive ? '<= ' : '< '}${range.end}` : '任意高版本';
    return `${start} 且 ${end}`;
}
/** 去重后的受影响组件名。 */
function distinctComponents(products) {
    return Array.from(new Set(products.map((item) => item.component)));
}

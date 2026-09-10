import { fetchJson } from "../core/http.js";
const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,}$/i;
/** 归一化 CVE 编号。 */
export function normalizeCveId(cveId) {
    return String(cveId ?? '').trim().toUpperCase();
}
/** 校验 CVE 编号格式。 */
export function isValidCveId(cveId) {
    return CVE_ID_PATTERN.test(normalizeCveId(cveId));
}
/** 查询 CVE 详情。查询失败时返回带 error 字段的对象而不是抛异常。 */
export async function lookupCve(cfg, cveIdRaw, signal) {
    const cveId = normalizeCveId(cveIdRaw);
    if (!isValidCveId(cveId)) {
        return emptyCve(cveId, `CVE 编号格式非法: ${cveIdRaw}`);
    }
    const nvd = await queryNvd(cfg, cveId, signal);
    if (nvd && !nvd.error)
        return nvd;
    const github = await queryGithubAdvisory(cfg, cveId, signal);
    if (github && !github.error)
        return github;
    return (nvd ??
        github ?? emptyCve(cveId, 'NVD 与 GitHub Advisory 均未返回有效数据'));
}
function emptyCve(cveId, error) {
    return {
        cveId,
        description: '',
        cvssScore: null,
        severity: null,
        affectedProducts: [],
        references: [],
        source: 'none',
        error,
    };
}
async function queryNvd(cfg, cveId, signal) {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`;
    const headers = { accept: 'application/json' };
    if (cfg.nvdApiKey?.trim())
        headers.apiKey = cfg.nvdApiKey.trim();
    const result = await fetchJson(cfg, url, headers, signal);
    if (!result.data) {
        return { ...emptyCve(cveId, `NVD 查询失败（${result.error ?? '未知原因'}）`), source: 'NVD' };
    }
    const data = result.data;
    const vulnerability = data.vulnerabilities?.[0]?.cve;
    if (!vulnerability) {
        return { ...emptyCve(cveId, data.message ?? 'NVD 中未找到该 CVE'), source: 'NVD' };
    }
    const description = vulnerability.descriptions?.find((item) => item.lang === 'en')?.value ??
        vulnerability.descriptions?.[0]?.value ??
        '';
    let cvssScore = null;
    let severity = null;
    const metrics = vulnerability.metrics ?? {};
    for (const key of ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']) {
        const entry = metrics[key]?.[0]?.cvssData;
        if (entry) {
            cvssScore = typeof entry.baseScore === 'number' ? entry.baseScore : null;
            severity = entry.baseSeverity ?? null;
            break;
        }
    }
    const products = [];
    for (const configuration of vulnerability.configurations ?? []) {
        for (const node of configuration.nodes ?? []) {
            for (const match of node.cpeMatch ?? []) {
                if (!match.vulnerable)
                    continue;
                const parsed = parseCpe(match.criteria ?? '');
                products.push({
                    component: parsed.product || parsed.vendor || 'unknown',
                    // CPE 里的 `*` 表示「所有版本」，必须转成 null：空串会让区间判断被跳过。
                    versionStart: match.versionStartIncluding ?? match.versionStartExcluding ?? (parsed.version || null),
                    versionEnd: match.versionEndIncluding ?? match.versionEndExcluding ?? null,
                    versionEndInclusive: Boolean(match.versionEndIncluding),
                    criteria: match.criteria ?? null,
                    ecosystem: null,
                });
            }
        }
    }
    return {
        cveId,
        description,
        cvssScore,
        severity,
        affectedProducts: dedupeProducts(products),
        references: (vulnerability.references ?? [])
            .map((ref) => ref.url ?? '')
            .filter((url) => url.length > 0)
            .slice(0, 8),
        source: 'NVD',
    };
}
async function queryGithubAdvisory(cfg, cveId, signal) {
    const url = `https://api.github.com/advisories?cve_id=${encodeURIComponent(cveId)}`;
    const headers = githubHeaders(cfg);
    const result = await fetchJson(cfg, url, headers, signal);
    if (!result.data) {
        return {
            ...emptyCve(cveId, `GitHub Advisory 查询失败（${result.error ?? '未知原因'}）`),
            source: 'GitHub Advisory',
        };
    }
    const advisory = result.data[0];
    if (!advisory) {
        return { ...emptyCve(cveId, 'GitHub Advisory 中未找到该 CVE'), source: 'GitHub Advisory' };
    }
    const products = (advisory.vulnerabilities ?? []).map((vulnerability) => {
        const range = parseVersionRangeString(vulnerability.vulnerable_version_range ?? '');
        return {
            component: vulnerability.package?.name ?? 'unknown',
            versionStart: range.start,
            versionEnd: range.end,
            versionEndInclusive: range.endInclusive,
            criteria: null,
            ecosystem: vulnerability.package?.ecosystem ?? null,
        };
    });
    return {
        cveId,
        description: advisory.summary ?? '',
        cvssScore: advisory.cvss?.score ?? null,
        severity: advisory.severity ?? null,
        affectedProducts: dedupeProducts(products),
        references: (advisory.references ?? [])
            .map((ref) => (typeof ref === 'string' ? ref : (ref.url ?? '')))
            .filter((url) => url.length > 0)
            .slice(0, 8),
        source: 'GitHub Advisory',
    };
}
/** GitHub API 通用请求头（含可选 Token 与强制 UA）。 */
export function githubHeaders(cfg) {
    const token = cfg.githubToken?.trim() || process.env.GITHUB_TOKEN?.trim() || '';
    const headers = {
        accept: 'application/vnd.github+json',
        'x-github-api-version': '2022-11-28',
    };
    if (token)
        headers.authorization = `Bearer ${token}`;
    return headers;
}
/** 解析 CPE 2.3 字符串，取出 vendor / product / version。 */
export function parseCpe(criteria) {
    const parts = criteria.split(':');
    if (parts.length < 6 || parts[0] !== 'cpe')
        return { vendor: '', product: '', version: null };
    const vendor = starToEmpty(parts[3]);
    const product = starToEmpty(parts[4]);
    // `*` / `-` 表示「不限版本」，用 null 表示，避免下游把空串当成有效约束。
    const version = starToEmpty(parts[5]) || null;
    return { vendor, product, version };
}
function starToEmpty(value) {
    if (!value || value === '*' || value === '-')
        return '';
    return value;
}
/** 解析 ">= 1.2.0, < 1.2.84" / "< 2.11.1" 这类范围字符串。 */
export function parseVersionRangeString(raw) {
    let start = null;
    let end = null;
    let endInclusive = false;
    for (const piece of String(raw ?? '').split(',')) {
        const token = piece.trim();
        if (!token)
            continue;
        const match = token.match(/^(>=|<=|>|<|=|==)\s*([0-9][0-9A-Za-z.\-_+]*)$/);
        if (!match)
            continue;
        const operator = match[1];
        const version = match[2];
        if (operator === '>=' || operator === '>') {
            start = version;
        }
        else if (operator === '<=' || operator === '<') {
            end = version;
            endInclusive = operator === '<=';
        }
        else {
            start = version;
            end = version;
            endInclusive = true;
        }
    }
    return { start, end, endInclusive };
}
function dedupeProducts(products) {
    const seen = new Set();
    const result = [];
    for (const product of products) {
        const key = `${product.component}|${product.versionStart ?? ''}|${product.versionEnd ?? ''}|${product.versionEndInclusive}`;
        if (seen.has(key))
            continue;
        seen.add(key);
        result.push(product);
    }
    // 应用类 CPE（a）排在硬件（h）/ 操作系统（o）之前：NVD 的 configuration 里
    // 常混入大量平台 CPE，先给出真正的受影响应用更利于模型判读。
    return result.sort((left, right) => cpePartRank(left.criteria) - cpePartRank(right.criteria));
}
function cpePartRank(criteria) {
    if (!criteria)
        return 3;
    const part = criteria.split(':')[2];
    if (part === 'a')
        return 0;
    if (part === 'o')
        return 1;
    if (part === 'h')
        return 2;
    return 3;
}

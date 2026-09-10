/**
 * 情报缓存。
 *
 * 单文件 JSON + 原子写 + TTL + 写入串行化，而不是引入数据库：缓存规模远小于
 * 依赖清单级数据，且可直接人工查看与归档，零原生依赖。写入串行化避免并发
 * 工具调用互相覆盖同一份文件。
 */
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
const CACHE_VERSION = 1;
/** 解析缓存文件路径：配置优先，否则落到 ~/.cvescout/。 */
export function resolveCachePath(cfg) {
    const configured = cfg.cachePath?.trim();
    return configured ? configured : join(homedir(), '.cvescout', 'intel-cache.json');
}
/** 解析报告输出目录。 */
export function resolveReportDir(cfg) {
    const configured = cfg.reportDir?.trim();
    return configured ? configured : join(homedir(), '.cvescout', 'reports');
}
export class IntelCache {
    filePath;
    ttlHours;
    queue = Promise.resolve();
    constructor(filePath, ttlHours) {
        this.filePath = filePath;
        this.ttlHours = ttlHours;
    }
    get path() {
        return this.filePath;
    }
    /** 读取目标情报；不存在或已过期返回 null。 */
    async get(targetUrl) {
        const data = await this.read();
        const entry = data.entries[normalizeKey(targetUrl)];
        if (!entry)
            return null;
        if (this.isStale(entry.lastScanned))
            return null;
        return entry;
    }
    /** 写入（覆盖）目标情报。 */
    async set(intel) {
        await this.enqueue(async () => {
            const data = await this.read();
            data.entries[normalizeKey(intel.targetUrl)] = intel;
            await this.write(data);
        });
    }
    /** 使单个目标缓存失效，返回是否真的删掉了条目。 */
    async invalidate(targetUrl) {
        return this.enqueue(async () => {
            const data = await this.read();
            const key = normalizeKey(targetUrl);
            if (!(key in data.entries))
                return false;
            delete data.entries[key];
            await this.write(data);
            return true;
        });
    }
    /** 列出全部缓存条目及其新鲜度。 */
    async list() {
        const data = await this.read();
        return Object.values(data.entries)
            .map((entry) => ({
            targetUrl: entry.targetUrl,
            lastScanned: entry.lastScanned,
            scanStatus: entry.scanStatus,
            stale: this.isStale(entry.lastScanned),
            components: entry.techStack?.length ?? 0,
        }))
            .sort((a, b) => b.lastScanned.localeCompare(a.lastScanned));
    }
    /** 清空缓存，返回被清除的条目数。 */
    async clear() {
        return this.enqueue(async () => {
            const data = await this.read();
            const count = Object.keys(data.entries).length;
            await this.write({ version: CACHE_VERSION, entries: {} });
            return count;
        });
    }
    /** 判断某个扫描时间是否超过 TTL。 */
    isStale(lastScanned) {
        const scanned = Date.parse(lastScanned);
        if (Number.isNaN(scanned))
            return true;
        return Date.now() - scanned > this.ttlHours * 3600_000;
    }
    async read() {
        try {
            const raw = await readFile(this.filePath, 'utf8');
            const parsed = JSON.parse(raw);
            if (!parsed || typeof parsed !== 'object' || typeof parsed.entries !== 'object' || parsed.entries === null) {
                return { version: CACHE_VERSION, entries: {} };
            }
            return { version: CACHE_VERSION, entries: parsed.entries };
        }
        catch {
            return { version: CACHE_VERSION, entries: {} };
        }
    }
    async write(data) {
        await mkdir(dirname(this.filePath), { recursive: true });
        const tmp = `${this.filePath}.tmp`;
        await writeFile(tmp, JSON.stringify(data, null, 2), 'utf8');
        await rename(tmp, this.filePath);
    }
    enqueue(task) {
        const run = this.queue.then(task, task);
        this.queue = run.then(() => undefined, () => undefined);
        return run;
    }
}
/**
 * URL 归一化键：忽略末尾斜杠与查询串，避免同一目标重复侦察。
 * 裸域名（`portal.example.com`）按 https 补齐后再归一化，保证与已解析 URL 的键一致。
 */
export function normalizeKey(targetUrl) {
    const attempt = (candidate) => {
        try {
            const parsed = new URL(candidate);
            if (!parsed.hostname)
                return null;
            parsed.hash = '';
            parsed.search = '';
            const path = parsed.pathname.replace(/\/+$/, '');
            return `${parsed.protocol}//${parsed.host}${path}`;
        }
        catch {
            return null;
        }
    };
    const raw = String(targetUrl ?? '').trim();
    return attempt(raw) ?? attempt(`https://${raw.replace(/^\/+/, '')}`) ?? raw;
}

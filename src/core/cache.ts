/**
 * 情报缓存。
 *
 * 单文件 JSON + 原子写 + TTL + 写入串行化，而不是引入数据库：缓存规模远小于
 * 依赖清单级数据，且可直接人工查看与归档，零原生依赖。写入串行化避免并发
 * 工具调用互相覆盖同一份文件。
 */
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import type { CvescoutConfig } from '../config.ts'
import type { TargetIntel } from '../types.ts'

export interface CacheEntrySummary {
  targetUrl: string
  lastScanned: string
  scanStatus: string
  stale: boolean
  components: number
}

interface CacheFile {
  version: number
  entries: Record<string, TargetIntel>
}

const CACHE_VERSION = 1

/** 解析缓存文件路径：配置优先，否则落到 ~/.cvescout/。 */
export function resolveCachePath(cfg: CvescoutConfig): string {
  const configured = cfg.cachePath?.trim()
  return configured ? configured : join(homedir(), '.cvescout', 'intel-cache.json')
}

/** 解析报告输出目录。 */
export function resolveReportDir(cfg: CvescoutConfig): string {
  const configured = cfg.reportDir?.trim()
  return configured ? configured : join(homedir(), '.cvescout', 'reports')
}

export class IntelCache {
  private readonly filePath: string
  private readonly ttlHours: number
  private queue: Promise<unknown> = Promise.resolve()

  constructor(filePath: string, ttlHours: number) {
    this.filePath = filePath
    this.ttlHours = ttlHours
  }

  get path(): string {
    return this.filePath
  }

  /** 读取目标情报；不存在或已过期返回 null。 */
  async get(targetUrl: string): Promise<TargetIntel | null> {
    const data = await this.read()
    const entry = data.entries[normalizeKey(targetUrl)]
    if (!entry) return null
    if (this.isStale(entry.lastScanned)) return null
    return entry
  }

  /** 写入（覆盖）目标情报。 */
  async set(intel: TargetIntel): Promise<void> {
    await this.enqueue(async () => {
      const data = await this.read()
      data.entries[normalizeKey(intel.targetUrl)] = intel
      await this.write(data)
    })
  }

  /** 使单个目标缓存失效，返回是否真的删掉了条目。 */
  async invalidate(targetUrl: string): Promise<boolean> {
    return this.enqueue(async () => {
      const data = await this.read()
      const key = normalizeKey(targetUrl)
      if (!(key in data.entries)) return false
      delete data.entries[key]
      await this.write(data)
      return true
    })
  }

  /** 列出全部缓存条目及其新鲜度。 */
  async list(): Promise<CacheEntrySummary[]> {
    const data = await this.read()
    return Object.values(data.entries)
      .map((entry) => ({
        targetUrl: entry.targetUrl,
        lastScanned: entry.lastScanned,
        scanStatus: entry.scanStatus,
        stale: this.isStale(entry.lastScanned),
        components: entry.techStack?.length ?? 0,
      }))
      .sort((a, b) => b.lastScanned.localeCompare(a.lastScanned))
  }

  /** 清空缓存，返回被清除的条目数。 */
  async clear(): Promise<number> {
    return this.enqueue(async () => {
      const data = await this.read()
      const count = Object.keys(data.entries).length
      await this.write({ version: CACHE_VERSION, entries: {} })
      return count
    })
  }

  /** 判断某个扫描时间是否超过 TTL。 */
  isStale(lastScanned: string): boolean {
    const scanned = Date.parse(lastScanned)
    if (Number.isNaN(scanned)) return true
    return Date.now() - scanned > this.ttlHours * 3600_000
  }

  private async read(): Promise<CacheFile> {
    try {
      const raw = await readFile(this.filePath, 'utf8')
      const parsed = JSON.parse(raw) as CacheFile
      if (!parsed || typeof parsed !== 'object' || typeof parsed.entries !== 'object' || parsed.entries === null) {
        return { version: CACHE_VERSION, entries: {} }
      }
      return { version: CACHE_VERSION, entries: parsed.entries }
    } catch {
      return { version: CACHE_VERSION, entries: {} }
    }
  }

  private async write(data: CacheFile): Promise<void> {
    await mkdir(dirname(this.filePath), { recursive: true })
    const tmp = `${this.filePath}.tmp`
    await writeFile(tmp, JSON.stringify(data, null, 2), 'utf8')
    await rename(tmp, this.filePath)
  }

  private enqueue<T>(task: () => Promise<T>): Promise<T> {
    const run = this.queue.then(task, task)
    this.queue = run.then(
      () => undefined,
      () => undefined,
    )
    return run
  }
}

/**
 * URL 归一化键：忽略末尾斜杠与查询串，避免同一目标重复侦察。
 * 裸域名（`portal.example.com`）按 https 补齐后再归一化，保证与已解析 URL 的键一致。
 */
export function normalizeKey(targetUrl: string): string {
  const attempt = (candidate: string): string | null => {
    try {
      const parsed = new URL(candidate)
      if (!parsed.hostname) return null
      parsed.hash = ''
      parsed.search = ''
      const path = parsed.pathname.replace(/\/+$/, '')
      return `${parsed.protocol}//${parsed.host}${path}`
    } catch {
      return null
    }
  }
  const raw = String(targetUrl ?? '').trim()
  return attempt(raw) ?? attempt(`https://${raw.replace(/^\/+/, '')}`) ?? raw
}

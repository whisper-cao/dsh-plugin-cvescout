/**
 * TLS / ALPN 探测。
 *
 * 只做一次裸 TLS 握手：不发送任何 HTTP 请求、不携带任何载荷，比一次 GET 还轻，
 * 属于最保守的一类被动探测。换来的是几个「只有握手阶段才看得到」的事实：
 *
 *  - **ALPN 协商结果** → 判定 HTTP/2 over TLS 是否可用。RFC 9113 §3.3 规定
 *    HTTP/2 over TLS 必须用 ALPN 的 `h2` 标识符协商，所以协商不出 `h2`
 *    就等于这个入口用不了 HTTP/2——这对一大批「仅 HTTP/2 可触发」的 CVE
 *    是决定性的排除依据。
 *  - 实际协商出的 TLS 版本与密码套件。
 *  - 对端证书的主题 / 签发者 / 有效期 / SAN / 公钥长度 / 指纹。
 *  - 证书链是否被本机信任（自签或内网 CA 会为 false，本身不是漏洞，只作事实记录）。
 *
 * 刻意不做的事：不枚举密码套件、不逐个试探旧版协议。前者会变成主动扫描，
 * 后者在 Node 自带的 OpenSSL 3 上因安全等级限制本就不可靠，给出「探测不了」
 * 的假阴性比不探测更糟。
 */
import tls from 'node:tls'

import type { TlsCertificateIntel, TlsIntel } from '../types.ts'

/** 向服务器提供的 ALPN 协议列表，顺序即偏好。 */
const ALPN_OFFER: readonly string[] = ['h2', 'http/1.1']

/** 握手超时的下限：太短的超时会把正常的慢握手误判成「不支持」。 */
const TIMEOUT_FLOOR_MS = 3000

export type TlsProbeOptions = {
  host: string
  /** 目标端口，https 默认 443。 */
  port: number
  /** SNI 主机名，留空则用 host。 */
  servername?: string
  timeoutMs: number
  signal?: AbortSignal
}

type HandshakeOutcome = {
  ok: boolean
  error: string | null
  protocol: string | null
  cipher: string | null
  /** ALPN 协商结果；服务器未选择任何协议时为 null。 */
  alpnProtocol: string | null
  alpnNegotiated: boolean
  certTrusted: boolean | null
  certificate: TlsCertificateIntel | null
}

/** 空结果，用于探测未执行或整体失败的场合。 */
export function emptyTlsIntel(error: string | null = null): TlsIntel {
  return {
    ok: false,
    error,
    protocol: null,
    cipher: null,
    alpnProtocol: null,
    alpnNegotiated: false,
    http2: false,
    http2Evidence: error ? `TLS 探测未完成（${error}）` : 'TLS 探测未执行',
    certificate: null,
    certTrusted: null,
    elapsedMs: 0,
  }
}

/**
 * 做一次裸 TLS 握手并读出手法与证书事实。
 *
 * 失败路径全部收敛成 `ok: false` + 可读的 `error`，不向上抛——单点探测失败
 * 不应该让整次指纹识别中断。
 */
export async function probeTls(options: TlsProbeOptions): Promise<TlsIntel> {
  const startedAt = Date.now()
  const outcome = await handshake(options)

  if (!outcome.ok) {
    return { ...emptyTlsIntel(outcome.error), elapsedMs: Date.now() - startedAt }
  }

  const alpnProtocol = outcome.alpnProtocol
  const http2 = alpnProtocol === 'h2'
  let http2Evidence: string
  if (http2) {
    http2Evidence = 'ALPN 协商为 h2，该入口提供 HTTP/2 over TLS'
  } else if (outcome.alpnNegotiated) {
    http2Evidence = `ALPN 协商为 ${alpnProtocol}，未提供 h2，该入口不支持 HTTP/2 over TLS`
  } else {
    http2Evidence = '服务器未在 ALPN 中选中任何协议，该入口不支持 HTTP/2 over TLS'
  }

  return {
    ok: true,
    error: null,
    protocol: outcome.protocol,
    cipher: outcome.cipher,
    alpnProtocol,
    alpnNegotiated: outcome.alpnNegotiated,
    http2,
    http2Evidence,
    certificate: outcome.certificate,
    certTrusted: outcome.certTrusted,
    elapsedMs: Date.now() - startedAt,
  }
}

function handshake(options: TlsProbeOptions): Promise<HandshakeOutcome> {
  return new Promise<HandshakeOutcome>((resolve) => {
    let settled = false
    let socket: tls.TLSSocket | null = null

    const finish = (outcome: HandshakeOutcome): void => {
      if (settled) return
      settled = true
      options.signal?.removeEventListener('abort', onAbort)
      resolve(outcome)
    }

    const fail = (message: string): HandshakeOutcome => ({
      ok: false,
      error: message,
      protocol: null,
      cipher: null,
      alpnProtocol: null,
      alpnNegotiated: false,
      certTrusted: null,
      certificate: null,
    })

    const onAbort = (): void => {
      socket?.destroy()
      finish(fail('调用方已取消'))
    }

    try {
      const host = options.host
      socket = tls.connect({
        host,
        port: options.port,
        // SNI 不允许填 IP 字面量（RFC 6066），本地/内网直连 IP 时留空。
        servername: resolveServername(options.servername ?? host),
        ALPNProtocols: [...ALPN_OFFER],
        // 只读事实，不做信任判定：自签/内网证书不应导致探测失败。
        rejectUnauthorized: false,
        timeout: Math.max(TIMEOUT_FLOOR_MS, options.timeoutMs),
      })
    } catch (error) {
      finish(fail(`握手初始化失败: ${(error as Error).message}`))
      return
    }

    if (options.signal) {
      if (options.signal.aborted) {
        onAbort()
        return
      }
      options.signal.addEventListener('abort', onAbort, { once: true })
    }

    socket.once('secureConnect', () => {
      try {
        const current = socket
        const cipher = current?.getCipher()
        const peer = current?.getPeerCertificate() as (tls.PeerCertificate & { bits?: number }) | undefined
        const alpn = typeof current?.alpnProtocol === 'string' ? current.alpnProtocol : null
        finish({
          ok: true,
          error: null,
          protocol: current?.getProtocol() ?? null,
          cipher: cipher?.name ?? null,
          alpnProtocol: alpn,
          alpnNegotiated: alpn !== null,
          certTrusted: typeof current?.authorized === 'boolean' ? current.authorized : null,
          certificate: peer && Object.keys(peer).length > 0 ? toCertificateIntel(peer) : null,
        })
      } catch (error) {
        finish(fail(`读取握手结果失败: ${(error as Error).message}`))
      } finally {
        socket?.end()
      }
    })

    socket.once('error', (error: Error) => {
      finish(fail(error.message))
      socket?.destroy()
    })

    socket.once('timeout', () => {
      finish(fail('握手超时'))
      socket?.destroy()
    })
  })
}

function toCertificateIntel(peer: tls.PeerCertificate & { bits?: number }): TlsCertificateIntel {
  const validTo = peer.valid_to ?? null
  return {
    subject: describeName(peer.subject),
    issuer: describeName(peer.issuer),
    validFrom: peer.valid_from ?? null,
    validTo,
    daysUntilExpiry: validTo ? daysUntil(validTo) : null,
    altNames: parseAltNames(peer.subjectaltname),
    keyBits: typeof peer.bits === 'number' && peer.bits > 0 ? peer.bits : null,
    serialNumber: peer.serialNumber ?? null,
    fingerprint256: peer.fingerprint256 ?? null,
  }
}

function describeName(name: unknown): string | null {
  if (!name || typeof name !== 'object') return null
  const record = name as Record<string, unknown>
  const preferred = ['CN', 'O', 'OU']
  for (const key of preferred) {
    const value = record[key]
    if (typeof value === 'string' && value.trim()) return value.trim()
  }
  const first = Object.values(record).find((value) => typeof value === 'string' && value.trim())
  return typeof first === 'string' ? first.trim() : null
}

function parseAltNames(raw: unknown): string[] {
  if (typeof raw !== 'string' || !raw.trim()) return []
  return raw
    .split(',')
    .map((item) => item.replace(/^\s*(DNS|IP Address|IP|email|URI):/i, '').trim())
    .filter((item) => item.length > 0)
}

/** 把 Node 返回的 `Sep 10 08:40:59 2026 GMT` 形式转成剩余天数。 */
function daysUntil(dateText: string): number | null {
  const parsed = Date.parse(dateText)
  if (Number.isNaN(parsed)) return null
  return Math.floor((parsed - Date.now()) / 86_400_000)
}

/** SNI 必须是一个主机名；IP 字面量按 RFC 6066 不能放进 SNI 扩展，此时留空。 */
function resolveServername(value: string): string | undefined {
  const trimmed = value.trim()
  if (!trimmed) return undefined
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed)) return undefined
  if (trimmed.includes(':')) return undefined // IPv6 字面量
  if (/^\[.*\]$/.test(trimmed)) return undefined
  return trimmed
}

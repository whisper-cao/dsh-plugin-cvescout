/**
 * 测试用自签证书。
 *
 * 在测试运行时用 openssl 现场生成到 `test/fixtures/.certs/`（已被 .gitignore 忽略），
 * 而不是把证书和私钥提交进仓库：自签证书本身没有保密价值，但把 private key 放在
 * 公开仓库里会触发各类密钥扫描告警，也会给读者错误的示范。
 *
 * 若所在环境没有 openssl，返回 null，调用方应跳过依赖 TLS 的断言
 * （而不是伪造成通过）。
 */
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const outDir = join(here, '.certs')
const keyPath = join(outDir, 'key.pem')
const certPath = join(outDir, 'cert.pem')

/**
 * 确保存在一份可用的自签证书。
 * @returns {{ key: Buffer, cert: Buffer } | null} 无 openssl 时返回 null。
 */
export function ensureTestCertificate() {
  try {
    if (existsSync(keyPath) && existsSync(certPath)) {
      return { key: readFileSync(keyPath), cert: readFileSync(certPath) }
    }
    mkdirSync(outDir, { recursive: true })
    execFileSync(
      'openssl',
      [
        'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', keyPath,
        '-out', certPath,
        '-days', '3650',
        '-subj', '/CN=localhost',
        '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
      ],
      { stdio: 'ignore' },
    )
    return { key: readFileSync(keyPath), cert: readFileSync(certPath) }
  } catch {
    return null
  }
}

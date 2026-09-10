# dsh-plugin-cvescout

把 **CVE 影响面复测**做成便捷快速排查插件。加载后，用户直接说
「example.com 涉及 CVE-XXXX-XXXXX，帮我排查一下」，模型就会自动完成
目标侦察 → CVE 情报获取 → 版本区间判读 → 被动取证 → 给出带证据和限制说明的结论。

**特性**

- **11 个原生工具**：7 个原子能力 + 4 个编排能力，schema 自动进入提示词组装
- **常驻系统提示词指引**：不靠模型「恰好想起来」，把触发话术、调用顺序、汇报要求写进提示词
- **目标表达宽容**：完整 URL / 裸域名 / `host:port` / 配置里的系统别名都能接
- **协议能力探测**：一次裸 TLS 握手判定 HTTP/2 是否可用（ALPN），并采集 TLS 版本、密码套件、证书事实
- **协议前置条件排除**：对「必须启用 HTTP/2 才能触发」的 CVE（如 CVE-2023-44487），实测不支持即直接排除——
  这类结论不依赖版本号是否可见，目标隐藏 `Server` 版本时同样成立
- **探测并行化**：根请求之后的各组探测并发执行，实测 300 ms 延迟下耗时从 ~1.5 s 降到 ~0.6 s
- **安全内建**：授权域名白名单、速率与总量双限、载荷黑名单、全量审计（参数脱敏）
- **只做被动探测与非破坏性复现**：不投递攻击载荷、不写入目标数据
- **一条命令安装**：`dsh plugin --profile web add dsh-plugin-cvescout`，包内自带构建产物，
  安装时不执行任何构建脚本，因此不需要授予 `allowBuilds` 权限
- **零原生依赖**：只需 `fetch`、`node:tls` 与文件系统；情报缓存用 JSON + 原子写
- **结论保守**：不做主动利用，就不宣称漏洞存在

## 1. 设计取舍

**安全约束内建，不靠提示词。** 提示词是概率性的，护栏必须是确定性的。所有对外请求都要过
`core/safety.ts`：白名单、速率、总量、载荷黑名单逐层校验，任一层拒绝都抛 `SafetyBlockedError`
向上冒泡——不允许被 `try/catch` 降级成「目标不可达」这类软失败蒙混过关。

**结论保守优于结论好看。** 因为不投递攻击载荷，插件没有能力证明「漏洞可利用」。
所以 `VULNERABLE` 只在拿到非破坏性复现的正向证据时给出，其余情况一律 `UNCERTAIN`，
并在 `limitations[]` 里说清还差什么。

**零原生依赖。** 情报缓存用单文件 JSON + 原子写 + TTL + 写入串行化，而不是 SQLite：
规模远小于依赖清单级数据，且可直接人工查看与归档。

---

## 2. 目录结构

```
dsh-plugin-cvescout/
├── package.json            组合包元数据（dsh.bundle.patch / main: lib/index.js）
├── cordis.patch.yml        **发布用** patch 层：按包名引用，随组合包一起分发
├── cordis.dev.patch.yml    开发用 patch 层：按源码绝对路径引用，跳过构建
├── tsconfig.json           tsc --noEmit 类型校验
├── tsconfig.build.json     tsc 构建配置（src/*.ts → lib/*.js，固定 LF 行尾）
├── LICENSE / .gitignore / .gitattributes
├── .github/workflows/ci.yml  CI：类型检查 + lib 同步校验 + 测试 + 打包检查
├── lib/                    **构建产物，随仓库提交**（安装后真正被加载的代码）
├── src/
│   ├── index.ts            插件入口：name / inject / Config / apply
│   ├── config.ts           Config 接口 + Schemastery schema + 防御性默认值
│   ├── prompt.ts           系统提示词指引段（把「什么话术该走本插件」教给模型）
│   ├── types.ts            领域模型
│   ├── core/
│   │   ├── runtime.ts      运行期依赖集合（cfg / safety / cache / judge）+ 目标解析
│   │   ├── errors.ts       传输层错误类型（打断 http↔url 循环依赖）
│   │   ├── url.ts          目标地址解析（裸域名 / 别名 / 中文标点 / 协议回退）
│   │   ├── tls.ts          TLS / ALPN 探测（HTTP-2 判定、协议版本、证书事实）
│   │   ├── http.ts         受控 HTTP 客户端（方法白名单、超时、取消、截断、协议回退）
│   │   ├── safety.ts       安全护栏 + 审计（速率/总量/白名单/载荷黑名单）
│   │   ├── cache.ts        情报缓存（JSON 文件 + 原子写 + TTL）
│   │   ├── judge.ts        情报判读 + 版本比较 + 组件名匹配 + 协议前置条件
│   │   ├── retest.ts       复测流水线（单条 / 批量 / 报告渲染）
│   │   └── pentest.ts      复现文档解析 + 载荷安全化 + 非破坏性执行
│   ├── sources/
│   │   ├── nvd.ts          NVD API 2.0 + GitHub Advisory，归一化受影响范围
│   │   ├── poc.ts          GitHub 仓库搜索 + ExploitDB 检索页
│   │   └── fingerprint.ts  技术栈指纹规则与采集
│   └── tools/
│       ├── index.ts        工具注册入口 + TOOL_NAMES
│       ├── atomic.ts       7 个原子工具（含 target_scope）
│       ├── pipeline.ts     4 个编排工具
│       └── json.ts         canonical JSON 值边界转换
└── test/                   测试对象是 lib/（构建产物），纯 Node 直跑
    ├── fixtures/           运行时生成自签证书（.certs/ 已忽略，私钥不入库）
    ├── smoke.mjs           纯逻辑（护栏/URL/版本/缓存/解析/载荷/指引/协议判读），不联网
    ├── register.mjs        入口 apply()、schema 编译与指引段注册，不联网
    └── e2e-local.mjs       本地 HTTP + HTTPS(ALPN) 服务上的端到端测试，不触碰外部站点
```

> `src/` 是 TypeScript 源码，`lib/` 是 `tsc` 产物（`import './x.ts'` 会被改写成
> `import './x.js'`）。**`lib/` 会提交进仓库**，这样从 git 安装的用户不需要任何构建步骤、
> 也不需要为依赖授予 `prepare` 执行权限——安装即用。

---

## 3. 安装

**前置条件**

- Node.js `^22.19.0 || >=24.0.0`（与 Harness 自身要求一致）
- 已安装 DeepSeek Harness（`dsh` 命令可用）
- `dsh plugin` 会把参数转发给 profile 目录里的 pnpm，所以需要 pnpm

### 方式 A：从 npm 安装（使用者推荐）

```bash
dsh plugin --profile web add dsh-plugin-cvescout
```

包内已带构建产物 `lib/`，安装时**不会**执行任何 `prepare`/`build` 脚本，
所以不需要为依赖授予 pnpm 的 `allowBuilds` 执行权限。

### 方式 B：从 GitHub 安装（想跟 main 或未发版时）

```bash
dsh plugin --profile web add github:whisper-cao/dsh-plugin-cvescout
```

锁定版本或 commit，避免后续推送悄悄改变实际运行的内容：

```bash
dsh plugin --profile web add github:whisper-cao/dsh-plugin-cvescout#v0.1.0
dsh plugin --profile web add github:whisper-cao/dsh-plugin-cvescout#<40 位 commit sha>
```

### 卸载

```bash
dsh plugin --profile web remove dsh-plugin-cvescout
```

`package.json` 里的 `dsh.bundle.patch` 会被自动采纳，无需手写 insert 段。
装好后用 `dsh --profile web --dump-config` 应该能看到 `# == dsh-plugin-cvescout` 这一层。

因为仓库里已经带有 `lib/` 构建产物，两种安装方式都**不需要** `prepare`/`build` 权限，
不会触发 pnpm 的 `allowBuilds` 授权提示。

### 装完必须做的一步：改授权目标

组合包里 `cordis.patch.yml` 的 `allowedDomains` 是**示例占位值**（`example.com`），
而 bundle 的 patch 层安装后会立即生效——所以刚装好时插件会把你的真实站点全部当作
「未授权」拒掉（报错信息里会带上当前白名单并说明怎么改）。

按层顺序，**profile 自己的 `cordis.patch.yml` 在所有 bundle 层之后应用**，用它覆盖即可：

```bash
$EDITOR "${DSH_HOME:-$HOME/.dsh}/profiles/web/cordis.patch.yml"
```

```yaml
- insert:
    - id: cvescout
      name: dsh-plugin-cvescout
      config:
        allowedDomains:
          - 你的域名            # 填父域即可覆盖子域
        targetAliases:
          系统简称: 你的域名
```

注意 patch 是**整行替换 `config`、不做深合并**，所以要用到的键都得重述（没写的键回到 schema 默认值）。
改完用 `dsh --profile web --dump-config` 确认生效。

### 装完必须重启

`dsh plugin add` 只把 bundle 写进 profile；运行中的进程只有在 HMR 启用时才会热加载。
默认部署里 `hmr` 是关闭的，所以在 `plugin_status` 里会看到本插件是 `[enabled]` 但**没有
`active` 标记**——这不是加载失败，重启 dsh 即可，随后启动日志会出现：

```
[cvescout] 已注册 11 个工具 + 1 段系统提示词指引；授权域名 …；限速 30/min、总量 200；情报缓存 …
```

---

## 4. 使用：自然语言 → 自动调用

加载后不需要记工具名，直接说人话即可：

```
portal.example.com 涉及 CVE-2021-44228，帮我排查一下
内部管理系统有没有 CVE-2022-25845 和 CVE-2020-36518
example.com 这个站点用的什么组件
上次扫描的结果还在吗，清一下缓存
```

「自动调起来」靠三件事配合，不是靠祈祷模型想起来：

1. **系统提示词指引段**（`src/prompt.ts`，注册为 `plugin:cvescout:guidance` @ order 120）
   把「用户提到站点 + CVE 要求排查时必须调本插件、按什么顺序调、汇报要包含什么」写进系统提示词，
   并动态带出**当前授权域名与别名表**（模型看不到插件配置）。这是最可靠的自动路由机制。
2. **工具描述里的触发话术**：`cve_retest` 的描述明确写了「当用户说『某网站涉及某 CVE，帮我排查』
   时优先用本工具」，并标注了边界（问具体 URL 可达性该用 `http_probe`）。
3. **`target_scope` 工具**：用户只说系统名（「内部管理系统」）时，模型先调它用 `targetAliases`
   把名字解析成域名，并确认该目标是否在授权范围内。

模型能接受的目标写法很宽松——完整 URL、裸域名、`host:port`、别名都可以，
解析规则见 `src/core/url.ts`：抠出句子里的 URL → 剥掉中文标点 → 查别名表 → 补默认协议 →
若连接/TLS 失败自动换一次协议重试（内网站点常有只开 http 的情况）。

---

## 5. 配置参考

全部字段都有默认值，可只在 `cordis.yml` 里覆写需要改的项。


| 字段                      | 默认                                           | 说明                                                                                                                                                                                                                                                                  |
| ------------------------- | ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `allowedDomains`          | `[]`                                           | **授权目标域名白名单，填你已获授权测试的站点。** 空数组＝不限制（不建议，插件会在启动日志与 `target_scope` 里告警）。匹配规则：主机名精确匹配或后缀匹配子域——填 `example.com` 即可覆盖 `portal.example.com`、`erp.example.com`；`example.com.attacker.com` 不会命中 |
| `targetAliases`           | `{}`                                           | 系统别名表：用户口中的名字 → 域名。如`内部管理系统: erp.example.com`。`target_scope` 会读它把名字解析成目标                                                                                                                                                          |
| `defaultScheme`           | `https`                                        | 用户只给域名时补的协议                                                                                                                                                                                                                                                |
| `allowSchemeFallback`     | `true`                                         | 首次请求在连接/TLS 层失败时自动换协议重试一次（仅被动方法）                                                                                                                                                                                                           |
| `maxRequestsPerMinute`    | `30`                                           | 60 秒滑动窗口内的最大请求数                                                                                                                                                                                                                                           |
| `maxTotalRequests`        | `200`                                          | 单次插件生命周期内的最大请求数                                                                                                                                                                                                                                        |
| `timeoutMs`               | `10000`                                        | 单次 HTTP 请求超时                                                                                                                                                                                                                                                    |
| `maxResponseBytes`        | `20000`                                        | 回给模型的响应体预览上限；内部解析结构化 API 时使用独立的高上限                                                                                                                                                                                                       |
| `userAgent`               | `CVEScout-DSH/0.1 (…)`                        | 探测请求 UA                                                                                                                                                                                                                                                           |
| `cachePath`               | `''`                                           | 情报缓存文件；空值 →`~/.cvescout/intel-cache.json`                                                                                                                                                                                                                   |
| `cacheTtlHours`           | `24`                                           | 情报有效期                                                                                                                                                                                                                                                            |
| `nvdApiKey`               | `''`                                           | 可选。带 Key 后 NVD 限额从 5 次/30 秒 → 50 次/30 秒                                                                                                                                                                                                                  |
| `githubToken`             | `''`                                           | 可选。留空回退到环境变量`GITHUB_TOKEN`                                                                                                                                                                                                                                |
| `allowNonIdempotentProbe` | `false`                                        | **红线开关**。开启后放行 POST/PUT/PATCH/DELETE 探测                                                                                                                                                                                                                   |
| `blockedPayloadPatterns`  | 12 条正则                                      | 载荷黑名单，命中即拦截                                                                                                                                                                                                                                                |
| `reportDir`               | `''`                                           | 批量报告输出目录；空值 →`~/.cvescout/reports`                                                                                                                                                                                                                        |
| `probeAllowedMethods`     | `true`                                         | 指纹阶段是否发 OPTIONS 读`Allow` 头                                                                                                                                                                                                                                   |
| `errorPageProbe`          | `true`                                         | 是否用随机路径采一次 404 错误页特征                                                                                                                                                                                                                                   |
| `passiveProbePaths`       | `['/robots.txt', '/.well-known/security.txt']` | 额外被动路径（只读 200 响应）                                                                                                                                                                                                                                         |
| `tlsProbe`                | `true`                                         | 是否做一次裸 TLS 握手判定 HTTP/2 可用性并采集协议/证书事实。**关掉会让「仅 HTTP/2 可触发」类 CVE 失去排除依据**                                                                                                      |
| `probeConcurrency`        | `6`                                            | 并行探测并发上限（1..32）。设为 `1` 即退回串行；内网站点或前置 WAF 的站点建议调小                                                                                                                      |

---

## 6. 工具目录

### 原子工具


| 工具             | 关键参数                                         | 作用                                                                                                                                                                |
| ---------------- | ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `target_scope`   | `alias`（可选）                                  | 读授权范围与配置状态：白名单、别名映射、默认协议、配额、缓存/报告路径；传`alias` 可把系统名解析成域名并判定是否已授权。**用户只说系统名，或目标被判定越权时先调它** |
| `cve_lookup`     | `cve_id`                                         | NVD 2.0 → GitHub Advisory 回退；返回描述、CVSS、受影响组件与版本区间（应用类 CPE 排在 OS/硬件类之前）、参考链接                                                    |
| `cve_poc_search` | `cve_id`, `max_results`                          | GitHub 仓库搜索（按 star 排序）+ ExploitDB 检索页弱信号                                                                                                             |
| `http_probe`     | `url`, `method`, `headers`, `body`, `timeout_ms` | 受护栏约束的单次探测。非幂等方法默认被拒                                                                                                                            |
| `fingerprint`    | `url`, `write_cache`                             | 服务器/框架/CMS/前端库/WAF/前置代理指纹 +`Allow` 方法 + 错误页特征 + robots/security.txt + **TLS 版本、ALPN(HTTP-2)、证书事实**                                                                            |
| `intel_cache`    | `action`, `url`, `limit`                         | `get` / `list` / `invalidate` / `clear`                                                                                                                             |
| `safety_audit`   | `limit`                                          | 调用总数、拦截次数与原因、配额用量、审计流水（敏感字段已脱敏）                                                                                                      |

### 编排工具


| 工具               | 关键参数                                                                       | 作用                                                                                                                                 |
| ------------------ | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| `cve_retest`       | `url`, `cve_id`, `force_recon`, `run_pentest`, `repro_document(_path)`         | **主入口**。单 CVE 复测全流程，返回判定 + 置信度 + 依据 + 证据 + 限制。`cve_id` 可给多个（逗号/空格/顿号分隔），会自动委托给批量路径 |
| `cve_batch_retest` | `url`, `cve_ids`, `force_recon`, `save_report`, `report_dir`, `repro_document` | 同目标多 CVE 批量复测，复用一次侦察，产出 Markdown 汇总报告                                                                          |
| `cve_repro_parse`  | `document`, `cve_id`, `format`                                                 | 解析复现文档，标出破坏性步骤；**不发任何请求**                                                                                       |
| `pentest_repro`    | `url`, `cve_id`, `document(_path)`, `dry_run`                                  | 执行非破坏性复现步骤。`dry_run=true` 时只输出载荷安全化预览                                                                          |

输出约定：`output.schema` 统一为 `{ type: 'json' }`，`render` 给出一句人读结论 + 完整规范化 JSON。
在 Code/PTC 模式下可直接 `await tools.cve_retest({ ... })` 拿到结构化值做程序化处理。

---

## 7. 安全模型

**分层拦截（顺序固定）**

1. 破坏性工具名单（`write_file` / `exec_command` / …）——纵深防御
2. 载荷黑名单正则——命中即拒，且**不消耗配额**
3. 授权域名白名单——按主机名精确/后缀匹配
4. 速率限制（60 s 滑动窗口）
5. 总量上限

任一层拒绝都会落审计（参数先脱敏，`authorization` / `token` / `cookie` 之类替换为 `***REDACTED***`）。

**幂等默认**：只有 `GET` / `HEAD` / `OPTIONS` 通过；`TRACE` / `CONNECT` 永远禁止；
`POST` / `PUT` / `PATCH` / `DELETE` 需要显式打开 `allowNonIdempotentProbe`。

**协议探测同样受管**：TLS 握手虽然不属于 HTTP 方法，但同样是对外触达目标，因此也要先过护栏
（并计入速率与总量配额）。它只在**目标自身是 https** 时执行——不会出现「http 目标去连 443」
这种与用户意图不符的连接；此时协议能力记为 `unknown` 而非「不支持」。

**不做的事**

- 不投递攻击载荷、不做真实内容写入、不尝试提权或横向移动；
- 不枚举密码套件、不逐个试探旧版 TLS 协议——那会退化成主动扫描；而且 Node 自带的 OpenSSL
  安全等级本就禁止协商 TLS 1.0/1.1，强行做只会得到假阴性，比不做更糟；
- 复现文档里判为破坏性的步骤（Delete/Drop/Update/Insert/删除/清空… 或 `DELETE` 方法）一律跳过；
- 需要落地的载荷先过 `sanitizePayload()` 做无害化替换，无法安全化的步骤直接放弃；
- 报告里的 `set-cookie` 只记 **Cookie 名**，不记值。

**几个刻意的实现决定**

- **域名匹配不用子串包含**：`domain in url` 这种写法会让 `example.com.attacker.com` 命中白名单。
  这里解析 URL 主机名后做精确/后缀匹配（`test/smoke.mjs` 有回归用例）。
- **拒绝即硬失败**：越权抛 `SafetyBlockedError` 并向上冒泡，不允许被降级成「目标不可达」这类软失败。
- **拦截信息是给模型的可执行指引**：会带上当前白名单，并说明需要把域名加入 `allowedDomains`——
  这样模型在汇报时会如实告诉用户去补配置，而不是含糊地说「扫不了」。
- **白名单校验接受裸域名**（`portal.example.com`、`host:port`）：模型可能把用户原话直接传进来，
  归一化在护栏之前完成，避免合法目标因解析失败被误判越权。

---

## 8. 判定语义


| 判定             | 含义                     | 触发条件                                                                 |
| ---------------- | ------------------------ | ------------------------------------------------------------------------ |
| `NOT_VULNERABLE` | 有明确证据可排除         | ① 目标组件版本明确落在受影响区间之外（依据 `version`，置信度 0.95）<br>② 目标不满足该 CVE 的协议前置条件，例如实测不支持 HTTP/2（依据 `protocol`，置信度 0.9） |
| `VULNERABLE`     | 有非破坏性复现的正向证据 | 仅当提供复现文档且步骤命中成功指标时给出（置信度 0.9）                   |
| `UNCERTAIN`      | 需人工核查               | 版本命中区间但未实证、组件未识别、情报不可用、协议能力未知等             |

判定结果的 `judgment.exclusionBasis` 会写明排除依据是 `version` 还是 `protocol`，报告里的
`limitations[]` 也会相应区分措辞。

**协议前置条件为什么值得单独做一层**：像 CVE-2023-44487（HTTP/2 Rapid Reset）这类漏洞，
触发面完全落在 HTTP/2 帧层。实测目标不提供 HTTP/2 over TLS 时，即使 `Server` 头隐藏了版本号
（`Server: nginx` 没有版本），也能给出确定性排除——版本比对在这种情况下是无解的。
反之，**探测失败或情报来自旧缓存时会返回 `unknown` 而不是 `violated`**，绝不把「不知道」
当成「不支持」。

给出 `UNCERTAIN` 时，结果里的 `limitations[]` 会说明**还差什么**（无公开 PoC / 指纹覆盖不足 /
WAF 可能干扰 / 情报来自缓存 / 协议能力未能确认 / 未做主动利用）。这是刻意的：插件不主动利用，
就不宣称漏洞存在。

---

## 9. 开发与测试

```bash
npm run build         # tsc -p tsconfig.build.json → lib/（改完 src/ 必须跑，否则测试测的是旧产物）
npm run typecheck     # tsc --noEmit，对真实 @deepseek-ai/dsh-tools 类型校验
npm test              # 自动先 build，再跑纯逻辑（44 项断言）+ 入口 apply() 冒烟，不联网
npm run test:e2e      # 起本地 HTTP + HTTPS(ALPN) 服务跑完整流水线，目标固定 127.0.0.1
npm run check:dist    # 校验 lib/ 与 src/ 同步——提交前跑，CI 也会跑
```

`test:e2e` 覆盖三条用户入口（完整 URL / 裸 `host:port` / 系统别名 + 多 CVE），
并额外用两个自签 HTTPS 靶机（ALPN 分别为 `h2` 与 `http/1.1`）验证：

- TLS 握手确实能区分「支持 HTTP/2」与「只支持 HTTP/1.1」；
- 同一个 CVE-2023-44487、两个靶机的 nginx 版本都落在受影响区间内，
  唯一的差别是 HTTP/2 是否可用——只有这一个变量时，判读结果分别是 `no（protocol）` 与 `yes`。

测试用的自签证书在运行时由 `openssl` 现场生成到 `test/fixtures/.certs/`（已忽略），
**私钥不进仓库**；若环境没有 `openssl`，依赖 TLS 的断言会被明确跳过，而不是伪造成通过。

`test:e2e` 还会真实访问 NVD（只读公开接口）以覆盖 CVE 情报链路；GitHub 若因网络/TLS 不可达，
会以 `error` 路径收敛并在报告里如实标注原因，测试仍然断言结构完整。

若所在环境的 npm 无法正常派生脚本进程（例如 PATH 只有 POSIX 形式），直接调用等价命令：

```bash
node test/smoke.mjs && node test/register.mjs
node test/e2e-local.mjs
npx tsc --noEmit

# check:dist 的等价写法：先构建，再看 lib/ 有无 diff
npx tsc -p tsconfig.build.json && git diff --exit-code -- lib
```

> 个别 Windows + Git Bash 环境下 `npm run <script>` 会返回非零退出码而实际命令已成功执行
> （脚本输出里看不到任何错误）。判断是否真的失败，以上面这类直接调用为准。

### 维护者：发版流程

```bash
npm run check:dist          # 确认 lib/ 与 src/ 同步
npm version patch           # 升版本 + 打标签
npm publish                 # prepublishOnly 会再跑一遍 typecheck + 测试兜底
git push --follow-tags
```

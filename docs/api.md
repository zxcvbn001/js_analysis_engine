# API 对接文档

本文档描述 JavaScript Analysis Engine 暴露给 Burp Suite 扩展或其他客户端调用的 HTTP API。

## 基础地址

```text
http://127.0.0.1:3000
```

生产环境请以 `config/config.json` 或 `CONFIG_FILE` 指向的配置文件为准，使用其中配置的 host 和 port。

## 鉴权

API Key 鉴权是可选能力，由配置控制：

```json
{
  "auth": {
    "enabled": true,
    "headerName": "x-api-key",
    "apiKeys": ["your-production-api-key"]
  }
}
```

启用后，分析相关接口都需要携带配置中的 Header：

```http
x-api-key: your-production-api-key
```

`GET /health` 始终不需要鉴权，方便健康检查。

启用鉴权后，以下接口需要 API Key：

```text
POST /analyze/js
GET  /analyze/tasks/:id
POST /analyze/secret
```

## 通用错误格式

```json
{
  "success": false,
  "error": {
    "message": "Missing or invalid API key"
  }
}
```

常见 HTTP 状态码：

```text
200 分析完成或请求成功
202 异步任务已提交
400 请求体不合法
401 API Key 缺失或错误
404 任务不存在
502 下载 JavaScript 失败
500 服务端错误
```

请求参数校验失败时返回 HTTP `400`，`message` 字段由 zod 生成，可能包含 JSON 格式的校验详情。

如果 `/analyze/js` 只传了 `url`，但引擎无法下载 JavaScript，响应可能类似：

```json
{
  "success": false,
  "error": {
    "message": "Failed to download JS from https://target.example/app.js: fetch failed. Check network, DNS, TLS certificate, proxy, or target availability."
  }
}
```

这表示引擎没有收到 `content`，只能尝试从 `url` 下载脚本，但下载失败。Burp 已经拿到 JS 响应体时，推荐直接传 `content`，避免二次下载。

## GET /health

健康检查接口。

### 响应

```json
{
  "success": true
}
```

### 示例

```bash
curl http://127.0.0.1:3000/health
```

## POST /analyze/js

分析 JavaScript 内容，恢复 API、参数、认证信号、Secret 候选、风险提示和静态资源。

当 webpack/vite chunk 文件可以被安全枚举时，响应中也会包含 `assets`。

主分析链路基于 AST：引擎先用 Babel parser 构建 AST，再做字符串传播、发包调用图、API 提取、参数提取、Secret 候选和风险分类。正则只用于 AST 节点值、变量名、属性名和调用名上的分类匹配，不作为 API 提取主逻辑。

API 恢复以“发包调用图”为主：引擎会先识别 `fetch`、`axios`、`axios.create()` 实例、jQuery Ajax、XHR，以及转发到这些客户端的包装函数，再从真实发包调用中提取 `url/method/headers/data/params`。普通字符串只作为低置信度兜底，不应和真实发包点混为一类。

### 支持的 JavaScript 来源

分析器以 AST 为主，面向老项目和现代前端项目：

```text
老项目：
- jQuery $.ajax / $.get / $.post
- XMLHttpRequest open / setRequestHeader
- RequireJS / AMD 模块包装

现代前端：
- React JSX
- Vue 单文件组件 script
- Next.js 页面/模块代码
- Vite import.meta 语法
- TypeScript 语法
- axios/fetch/request wrapper 风格调用
- request factory 调用，例如 r()({ url, method, data })
```

### 请求头

```http
Content-Type: application/json
x-api-key: your-production-api-key
```

`x-api-key` 只有在 `auth.enabled=true` 时才需要。

### 请求体

```json
{
  "url": "https://target.example/static/app.js",
  "content": "const API='/api'; fetch(API + '/user')",
  "fast_mode": true,
  "mode": "fast",
  "async": false
}
```

字段说明：

```text
url       可选。Burp 看到的原始 JS URL；当 content 为空时用于下载 JS。
content   可选。JavaScript 源码或打包后的 bundle 内容。
fast_mode 可选。true 表示只做 AST/规则分析，不进入 LLM 队列，推荐 Burp 被动扫描流程使用。
mode      可选。"fast" 或 "full"。不传时默认 "full"；"full" 会启用 Secret 候选的 LLM 增强队列。
async     可选。true 表示立即返回任务 id，后台异步分析。
```

`content` 和 `url` 至少传一个。两者都存在时，优先分析 `content`。如果 `content` 缺失或为空，引擎会从 `url` 下载 JavaScript 后分析。

优先级明确如下：

```text
1. content 非空：直接分析 content，不会再下载 url。
2. content 缺失、为空字符串或只有空白字符：使用 url 下载 JavaScript 后分析。
3. content 和 url 都缺失或都为空：返回 400。
```

因此，`url` 在 `content` 非空时只作为上下文信息使用，例如用于恢复相对路径、判断脚本来源 host、辅助生成 `resolvedUrl`。

模式优先级：

```text
1. fast_mode=true：强制 fast，只做 AST/规则分析，不调用 LLM。
2. mode="fast"：只做 AST/规则分析，不调用 LLM。
3. mode 缺失或 mode="full"：默认 full，规则结果先返回，Secret 候选进入 LLM 队列二次分析。
```

LLM 队列默认限速为 `60/min`，即每秒最多启动 1 个 LLM 分析任务。LLM 只接收 Secret 候选的小上下文，不会发送整份 JavaScript bundle。

为避免大 bundle 或大量请求导致内存堆积，服务端会限制单次分析的发现项数量和证据长度，并限制 LLM 等待队列长度。Burp 被动扫描或批量扫描建议始终传 `fast_mode:true`；`full` 更适合用户主动触发的单文件深度分析。

敏感凭据类结果的返回规则：

```text
fast 模式：返回规则识别出的 Secret 候选，source 通常为 regex。
full 模式且 LLM 已正确配置：Secret 候选会同步交给 LLM 复核，只返回 LLM 确认为真实泄露的结果；LLM 明确为误报的候选会直接丢弃。
full 模式但 LLM 未配置：退回规则结果，不中断主分析。
```

LLM 复核会按 10 个 Secret 候选一组批量提交，响应的 `meta.analysis.llm` 会返回批次数和复核统计：

```json
{
  "meta": {
    "analysis": {
      "llm": {
        "enabled": true,
        "candidateCount": 23,
        "reviewedCount": 23,
        "confirmedCount": 2,
        "rejectedCount": 21,
        "batchCount": 3,
        "batchSize": 10
      }
    }
  }
}
```

当使用 `url` 下载时，`url` 必须是合法的绝对 URL。下载行为由配置控制：

```json
{
  "fetch": {
    "timeoutMs": 10000,
    "maxBytes": 10485760
  }
}
```

如果 `async=true`，接口返回 HTTP `202 Accepted`：

```json
{
  "success": true,
  "task_id": "c65125b2-0f3c-4099-9740-0dbb6d1b5870",
  "status": "queued",
  "status_url": "/analyze/tasks/c65125b2-0f3c-4099-9740-0dbb6d1b5870"
}
```

### Burp 调用建议

Burp 默认建议传：

```json
{
  "url": "https://target.example/app.js",
  "content": "...",
  "fast_mode": true
}
```

如果 Burp 已经拿到 JavaScript 响应体，请直接传 `content`。这样速度最快，也能避免目标站点网络、TLS、代理、DNS 等因素导致二次下载失败。

如果只有脚本 URL，没有响应体，可以只传 `url`，由引擎下载。

Burp 同时传 `url` 和 `content` 时，以 `content` 为准；`url` 不会触发二次下载，只用于上下文解析。

被动扫描建议 `fast_mode:true`。如果不传 `fast_mode` 且不传 `mode`，接口默认按 `full` 处理，Secret 候选会进入 LLM 队列。

### 成功响应

```json
{
  "success": true,
  "url": "https://target.example/static/app.js",
  "apis": [
    {
      "url": "/api/user",
      "resolvedUrl": "https://target.example/api/user",
      "baseUrl": "https://target.example",
      "method": "POST",
      "params": ["uid", "role"],
      "headers": ["Authorization"],
      "auth": "Authorization",
      "source": "axios.post",
      "confidence": "high",
      "notes": ["resolved-from-static-base-url"]
    }
  ],
  "assets": [
    {
      "url": "assets/js/chunk-01d475cb.4ef8f8dc.js",
      "type": "script",
      "chunkName": "chunk-01d475cb",
      "source": "webpack-runtime-return"
    }
  ],
  "params": [
    {
      "name": "uid",
      "location": "body",
      "api": "/api/user",
      "source": "object"
    }
  ],
  "auth": ["Authorization", "Bearer"],
  "secrets": [
    {
      "type": "aws-key",
      "value": "AKIA1234567890ABCDEF",
      "severity": "high",
      "confidence": 0.75,
      "source": "regex",
      "evidence": "AWS_SECRET_ACCESS_KEY=AKIA12...CDEF"
    }
  ],
  "risk": [
    {
      "type": "admin-api",
      "severity": "high",
      "evidence": "/api/admin/user"
    }
  ],
  "findings": [
    {
      "category": "敏感凭据",
      "type": "aws-key",
      "value": "AKIA1234567890ABCDEF",
      "severity": "high",
      "confidence": 0.75,
      "source": "secret",
      "evidence": "AWS_SECRET_ACCESS_KEY=AKIA12...CDEF"
    },
    {
      "category": "API 信息",
      "type": "api-endpoint",
      "value": "https://target.example/api/user",
      "severity": "medium",
      "confidence": 0.9,
      "source": "api",
      "evidence": "POST https://target.example/api/user"
    }
  ],
  "groups": {
    "endpoints": {
      "apis": [],
      "findings": [],
      "count": 0
    },
    "exposures": {
      "secrets": [],
      "findings": [],
      "count": 0
    },
    "scripts": {
      "assets": [],
      "findings": [],
      "count": 0
    }
  }
}
```

同步接口在内容已经准备好但解析或分析失败时，可能以 HTTP `200` 返回 `success:false`。下载 JS 失败发生在分析前，会返回 HTTP `502`。

### 响应字段说明

`apis[].url` 是从 JavaScript 中恢复出的原始 URL 表达式，可能是相对路径，例如 `/login`。

`apis[].resolvedUrl` 是引擎能从 bundle 中恢复静态运行时 base URL 时拼出的完整 URL，例如：

```json
{
  "url": "/login",
  "baseUrl": "https://grow.guosen.com.cn/ep",
  "resolvedUrl": "https://grow.guosen.com.cn/ep/login",
  "confidence": "high"
}
```

Burp 对接时应优先使用 `apis[].resolvedUrl` 做验证和重放。如果没有 `resolvedUrl`，再由 Burp 侧按页面 URL 或脚本 URL 解析 `apis[].url`。

`apis[].baseUrl` 来自前端静态配置，例如 `baseUrl`、`baseURL`、`domainName`。引擎支持常见打包运行时代码形式，例如：

```js
var p = document.location.protocol;
baseUrl: p + (window.location.host === "dev.local" ? "//dev.local/api" : "//target.example/api")
```

`apis[].confidence` 取值：

```text
high    绝对 URL，或已通过静态 baseUrl 解析出的相对 URL
medium  未恢复到静态 baseUrl 的根相对 URL
low     非根相对表达式，但仍然像请求地址
```

`apis[].notes` 常见取值：

```text
resolved-from-static-base-url
relative-url-without-static-base-url
```

`apis[].source` 常见取值：

```text
fetch
axios.get
axios.post
service.get
r()
requestFactory()
$.ajax
$.get
$.post
jQuery.ajax
xhr.open / XMLHttpRequest.open 风格调用
xhr.setRequestHeader / XMLHttpRequest.setRequestHeader 风格调用
```

当接口来自包装函数时，`source` 会显示命中的函数名，例如 `request`、`postJson`、`o()`，方便定位具体发包链路。

`params[].location` 取值：

```text
query
body
path
header
```

`assets[].type` 取值：

```text
script
style
asset
```

`assets` 表示从打包运行时代码中恢复出的静态资源，例如 webpack chunk 文件名映射。这些不是 HTTP API endpoint，应和 `apis` 分开展示。

`secrets[].severity` 取值：

```text
low
medium
high
```

`secrets[].source` 取值：

```text
regex
llm
llm+regex
```

`risk[].severity` 同样为：

```text
low
medium
high
```

`findings` 是面向 Burp 展示的统一发现项列表。它会把 `apis`、`assets`、`secrets`、`risk` 以及 AST 中的字符串、变量名、调用点汇总为分类结果。

`findings[].category` 当前覆盖：

```text
敏感凭据       AK/SK/token/password
API 信息       接口路径、网关、环境
权限信息       role/admin/auth/permission
云配置         OSS/S3/COS/STSToken
第三方配置     微信、阿里云、腾讯云
调试信息       sourceMap/dev/debug
内网信息       内网 IP/域名
业务敏感       手机号/身份证字段
加密逻辑       AES/RSA/key/iv
SSRF/RCE点     动态 URL/命令执行
JWT/OAuth      auth 逻辑、JWT、OAuth 参数
GraphQL        schema/query/mutation/graphql endpoint
webpack模块    隐藏 chunk/静态资源
路由信息       admin/debug/internal/actuator
```

`findings[].source` 取值：

```text
api
asset
string
identifier
call
secret
risk
```

建议 Burp 展示时以 `findings` 做总览和分类筛选，以 `apis/assets/secrets/risk` 做详情面板。

也可以直接使用 `groups` 做三栏展示：

```text
groups.endpoints  API/endpoint 类，包括真实发包点 apis 和 API 信息 findings
groups.exposures  信息泄露/风险线索类，包括 secrets 和敏感凭据、权限、云配置、内网、GraphQL、SSRF/RCE 等 findings
groups.scripts    webpack/script 类，包括 assets 和 webpack 模块 findings
```

这三个分组是为了前端展示和 Burp 对接方便；原始明细仍保留在 `apis`、`assets`、`secrets`、`risk`、`findings` 中。

`secrets[].evidence` 和 `findings[].evidence` 会尽量提供命中位置上下两行上下文，格式类似：

```text
12: const before = true;
13: const token = 'Bearer abcdefghijklmnopqrstuvwxyz12345';
14: const after = true;
```

如果无法定位源码行，会退回到简短证据，例如 `POST /api/user` 或 `call:eval`。

### 示例

```bash
curl -X POST http://127.0.0.1:3000/analyze/js \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-production-api-key" \
  -d "{\"url\":\"https://target.example/app.js\",\"content\":\"axios.post('/api/user', {uid:id})\",\"fast_mode\":true}"
```

## GET /analyze/tasks/:id

查询异步 JavaScript 分析任务。

任务 id 不存在时返回 HTTP `404`。当前任务状态保存在内存中，Node.js 进程重启后任务状态会丢失。

### 运行中响应

```json
{
  "success": true,
  "task": {
    "id": "c65125b2-0f3c-4099-9740-0dbb6d1b5870",
    "status": "running",
    "createdAt": "2026-05-19T06:30:00.000Z",
    "updatedAt": "2026-05-19T06:30:01.000Z"
  }
}
```

### 完成响应

```json
{
  "success": true,
  "task": {
    "id": "c65125b2-0f3c-4099-9740-0dbb6d1b5870",
    "status": "completed",
    "createdAt": "2026-05-19T06:30:00.000Z",
    "updatedAt": "2026-05-19T06:30:02.000Z",
    "result": {
      "success": true,
      "apis": [],
      "assets": [],
      "params": [],
      "auth": [],
      "secrets": [],
      "risk": []
    }
  }
}
```

### 失败响应

```json
{
  "success": true,
  "task": {
    "id": "c65125b2-0f3c-4099-9740-0dbb6d1b5870",
    "status": "failed",
    "createdAt": "2026-05-19T06:30:00.000Z",
    "updatedAt": "2026-05-19T06:30:02.000Z",
    "error": {
      "message": "Failed to download JS from https://target.example/app.js: HTTP 404"
    },
    "result": {
      "success": false,
      "error": {
        "message": "Failed to download JS from https://target.example/app.js: HTTP 404"
      }
    }
  }
}
```

任务状态：

```text
queued
running
completed
failed
```

### 示例

```bash
curl http://127.0.0.1:3000/analyze/tasks/c65125b2-0f3c-4099-9740-0dbb6d1b5870 \
  -H "x-api-key: your-production-api-key"
```

## POST /analyze/secret

分析单个 Secret 候选和一小段上下文。这个接口用于显式确认 Secret，不适合扫描整份 JavaScript bundle。

和 `/analyze/js` 不同，该接口直接返回 LLM 判断结果，成功响应外层没有 `success` 字段。

### 请求头

```http
Content-Type: application/json
x-api-key: your-production-api-key
```

### 请求体

```json
{
  "candidate": "AKIA1234567890ABCDEF",
  "context": "const AWS_SECRET_ACCESS_KEY = 'AKIA1234567890ABCDEF'"
}
```

字段说明：

```text
candidate 必填。Secret 候选文本。
context   必填。候选附近的小段代码上下文，不要传完整 bundle。
```

### 响应

```json
{
  "is_secret": true,
  "type": "aws-key",
  "severity": "high",
  "confidence": 0.95,
  "reason": "Hardcoded AWS credential"
}
```

如果 LLM 未配置或调用失败，接口会返回安全兜底结果：

```json
{
  "is_secret": false,
  "type": "unknown",
  "severity": "low",
  "confidence": 0,
  "reason": "LLM provider is not configured"
}
```

### 示例

```bash
curl -X POST http://127.0.0.1:3000/analyze/secret \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-production-api-key" \
  -d "{\"candidate\":\"AKIA1234567890ABCDEF\",\"context\":\"const AWS_SECRET_ACCESS_KEY='AKIA1234567890ABCDEF'\"}"
```

## Java/Burp 对接建议

建议 Burp 扩展按以下流程调用：

```text
1. 从 HTTP 响应中收集 JavaScript 响应体。
2. 调用 /analyze/js，传 fast_mode=true。
3. 展示 apis、params、auth、secrets、risk 和 assets。
4. 对接口验证和重放时，优先使用 apis[].resolvedUrl。
5. 用户主动要求深度确认 Secret 时，再调用 /analyze/secret 或使用 mode=full。
```

建议超时时间：

```text
fast_mode: 5-15 秒，取决于 bundle 大小
full mode 或 /analyze/secret: 15-60 秒，取决于 LLM provider
```

不要把完整 bundle 直接发送到 `/analyze/secret`；完整 bundle 分析请使用 `/analyze/js`。

生产部署建议给 Node.js 配置更大的 heap，尤其是需要分析 1-5MB 以上压缩 bundle 时：

```bash
NODE_OPTIONS="--max-old-space-size=4096" npm start
```

如果使用 systemd、PM2 或 Docker，请把 `NODE_OPTIONS=--max-old-space-size=4096` 放入对应环境变量配置中。

## 日志

启用文件日志后，引擎会按日期写入 JSON Lines 日志：

```text
logs/2026-05-19.log
```

每一行都是一个 JSON 对象，包含 `time`、`level`、`message` 和上下文字段。常见事件名：

```text
analyze_js_request_received
analyze_js_content_prepared
download_js_start
download_js_success
download_js_failed
download_js_timeout
analyze_js_start
analyze_js_success
analyze_js_failed
analysis_task_queued
analysis_task_running
analysis_task_content_prepared
analysis_task_completed
analysis_task_failed
llm_secret_batch_start
llm_secret_batch_completed
llm_secret_batch_failed
http_request_error
```

关键日志字段：

```text
url                       原始 JS URL
mode                      fast/full
llmExpected               当前模式是否预期进入 LLM
hasContent                请求是否携带非空 content
inputContentLength        请求体 content 字段长度
source                    content 或 download
contentLength             实际分析的 JS 长度
lineCount                 JS 行数
sha256                    JS 内容 SHA-256，用于排查重复样本，不记录 JS 原文
durationMs                分析耗时
apiCount                  API 数量
apiMethodCounts           GET/POST 等方法分布
resolvedApiCount          已补全 resolvedUrl 的 API 数量
assetCount                webpack/vite 静态资源数量
paramCount                参数数量
authCount                 认证信号数量
secretCount               Secret 候选数量
secretTypeCounts          Secret 类型分布
riskCount                 风险提示数量
findingCount              findings 总数
findingCategoryCounts     findings 分类分布
highSeverityFindingCount  高危 findings 数量
endpointGroupCount        groups.endpoints.count
exposureGroupCount        groups.exposures.count
scriptGroupCount          groups.scripts.count
llmEnabled                LLM provider 是否启用
llmCandidateCount         进入 LLM 判断范围的候选数
llmQueuedCount            成功加入 LLM 队列的数量
llmDroppedCount           因队列上限被丢弃的 LLM 候选数量
llmReviewedCount          LLM 已复核的候选数量
llmConfirmedCount         LLM 确认为真实泄露的数量
llmRejectedCount          LLM 判定为误报的数量
llmBatchCount             LLM 批次数
llmBatchSize              每批 Secret 候选数量，默认 10
```

日志不会记录完整 JavaScript 内容，也不会完整展开 Secret 原文；如需定位具体代码，请看响应里的 `evidence` 上下文。

配置示例：

```json
{
  "logging": {
    "fileEnabled": true,
    "directory": "logs",
    "level": "info"
  }
}
```

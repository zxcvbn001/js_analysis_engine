# JavaScript Analysis Engine

JavaScript Analysis Engine 是一个 JavaScript 攻击面分析工具。

它可以接收 JavaScript 源码或 JavaScript URL，基于轻量级 Node.js + AST 分析管线恢复结构化结果。对外返回面向 Burp 的三类结果：`endpoints`、`leaks`、`jsFiles`。

目标是：从前端 JavaScript 中快速、稳定、可维护地恢复有价值的攻击面信息。

## 核心能力

- 从 `fetch`、`axios`、`XMLHttpRequest`、请求封装函数、jQuery Ajax 中恢复 API。
- 支持 `r()({ url, method, data })` 这类 request factory 配置式调用。
- 从 webpack/vite runtime 中恢复可枚举的静态资源 Chunk，例如 `assets/js/chunk.xxx.js`。
- 支持字符串传播，包括常量、二元拼接、模板字符串和简单 fallback 表达式。
- 支持从打包代码里的 `baseUrl`、`baseURL`、`domainName` 配置恢复运行时 API 前缀，并输出可直接请求的 `resolvedUrl`。
- 提取 Query、Body、Path、Header 参数。
- 识别认证相关信号，例如 `Authorization`、`Bearer`、`JWT`、`X-Token`。
- 检测上下文相关的 Secret 候选，例如 JWT、AWS Key、Firebase、SMTP、OSS、内网 URL、Debug Endpoint、测试环境 URL。
- 输出 Burp 友好的三类结果：`endpoints`、`leaks`、`jsFiles`。
- `leaks` 聚合直接信息泄露，例如凭据、账号密码、测试/调试信息、内网地址、云或第三方配置、JWT/OAuth/敏感路由线索。
- 支持同步分析和异步任务分析。
- 支持生产环境 API Key 鉴权。
- 支持按日期写入文本文件日志，格式为 `[LEVEL] time event key=value`。
- 可选接入 LLM，对内部 Secret 候选和风险候选做统一复核；LLM 超时或失败时保留规则结果，不中断主分析。

## 支持的 JavaScript 场景

老项目常见写法：

- jQuery `$.ajax`、`$.get`、`$.post`、`jQuery.ajax`
- `XMLHttpRequest.open`
- `XMLHttpRequest.setRequestHeader`
- RequireJS / AMD 模块包装

现代前端写法：

- React JSX
- Vue 单文件组件中的 `<script>` 和 `<script setup>`
- Next.js 页面/模块代码
- Vite `import.meta.env`
- TypeScript 语法
- axios/fetch/request wrapper 风格调用

## 架构

```text
Burp Suite / Client
        |
        | HTTP
        v
Fastify API
        |
        v
Babel Parser
        |
        v
AST Pipeline
  - String propagation
  - Wrapper recovery
  - API extraction
  - Param extraction
  - Auth extraction
  - Secret candidate detection
  - Risk analysis
        |
        v
Structured JSON result
```

LLM 分析与主分析链路隔离，只接收小上下文候选、风险证据和 API 摘要，不会把整份 JavaScript Bundle 发送给 LLM。

## 环境要求

- Node.js 20+
- npm

主要技术栈：

- TypeScript
- Fastify
- Babel parser/traverse/types
- zod
- pino
- vitest

## 安装与启动

安装依赖：

```bash
npm ci
```

构建：

```bash
npm run build
```

开发模式：

```bash
npm run dev
```

生产启动：

```bash
npm start
```

## 配置

复制配置模板：

```bash
cp config/config.example.json config/config.json
```

Windows PowerShell：

```powershell
Copy-Item config\config.example.json config\config.json
```

`config/config.json` 已加入 `.gitignore`，因为它可能包含 API Key、LLM Key 等敏感信息。

也可以把配置文件放在仓库外：

```bash
CONFIG_FILE=/etc/js-analysis-engine/config.json npm start
```

配置示例：

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 3000,
    "logLevel": "info",
    "bodyLimitMb": 20
  },
  "fetch": {
    "timeoutMs": 10000,
    "maxBytes": 10485760
  },
  "logging": {
    "fileEnabled": true,
    "directory": "logs",
    "level": "info"
  },
  "auth": {
    "enabled": true,
    "headerName": "x-api-key",
    "apiKeys": ["your-production-api-key"]
  },
  "llm": {
    "provider": "deepseek",
    "model": "deepseek-v4-flash",
    "apiKey": "",
    "baseUrl": "https://api.deepseek.com",
    "timeoutMs": 30000,
    "logPrompts": true,
    "logResponses": true,
    "logRawPayloads": false
  }
}
```

环境变量可以覆盖配置文件：

```bash
HOST=0.0.0.0
PORT=3000
LOG_LEVEL=info
BODY_LIMIT_MB=20
FETCH_TIMEOUT_MS=10000
FETCH_MAX_BYTES=10485760
LOG_FILE_ENABLED=true
LOG_DIR=logs
LOG_FILE_LEVEL=info
API_AUTH_ENABLED=true
API_KEY_HEADER=x-api-key
API_KEYS=key-one,key-two
LLM_PROVIDER=deepseek
LLM_MODEL=deepseek-v4-flash
LLM_API_KEY=your-llm-key
LLM_BASE_URL=https://api.deepseek.com
LLM_TIMEOUT_MS=30000
LLM_LOG_PROMPTS=true
LLM_LOG_RESPONSES=true
LLM_LOG_RAW_PAYLOADS=false
LLM_REVIEW_SECRETS=true
LLM_REVIEW_RISK_CANDIDATES=true
LLM_ALLOWED_SECRET_TYPES=bearer-token,aws-key
LLM_ALLOWED_RISK_CATEGORIES=敏感凭据,云配置,JWT/OAuth
LOG_LLM_CONSOLE=true
```

LLM 交互日志默认记录脱敏后的 prompt/response 摘要，并会同步打印到服务进程控制台，方便通过 `pm2 logs`、`journalctl` 或 Docker logs 排查。可以设置 `LOG_LLM_CONSOLE=false` 关闭控制台打印。只有临时排障时才建议开启 `LLM_LOG_RAW_PAYLOADS=true`，因为原始 prompt 可能包含源码上下文和敏感候选。

如果 `full` 模式下 LLM 经常超时，可以缩小复核范围：

```text
LLM_REVIEW_SECRETS=false
  不再对 Secret 候选做 LLM 复核，保留规则结果。

LLM_REVIEW_RISK_CANDIDATES=false
  不再对内部风险候选做 LLM 复核，保留规则结果。

LLM_ALLOWED_SECRET_TYPES=type1,type2
  只让指定 Secret 类型进入 LLM；留空表示全部类型。

LLM_ALLOWED_RISK_CATEGORIES=分类1,分类2
  只让指定内部风险分类进入 LLM；留空表示全部分类。
```

## API 概览

API对接文档见：[docs/api.md](docs/api.md)。

### 健康检查

```bash
curl http://127.0.0.1:3000/health
```

### 同步 JavaScript 分析

```bash
curl -X POST http://127.0.0.1:3000/analyze/js \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-production-api-key" \
  -d "{\"url\":\"https://target.example/app.js\",\"content\":\"fetch('/api/user')\",\"fast_mode\":true}"
```

`content` 和 `url` 至少传一个：

- 如果 `content` 非空，优先分析 `content`。
- 如果 `content` 为空且传入 `url`，引擎会下载该 URL 的 JavaScript 后分析。
- Burp 已经拿到响应体时，推荐直接传 `content`，避免二次网络请求。

### 异步 JavaScript 分析

提交任务：

```bash
curl -X POST http://127.0.0.1:3000/analyze/js \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-production-api-key" \
  -d "{\"url\":\"https://target.example/app.js\",\"async\":true,\"fast_mode\":true}"
```

响应：

```json
{
  "success": true,
  "task_id": "c65125b2-0f3c-4099-9740-0dbb6d1b5870",
  "status": "queued",
  "status_url": "/analyze/tasks/c65125b2-0f3c-4099-9740-0dbb6d1b5870"
}
```

查询任务：

```bash
curl http://127.0.0.1:3000/analyze/tasks/c65125b2-0f3c-4099-9740-0dbb6d1b5870 \
  -H "x-api-key: your-production-api-key"
```

任务状态：

```text
queued
running
completed
failed
```

### Secret 候选确认

```bash
curl -X POST http://127.0.0.1:3000/analyze/secret \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-production-api-key" \
  -d "{\"candidate\":\"AKIA1234567890ABCDEF\",\"context\":\"const AWS_SECRET_ACCESS_KEY='AKIA1234567890ABCDEF'\"}"
```

该接口用于“小候选 + 小上下文”确认，不适合直接传整份 JS Bundle。

## 响应格式

JavaScript 分析成功时固定返回三类结果：`leaks`、`endpoints`、`jsFiles`。`response_mode` 目前只保留兼容入参，不再改变对外字段结构。

```json
{
  "success": true,
  "url": "https://target.example/app.js",
  "summary": {
    "endpointCount": 1,
    "leakCount": 1,
    "jsFileCount": 1
  },
  "leaks": [
    {
      "category": "敏感凭据",
      "type": "bearer-token",
      "value": "Bearer abcdefghijklmnopqrstuvwxyz12345",
      "severity": "high",
      "confidence": 0.9,
      "source": "regex",
      "evidence": "const token = 'Bearer ...';"
    }
  ],
  "endpoints": [
    {
      "url": "/api/user",
      "resolvedUrl": "https://target.example/api/user",
      "baseUrl": "https://target.example",
      "method": "POST",
      "confidence": "high"
    }
  ],
  "jsFiles": [
    {
      "url": "assets/js/chunk-01d475cb.4ef8f8dc.js",
      "type": "script",
      "chunkName": "chunk-01d475cb",
      "source": "webpack-runtime-return",
      "confidence": 0.85
    }
  ]
}
```

`endpoints` 是真实发包调用图恢复出的接口列表。`endpoints[].url` 是 JavaScript 中的原始路径，可能是 `/login` 这种相对路径。

`endpoints[].resolvedUrl` 是引擎能静态恢复运行时 `baseUrl` 时拼出的完整 URL。Burp 对接时应优先使用 `resolvedUrl` 做验证和重放；如果没有该字段，再由 Burp 按页面 URL 或脚本 URL 自行解析相对路径。

`leaks` 是对渗透测试有直接价值的信息泄露，包括凭据、账号密码、测试/调试信息、内网地址、云配置、第三方配置、JWT/OAuth、敏感路由和非发包点的网关/环境配置。

`jsFiles` 是 JS/静态资源线索，包括 webpack/vite runtime 恢复出的 chunk、脚本、样式和相关模块资源。外部 API 不再返回历史内部字段，只保留 `leaks`、`endpoints`、`jsFiles`。

错误响应：

```json
{
  "success": false,
  "error": {
    "message": "Error message"
  }
}
```

## LLM 使用边界

LLM 是可选能力，用于对内部 Secret 候选和风险候选做统一复核。

当前行为：

- `/analyze/js` + `fast_mode=true` 或 `mode="fast"`：不调用 LLM。
- `/analyze/js` 不传模式或 `mode="full"`：默认 full；如果 LLM 已正确配置，内部 Secret 候选和风险候选会统一复核，LLM 判定为误报的结果会丢弃。
- `/analyze/secret`：对单个 candidate + context 调用 LLM 确认。

统一 LLM 研判每批最多包含 5 个 Secret 候选和 10 个风险候选，限速为 60/min，即每秒最多启动 1 个 LLM 批次。引擎不会把完整 JavaScript Bundle 发送给 LLM。LLM 未配置、超时或调用失败时，full 会退回规则候选，不中断主分析；某个批次失败后会保留该批和剩余未复核候选并尽快返回。

Burp 被动扫描或批量扫描建议显式传 `fast_mode:true`。`full` 更适合用户主动触发的单文件深度分析。

## 日志

启用文件日志后，日志按日期写入文本文件：

```text
logs/YYYY-MM-DD.log
```

日志行格式类似：

```text
[INFO] 2026-05-26T02:55:14.134Z analyze_js_response_sent endpointCount=12 leakCount=3 jsFileCount=152
```

常见事件名：

```text
analyze_js_request_received
analyze_js_request_summary
analyze_js_content_prepared
analyze_js_task_submitted
analyze_js_response_sent
analyze_task_response_sent
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
llm_analysis_summary
llm_provider_prompt_built
llm_provider_request_start
llm_provider_request_retry
llm_provider_request_failed
http_request_error
```

日志会记录输入和输出摘要，例如请求模式、`response_mode`、是否异步、content 长度/行数/SHA-256、异步返回的 `task_id/status_url`、API 数量、`endpoint/leak/jsFile` 数量、Secret 候选数量、内部风险候选分类分布、LLM 候选数、复核数和失败保留数；不会记录完整 JS 原文。

## 测试

```bash
npm test
```

构建：

```bash
npm run build
```

## 发布包

Windows 下可以执行：

```bat
release.bat
```

发布包输出到：

```text
release/js-analysis-engine-YYYYMMDD-HHMMSS.zip
```

发布包包含源码、文档、配置模板和 npm 元数据；不包含本地密钥、日志、构建产物、依赖目录、缓存和历史发布包。

## 生产内存建议

分析 1-5MB 以上压缩 bundle 时，建议给 Node.js 配置更大的 heap：

```bash
NODE_OPTIONS="--max-old-space-size=4096" npm start
```

如果使用 systemd、PM2 或 Docker，请把 `NODE_OPTIONS=--max-old-space-size=4096` 放入对应环境变量配置中。


## License

MIT License. See [LICENSE](LICENSE).

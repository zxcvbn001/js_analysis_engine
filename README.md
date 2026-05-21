# JavaScript Analysis Engine

JavaScript Analysis Engine 是一个 JavaScript 攻击面分析工具。

它可以接收 JavaScript 源码或 JavaScript URL，基于轻量级 Node.js + AST 分析管线恢复结构化结果，包括 API、参数、Header、认证信号、Secret 候选和风险提示。

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
- 输出统一 `findings` 分类结果，覆盖敏感凭据、API 信息、权限信息、云配置、第三方配置、调试信息、内网信息、业务敏感、加密逻辑、SSRF/RCE 点、JWT/OAuth、GraphQL、webpack 模块和敏感路由。
- 从 API 路径、函数名、变量名、调用名中提取轻量风险提示。
- 支持同步分析和异步任务分析。
- 支持生产环境 API Key 鉴权。
- 支持按日期写入 JSON Lines 文件日志。
- 可选接入 LLM，但仅用于 Secret 候选确认。

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

LLM 分析与主分析链路隔离，只用于对 Secret 候选做小上下文确认，不会把整份 JavaScript Bundle 发送给 LLM。

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
cp config.example.json config/config.json
```

Windows PowerShell：

```powershell
Copy-Item config.example.json config\config.json
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
    "timeoutMs": 8000
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
LLM_TIMEOUT_MS=8000
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

JavaScript 分析成功时返回：

```json
{
  "success": true,
  "url": "https://target.example/app.js",
  "apis": [
    {
      "url": "/api/user",
      "resolvedUrl": "https://target.example/api/user",
      "baseUrl": "https://target.example",
      "method": "POST",
      "confidence": "high"
    }
  ],
  "assets": [],
  "params": [],
  "auth": [],
  "secrets": [],
  "risk": [],
  "findings": []
}
```

`apis[].url` 是从 JavaScript 中恢复出的原始路径，可能是 `/login` 这种相对路径。

`apis[].resolvedUrl` 是引擎能静态恢复运行时 `baseUrl` 时拼出的完整 URL。Burp 对接时应优先使用 `resolvedUrl` 做验证和重放；如果没有该字段，再由 Burp 按页面 URL 或脚本 URL 自行解析相对路径。

`findings` 是面向展示和筛选的统一发现项列表，字段包括 `category`、`type`、`value`、`severity`、`confidence`、`source` 和 `evidence`。

`groups` 是面向 Burp 展示的三类聚合：

```text
groups.endpoints  API/endpoint
groups.exposures  信息泄露/风险线索
groups.scripts    webpack/script
```

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

LLM 是可选能力，并且只用于 Secret 候选确认。

当前行为：

- `/analyze/js` + `fast_mode=true` 或 `mode="fast"`：不调用 LLM。
- `/analyze/js` 不传模式或 `mode="full"`：默认 full；如果 LLM 已正确配置，Secret 候选会同步复核，只返回 LLM 确认后的结果，LLM 判定为误报的候选会丢弃。
- `/analyze/secret`：对单个 candidate + context 调用 LLM 确认。

LLM 限速为 60/min，即每秒最多启动 1 个 LLM 分析任务。引擎不会把完整 JavaScript Bundle 发送给 LLM。LLM 未配置时，full 会退回规则候选，不中断主分析。

Burp 被动扫描或批量扫描建议显式传 `fast_mode:true`。`full` 更适合用户主动触发的单文件深度分析。

## 日志

启用文件日志后，日志按日期写入 JSON Lines 文件：

```text
logs/YYYY-MM-DD.log
```

常见事件名：

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
http_request_error
```

日志会记录输入和输出摘要，例如 JS 长度、行数、SHA-256、API 数量、Secret 候选数量、findings 分类分布、LLM 候选数和入队数；不会记录完整 JS 原文。

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

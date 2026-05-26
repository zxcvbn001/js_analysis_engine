# API 对接文档

本文档描述 JavaScript Analysis Engine 暴露给 Burp Suite 扩展或其他客户端调用的 HTTP API。

## 基础信息

默认地址：

```text
http://127.0.0.1:3000
```

生产环境以 `config/config.json` 或 `CONFIG_FILE` 指向的配置文件为准。

API Key 鉴权由配置控制：

```json
{
  "auth": {
    "enabled": true,
    "headerName": "x-api-key",
    "apiKeys": ["your-production-api-key"]
  }
}
```

启用后，分析接口需要携带：

```http
x-api-key: your-production-api-key
```

`GET /health` 始终不需要鉴权。

## 错误格式

```json
{
  "success": false,
  "error": {
    "message": "Missing or invalid API key"
  }
}
```

常见状态码：

```text
200 分析完成或请求成功
202 异步任务已提交
400 请求体不合法
401 API Key 缺失或错误
404 任务不存在
502 下载 JavaScript 失败
500 服务端错误
```

如果 `/analyze/js` 只传了 `url`，但引擎无法下载 JavaScript，会返回 `502`。Burp 已经拿到 JS 响应体时，建议直接传 `content`，避免二次下载受目标 TLS、代理、DNS 影响。

## GET /health

```bash
curl http://127.0.0.1:3000/health
```

响应：

```json
{
  "success": true
}
```

## POST /analyze/js

分析 JavaScript 内容，恢复对渗透测试真正有用的三类结果：

```text
leaks      直接信息泄露，例如凭据、账号密码、测试/调试信息、内网地址、云配置、JWT/OAuth、敏感路由、非发包点的网关/环境配置
endpoints  真实发包调用图恢复出的 API endpoint
jsFiles    JS/静态资源线索，包括 webpack/vite chunk、脚本、样式和 webpack 模块资源
```

内部仍然会使用 AST、发包调用图、Secret 候选、风险候选和 LLM 复核，但 HTTP 响应只暴露 `leaks`、`endpoints`、`jsFiles`。

### 请求

```http
Content-Type: application/json
x-api-key: your-production-api-key
```

```json
{
  "url": "https://target.example/static/app.js",
  "content": "const API='/api'; fetch(API + '/user')",
  "fast_mode": true,
  "mode": "fast",
  "response_mode": "compact",
  "async": false
}
```

字段说明：

```text
url           可选。Burp 看到的原始 JS URL；content 为空时用于下载 JS。
content       可选。JavaScript 源码或打包后的 bundle 内容。
fast_mode     可选。true 表示只做 AST/规则分析，不进入 LLM 队列。
mode          可选。"fast" 或 "full"。不传时默认 "full"。
response_mode 可选。"full" 或 "compact"。当前仅保留兼容参数，响应字段结构相同。
async         可选。true 表示立即返回任务 id，后台异步分析。
```

`content` 和 `url` 至少传一个。优先级：

```text
1. content 非空：直接分析 content，不下载 url。
2. content 缺失、为空字符串或只有空白字符：使用 url 下载 JavaScript 后分析。
3. content 和 url 都缺失或都为空：返回 400。
```

因此，Burp 同时传 `url` 和 `content` 时，以 `content` 为准；`url` 只作为上下文，用于相对路径、脚本来源 host、`resolvedUrl` 辅助恢复。

模式优先级：

```text
1. fast_mode=true：强制 fast，不调用 LLM。
2. mode="fast"：不调用 LLM。
3. mode 缺失或 mode="full"：默认 full；如果 LLM 已正确配置，内部 Secret 候选和风险候选会进入统一 LLM 研判。
```

Burp 被动扫描建议：

```json
{
  "url": "https://target.example/app.js",
  "content": "...",
  "fast_mode": true,
  "response_mode": "compact"
}
```

### 成功响应

同步和异步任务完成后的 `result` 都使用同一结构：

```json
{
  "success": true,
  "url": "https://target.example/static/app.js",
  "summary": {
    "endpointCount": 1,
    "leakCount": 2,
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
      "evidence": "12: const token = 'Bearer abcdefghijklmnopqrstuvwxyz12345';"
    },
    {
      "category": "调试信息",
      "type": "debug-dev",
      "value": "https://dev.example.com/debug",
      "severity": "medium",
      "confidence": 0.7,
      "source": "string",
      "evidence": "18: const debugUrl = 'https://dev.example.com/debug';"
    }
  ],
  "endpoints": [
    {
      "url": "/api/user",
      "resolvedUrl": "https://target.example/api/user",
      "baseUrl": "https://target.example",
      "kind": "api",
      "method": "POST",
      "params": ["uid", "role"],
      "headers": ["Authorization"],
      "auth": "Authorization",
      "source": "axios.post",
      "confidence": "high",
      "notes": ["resolved-from-static-base-url"],
      "evidence": "24: axios.post('/api/user', { uid, role })"
    }
  ],
  "jsFiles": [
    {
      "url": "assets/js/chunk-01d475cb.4ef8f8dc.js",
      "type": "script",
      "chunkName": "chunk-01d475cb",
      "source": "webpack-runtime-return",
      "confidence": 0.85,
      "evidence": "webpack-runtime-return"
    }
  ]
}
```

### 字段说明

`summary.endpointCount`、`summary.leakCount`、`summary.jsFileCount` 分别等于 `endpoints.length`、`leaks.length`、`jsFiles.length`。Burp 展示数量应以这三个字段或对应数组长度为准。

`leaks[].category` 常见取值：

```text
敏感凭据
API 信息
权限信息
云配置
第三方配置
调试信息
内网信息
JWT/OAuth
路由信息
```

`API 信息` 只用于非真实发包点的网关、环境、base URL 等泄露线索；真实发包接口放入 `endpoints`，不会重复塞进 `leaks`。

`leaks[].severity` 取值：

```text
low
medium
high
```

`leaks[].evidence` 尽量提供命中位置附近上下文。对压缩成单行的 bundle，会按命中值前后固定窗口截取，保证命中值本身可见，同时避免把超长 evidence 发给 Burp 或 LLM。

`endpoints[].url` 是从 JavaScript 中恢复出的原始 URL 表达式，可能是相对路径，例如 `/login`。

`endpoints[].resolvedUrl` 是引擎能从 bundle 中恢复静态运行时 base URL 时拼出的完整 URL。Burp 验证和重放时应优先使用 `resolvedUrl`；如果没有该字段，再由 Burp 按页面 URL 或脚本 URL 解析 `url`。

`endpoints[].source` 常见取值：

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
```

`endpoints[].confidence` 取值：

```text
high    绝对 URL，或已通过静态 baseUrl 解析出的相对 URL
medium  未恢复到静态 baseUrl 的根相对 URL
low     非根相对表达式，但仍然像请求地址
```

`jsFiles[].type` 取值：

```text
script
style
asset
webpack-module
```

`jsFiles` 不是 API endpoint，不建议直接送去接口验证；它用于继续拉取 chunk、定位隐藏路由和扩展后续 JS 分析范围。

### 异步分析

如果 `async=true`，提交接口返回 HTTP `202`：

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

运行中：

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

完成：

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
      "summary": {
        "endpointCount": 0,
        "leakCount": 0,
        "jsFileCount": 0
      },
      "leaks": [],
      "endpoints": [],
      "jsFiles": []
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

当前任务状态保存在内存中，Node.js 进程重启后任务状态会丢失。

## POST /analyze/secret

分析单个 Secret 候选和一小段上下文。这个接口用于手工确认 Secret，不适合扫描整份 JavaScript bundle。

请求：

```json
{
  "candidate": "AKIA1234567890ABCDEF",
  "context": "const AWS_SECRET_ACCESS_KEY = 'AKIA1234567890ABCDEF'"
}
```

响应：

```json
{
  "is_secret": true,
  "type": "aws-key",
  "severity": "high",
  "confidence": 0.95,
  "reason": "Hardcoded AWS credential"
}
```

如果 LLM 未配置或调用失败，会返回安全兜底结果：

```json
{
  "is_secret": false,
  "type": "unknown",
  "severity": "low",
  "confidence": 0,
  "reason": "LLM provider is not configured"
}
```

## LLM 行为

LLM 是可选能力。`fast_mode=true` 或 `mode="fast"` 不调用 LLM。默认 `mode="full"` 时，如果 LLM 已配置，内部 Secret 候选和风险候选会统一分批复核。

统一 LLM 研判每批最多包含 5 个 Secret 候选和 10 个风险候选，默认限速 `60/min`。引擎不会把完整 JavaScript bundle 发给 LLM，只发送受限长度的 evidence、候选值摘要和 API 上下文。

如果 LLM 未配置、超时或调用失败，主分析不会失败；该批和剩余未复核候选会保留规则结果并返回。

可通过配置缩小复核范围：

```text
LLM_REVIEW_SECRETS=false
  不再让 Secret 候选进入 LLM，保留规则结果。

LLM_REVIEW_RISK_CANDIDATES=false
  不再让内部风险候选进入 LLM，保留规则结果。

LLM_ALLOWED_SECRET_TYPES=bearer-token,aws-key
  只有命中的 Secret 类型才进入 LLM；留空表示全部类型。

LLM_ALLOWED_RISK_CATEGORIES=敏感凭据,云配置,JWT/OAuth
  只有命中的内部风险分类才进入 LLM；留空表示全部分类。
```

## 日志

启用文件日志后，引擎会按日期写入文本日志：

```text
logs/2026-05-19.log
```

每一行格式为 `[LEVEL] ISO时间 event key=value`：

```text
[INFO] 2026-05-26T02:55:14.134Z analyze_js_response_sent endpointCount=12 leakCount=3 jsFileCount=152
```

关键事件：

```text
analyze_js_request_received
analyze_js_request_summary
analyze_js_content_prepared
analyze_js_task_submitted
analyze_js_response_sent
analyze_task_response_sent
analysis_task_queued
analysis_task_running
analysis_task_content_prepared
analysis_task_completed
analysis_task_failed
download_js_start
download_js_success
download_js_failed
download_js_timeout
analyze_js_start
analyze_js_success
analyze_js_failed
llm_analysis_summary
llm_unified_review_decision
llm_unified_batch_start
llm_unified_batch_completed
llm_unified_batch_failed
llm_provider_prompt_built
llm_provider_request_start
llm_provider_request_attempt_start
llm_provider_response_received
llm_provider_response_body_received
llm_provider_response_parsed
llm_provider_request_retry
llm_provider_request_failed
http_request_error
```

日志会记录输入和输出摘要，例如请求模式、是否异步、content 长度/行数/SHA-256、异步返回的 `task_id/status_url`、内部 API/Secret/候选统计、对外 `endpoint/leak/jsFile` 数量、LLM 候选数、复核数和失败保留数。日志不会记录完整 JS 原文。

排查 LLM 调用时可临时开启：

```env
LLM_LOG_PROMPTS=true
LLM_LOG_RESPONSES=true
LLM_LOG_RAW_PAYLOADS=false
LOG_LLM_CONSOLE=true
```

开启后会在 `llm_provider_prompt_built`、`llm_provider_request_start`、`llm_provider_response_body_received` 等日志里看到脱敏后的 prompt/response 摘要。只有临时排障时才建议开启 `LLM_LOG_RAW_PAYLOADS=true`。

## Burp 对接建议

```text
1. 从 HTTP 响应中收集 JavaScript 响应体。
2. 调用 /analyze/js，传 content、url、fast_mode=true。
3. 展示 leaks、endpoints、jsFiles 三个列表。
4. 对接口验证和重放时，优先使用 endpoints[].resolvedUrl。
5. 对 jsFiles 中的 script/chunk，可继续拉取后再次调用 /analyze/js。
6. 用户主动要求深度确认时，使用 mode=full 触发统一 LLM 研判。
```

建议超时时间：

```text
fast_mode: 5-15 秒，取决于 bundle 大小
full mode 或 /analyze/secret: 15-60 秒，取决于 LLM provider
```

生产部署建议给 Node.js 配置更大的 heap：

```bash
NODE_OPTIONS="--max-old-space-size=4096" npm start
```

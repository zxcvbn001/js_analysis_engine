# Burp API Integration Guide

This document describes the HTTP API exposed by JavaScript Analysis Engine for Burp Suite extensions.

## Base URL

```text
http://127.0.0.1:3000
```

In production, use the host and port configured in `config/config.json` or `CONFIG_FILE`.

## Authentication

Authentication is optional and controlled by configuration:

```json
{
  "auth": {
    "enabled": true,
    "headerName": "x-api-key",
    "apiKeys": ["your-production-api-key"]
  }
}
```

When enabled, all analysis APIs require the configured header:

```http
x-api-key: your-production-api-key
```

`GET /health` is always unauthenticated for health checks.

## Common Error Format

```json
{
  "success": false,
  "error": {
    "message": "Missing or invalid API key"
  }
}
```

Common HTTP status codes:

```text
200 OK
202 Async task accepted
400 Invalid request body
401 Missing or invalid API key
404 Task not found
502 Failed to download JavaScript from URL
500 Server error
```

If `/analyze/js` is called with `url` only and the engine cannot download the JavaScript, the response may look like:

```json
{
  "success": false,
  "error": {
    "message": "Failed to download JS from https://target.example/app.js: fetch failed. Check network, DNS, TLS certificate, proxy, or target availability."
  }
}
```

This means the analysis engine did not receive `content` and failed while downloading the script from `url`. Prefer sending `content` from Burp when the response body is already available.

## GET /health

Health check endpoint.

### Response

```json
{
  "success": true
}
```

### Example

```bash
curl http://127.0.0.1:3000/health
```

## POST /analyze/js

Analyze JavaScript content and recover APIs, parameters, auth signals, secrets, and risks.

### Supported JavaScript Sources

The analyzer is AST-first and is intended to handle both legacy and modern frontend JavaScript:

```text
Legacy:
- jQuery $.ajax / $.get / $.post
- XMLHttpRequest open / setRequestHeader
- RequireJS / AMD module wrappers

Modern:
- React JSX
- Vue single-file component script blocks
- Next.js page/module code
- Vite import.meta syntax
- TypeScript syntax
- axios/fetch/request wrapper style calls
```

### Request Headers

```http
Content-Type: application/json
x-api-key: your-production-api-key
```

`x-api-key` is required only when `auth.enabled=true`.

### Request Body

```json
{
  "url": "https://target.example/static/app.js",
  "content": "const API='/api'; fetch(API + '/user')",
  "fast_mode": true,
  "mode": "fast",
  "async": false
}
```

Fields:

```text
url       Optional when content is present. Original JS URL from Burp.
content   Optional when url is present. JavaScript source code or bundle content.
fast_mode Optional. true means AST/rule analysis only. Recommended for Burp passive flows.
mode      Optional. "fast" or "full". "full" enables LLM secret enhancement queue.
async     Optional. true returns a task id immediately and runs analysis in the background.
```

At least one of `content` or `url` is required. If both are present, `content` is used first. If `content` is missing or empty, the engine downloads JavaScript from `url` and analyzes the downloaded body.

If `fast_mode=true`, it overrides `mode` and uses fast analysis.

If `async=true`, the response is `202 Accepted`:

```json
{
  "success": true,
  "task_id": "c65125b2-0f3c-4099-9740-0dbb6d1b5870",
  "status": "queued",
  "status_url": "/analyze/tasks/c65125b2-0f3c-4099-9740-0dbb6d1b5870"
}
```

### Burp Recommendation

Use this default from Burp:

```json
{
  "url": "https://target.example/app.js",
  "content": "...",
  "fast_mode": true
}
```

If Burp already has the JavaScript response body, send `content`; this is fastest and avoids a second network request. If only the script URL is available, send `url` only and the engine will download it.

Use `mode:"full"` only for explicit user-triggered analysis, because LLM calls may add cost and latency.

### Success Response

```json
{
  "success": true,
  "url": "https://target.example/static/app.js",
  "apis": [
    {
      "url": "/api/user",
      "method": "POST",
      "params": ["uid", "role"],
      "headers": ["Authorization"],
      "auth": "Authorization",
      "source": "axios.post"
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
  ]
}
```

### Response Object Notes

`apis[].source` examples:

```text
fetch
axios.get
axios.post
service.get
xhr.open
```

`params[].location` values:

```text
query
body
path
header
```

`secrets[].severity` values:

```text
low
medium
high
```

`secrets[].source` values:

```text
regex
llm
llm+regex
```

### Example

```bash
curl -X POST http://127.0.0.1:3000/analyze/js \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-production-api-key" \
  -d "{\"url\":\"https://target.example/app.js\",\"content\":\"axios.post('/api/user', {uid:id})\",\"fast_mode\":true}"
```

## GET /analyze/tasks/:id

Query an asynchronous analysis task.

### Response While Running

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

### Response When Completed

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
      "params": [],
      "auth": [],
      "secrets": [],
      "risk": []
    }
  }
}
```

Task status values:

```text
queued
running
completed
failed
```

### Example

```bash
curl http://127.0.0.1:3000/analyze/tasks/c65125b2-0f3c-4099-9740-0dbb6d1b5870 \
  -H "x-api-key: your-production-api-key"
```

## POST /analyze/secret

Analyze one secret candidate with a small code context. This endpoint is intended for explicit secret confirmation, not full JS bundle scanning.

### Request Headers

```http
Content-Type: application/json
x-api-key: your-production-api-key
```

### Request Body

```json
{
  "candidate": "AKIA1234567890ABCDEF",
  "context": "const AWS_SECRET_ACCESS_KEY = 'AKIA1234567890ABCDEF'"
}
```

Fields:

```text
candidate Required. Candidate secret text.
context   Required. Small nearby code slice. Do not send the entire bundle.
```

### Response

```json
{
  "is_secret": true,
  "type": "aws-key",
  "severity": "high",
  "confidence": 0.95,
  "reason": "Hardcoded AWS credential"
}
```

If the LLM provider is not configured or fails, the endpoint returns a safe fallback response:

```json
{
  "is_secret": false,
  "type": "unknown",
  "severity": "low",
  "confidence": 0,
  "reason": "LLM provider is not configured"
}
```

### Example

```bash
curl -X POST http://127.0.0.1:3000/analyze/secret \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-production-api-key" \
  -d "{\"candidate\":\"AKIA1234567890ABCDEF\",\"context\":\"const AWS_SECRET_ACCESS_KEY='AKIA1234567890ABCDEF'\"}"
```

## Java/Burp Integration Notes

Suggested Burp extension behavior:

```text
1. Collect JavaScript response body.
2. POST it to /analyze/js with fast_mode=true.
3. Display apis, params, auth, secrets, and risk.
4. Only call /analyze/secret or mode=full when the user asks for deeper secret confirmation.
```

Suggested request timeout:

```text
fast_mode: 5-15 seconds depending on bundle size
full mode or /analyze/secret: 15-60 seconds depending on LLM provider
```

Do not send entire bundles to `/analyze/secret`; use `/analyze/js` for bundle analysis.

## Logs

The engine writes JSON Lines logs by date when file logging is enabled:

```text
logs/2026-05-19.log
```

Each line is a JSON object containing `time`, `level`, `message`, and context fields. Useful message names include:

```text
download_js_start
download_js_success
download_js_failed
download_js_timeout
analyze_js_start
analyze_js_success
analyze_js_failed
analysis_task_queued
analysis_task_running
analysis_task_completed
analysis_task_failed
http_request_error
```

Configuration:

```json
{
  "logging": {
    "fileEnabled": true,
    "directory": "logs",
    "level": "info"
  }
}
```

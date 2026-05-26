# Configuration

Copy `config/config.example.json` to `config/config.json` for local or production configuration.

`config/config.json` is ignored by git because it can contain API keys.

The service loads configuration in this order:

1. Built-in defaults
2. JSON file from `CONFIG_FILE`, or `config/config.json` by default
3. Environment variable overrides

Useful environment overrides:

```bash
CONFIG_FILE=/etc/js-analysis-engine/config.json
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
LLM_API_KEY=your-secret-key
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

LLM prompt/response logs are redacted by default. Set `LLM_LOG_RAW_PAYLOADS=true`
only for short-term debugging because raw prompts can contain sensitive code context.
LLM logs are also mirrored to the process console by default. Set
`LOG_LLM_CONSOLE=false` to keep them in the log file only.

LLM review scope can be narrowed to reduce timeout risk:

```text
LLM_REVIEW_SECRETS=false
  Disable secret candidate review entirely. Full mode keeps regex/rule secret results.

LLM_REVIEW_RISK_CANDIDATES=false
  Disable risk candidate review entirely. Full mode keeps rule results.

LLM_ALLOWED_SECRET_TYPES=type1,type2
  Only these secret types enter LLM. Empty means all types.

LLM_ALLOWED_RISK_CATEGORIES=分类1,分类2
  Only these risk candidate categories enter LLM. Empty means all categories.
```

When `auth.enabled` is true, all analysis APIs require the configured API key header.
`GET /health` remains unauthenticated for health checks.

File logs are written as readable text lines by date:

```text
logs/YYYY-MM-DD.log
```

Set `logging.directory` or `LOG_DIR` to move logs to another directory.

# Configuration

Copy `config.example.json` to `config/config.json` for local or production configuration.

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
```

LLM prompt/response logs are redacted by default. Set `LLM_LOG_RAW_PAYLOADS=true`
only for short-term debugging because raw prompts can contain sensitive code context.

When `auth.enabled` is true, all analysis APIs require the configured API key header.
`GET /health` remains unauthenticated for health checks.

File logs are written as JSON Lines files by date:

```text
logs/YYYY-MM-DD.log
```

Set `logging.directory` or `LOG_DIR` to move logs to another directory.

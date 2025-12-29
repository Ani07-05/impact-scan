# Impact Scan GitHub App

Fast, context-aware code review for GitHub Pull Requests.

## Architecture

### Components

1. **Webhook Handler** (`webhook_handler.py`)
   - FastAPI server for GitHub webhooks
   - Signature verification
   - PR event processing
   - Health check endpoint

2. **Tier Manager** (`tier_manager.py`)
   - Free tier: 25 scans/day per installation
   - Pro tier: Unlimited (Coming Soon)
   - Redis-based quota tracking
   - Daily reset at 00:00 UTC

3. **Queue Manager** (`queue_manager.py`)
   - Redis-based job queue
   - Smart scheduling:
     - Pro tier gets priority
     - Smaller PRs go first within tier
   - Job status tracking

4. **GitHub Client** (`github_client.py`)
   - GitHub App authentication
   - Installation token caching
   - PR comments (post/edit)
   - Check runs (create/update)
   - Review comments (inline)

5. **Comment Formatter** (`comment_formatter.py`)
   - Progressive disclosure
   - Mermaid diagrams
   - "Coming Soon" Pro tier messaging
   - Validation stats display

## Setup

### 1. Create GitHub App

1. Go to GitHub Settings → Developer settings → GitHub Apps
2. Create new GitHub App:
   - **Webhook URL:** `https://your-domain.com/webhook`
   - **Webhook secret:** Generate a random string
   - **Permissions:**
     - Contents: Read
     - Pull requests: Read & Write
     - Checks: Read & Write
   - **Subscribe to events:**
     - Pull request (opened, synchronize)

3. Generate private key (download `.pem` file)
4. Note down App ID

### 2. Environment Variables

Create `.env` file:

```bash
# GitHub App credentials
GITHUB_APP_ID=123456
GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
GITHUB_WEBHOOK_SECRET=your_webhook_secret

# Redis connection
REDIS_URL=redis://localhost:6379/0

# Groq API (for AI validation - Phase 2)
GROQ_API_KEY=your_groq_api_key
```

### 3. Install Dependencies

```bash
pip install -r requirements-github-app.txt
```

### 4. Start Redis

```bash
# Using Docker
docker run -d -p 6379:6379 redis:latest

# Or install locally
# See: https://redis.io/docs/getting-started/
```

### 5. Run Webhook Server

```bash
# Development
python -m impact_scan.github_app.webhook_handler

# Production (with Uvicorn)
uvicorn impact_scan.github_app.webhook_handler:app --host 0.0.0.0 --port 8000
```

### 6. Expose Webhook (Development)

```bash
# Using ngrok
ngrok http 8000

# Update GitHub App webhook URL with ngrok URL
```

## Current Status

### ✅ Implemented (Phase 1)

- [x] Webhook handler with signature verification
- [x] Tier manager with 25/day quota
- [x] Redis queue with smart scheduling
- [x] GitHub API client
- [x] Comment formatter with Pro messaging
- [x] Limit reached messaging

### 🚧 In Progress (Phase 2)

- [ ] Scanner worker (Phase 1: Fast scan)
- [ ] Mermaid diagram generation (file relationships)
- [ ] Initial comment posting
- [ ] Repo caching with LRU eviction

### 📋 Planned (Phase 3-5)

- [ ] Knowledge graph integration
- [ ] AI validation with graph context
- [ ] Fix generation (template + LLM)
- [ ] Stack Overflow enrichment (Pro)
- [ ] Polish suggestions (Pro)
- [ ] Web dashboard (Week 2)

## API Endpoints

### `POST /webhook`

GitHub webhook receiver.

**Headers:**
- `X-Hub-Signature-256`: HMAC signature
- `X-GitHub-Event`: Event type

**Response:**
```json
{
  "status": "ok"
}
```

### `GET /health`

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "queue_depth": 3,
  "version": "0.1.0"
}
```

## Redis Schema

```
# Quota tracking (expires after 2 days)
scan_count:{installation_id}:{YYYY-MM-DD} -> int

# Tier management
installation_tier:{installation_id} -> "free" | "pro"

# Queue (sorted set by priority score)
scan_queue -> sorted set of job IDs

# Job data (expires after 24 hours)
job:{job_id} -> JSON {
  "job_id": "uuid",
  "installation_id": 123,
  "repo_full_name": "owner/repo",
  "pr_number": 42,
  "file_paths": ["file1.py", "file2.js"],
  "tier": "free",
  "status": "queued|processing|completed|failed",
  "queued_at": "ISO timestamp",
  ...
}
```

## Testing

### Manual Testing

1. Install GitHub App on a test repository
2. Open a Pull Request
3. Check webhook receives event:
   ```bash
   # View logs
   tail -f webhook.log
   ```
4. Verify comment posted with quota info

### Test Quota Limits

```python
from impact_scan.github_app import TierManager

tier_mgr = TierManager()

# Check quota
info = tier_mgr.get_tier_info(installation_id=12345)
print(f"Scans today: {info.scans_today}/{info.daily_limit}")

# Simulate scans
for i in range(26):
    count = tier_mgr.increment_scan_count(12345)
    print(f"Scan #{count}")
    info = tier_mgr.get_tier_info(12345)
    print(f"Can scan: {info.can_scan}")
```

## Deployment

See `DEPLOYMENT.md` for production deployment guide (Docker Compose, Nginx, SSL, monitoring).

## License

MIT

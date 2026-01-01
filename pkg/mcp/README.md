# TruffleHog MCP Server

> Expose TruffleHog's secret scanning capabilities to AI assistants via the Model Context Protocol (MCP).

This integration allows AI assistants like Claude to directly scan code, files, and repositories for leaked credentials during conversations—enabling interactive security workflows, real-time incident response, and automated security audits.

## What is MCP?

The [Model Context Protocol](https://modelcontextprotocol.io/) is an open standard that allows AI assistants to interact with external tools and data sources. By running TruffleHog as an MCP server, AI assistants can:

- Scan text, files, directories, and git repositories for secrets
- Verify if discovered secrets are still active
- Get detailed information about 800+ secret types
- Provide contextual remediation guidance

## Quick Start

### 1. Build TruffleHog with MCP support

```bash
git clone https://github.com/postrv/trufflehog-with-mcp.git
cd trufflehog-with-mcp
go build -o trufflehog .
```

### 2. Configure your MCP client

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "trufflehog": {
      "command": "/path/to/trufflehog",
      "args": ["mcp"]
    }
  }
}
```

Or for Claude Code (`~/.claude/claude_code.json`):

```json
{
  "mcpServers": {
    "trufflehog": {
      "command": "/path/to/trufflehog",
      "args": ["mcp", "--no-verify"]
    }
  }
}
```

### 3. Restart your AI assistant

The TruffleHog tools will now be available in your conversations.

## Available Tools

| Tool | Description |
|------|-------------|
| `list_detectors` | List all 800+ available secret detector types |
| `get_detector_info` | Get detailed information about a specific detector |
| `scan_text` | Scan arbitrary text content for secrets |
| `scan_file` | Scan a local file for secrets |
| `scan_directory` | Scan a directory recursively for secrets |
| `scan_git_repo` | Scan git repository history for secrets |
| `verify_secret` | Verify if a specific secret is still active |

## Use Cases

### 1. Real-Time Incident Response

When a potential secret leak is discovered, the AI assistant can immediately investigate:

```
User: "Someone posted this config file in Slack. Is it safe?"

AI: [scans the pasted content]
    Found 2 secrets:
    - AWS Access Key (VERIFIED ACTIVE) - needs immediate rotation
    - Stripe Test Key (not production) - low priority

    Immediate actions for the AWS key:
    1. Go to IAM Console → Users → Security Credentials
    2. Create new access key
    3. Update your application configuration
    4. Delete the compromised key
    5. Check CloudTrail for unauthorized API calls
```

### 2. Pre-Commit Security Review

Before merging code, ask the AI to scan for secrets:

```
User: "Can you check this PR for secrets before I merge?"

AI: [scans the changed files]
    Found 1 issue in config/database.yml line 23:
    - Database password hardcoded

    Recommendation: Move to environment variable or use a secrets manager.
    Here's how to fix it: [provides code example]
```

### 3. Security Audits

Scan entire repositories and get prioritized findings:

```
User: "Scan our main repo for any leaked credentials"

AI: [scans git history]
    Found 15 potential secrets across 47 commits:

    HIGH PRIORITY (verified active):
    - AWS key in deploy.sh (committed March 15)
    - GitHub token in .env.example

    MEDIUM (unverified):
    - 3 API keys in test fixtures

    LOW (likely false positives):
    - 10 example/placeholder values
```

### 4. Secret Classification

Identify unknown credential types:

```
User: "What kind of secret is this: xoxb-123456789..."

AI: [looks up detector info]
    This is a Slack Bot Token. It provides:
    - Read access to channels the bot is in
    - Ability to post messages as the bot
    - Access to user directory information

    To rotate: api.slack.com → Your Apps → OAuth & Permissions → Regenerate
```

### 5. Blast Radius Assessment

Understand the scope of a leak:

```
User: "We found a leaked AWS key. How bad is it?"

AI: [scans full git history]
    Timeline:
    - First committed: March 15, 2024 in commit abc123
    - Present in 47 commits across 3 branches
    - Also found in 5 other files
    - Removed from main branch: April 2, 2024

    The key was exposed in public history for 18 days.
    Recommend: Check AWS CloudTrail for this period.
```

### 6. Developer Education

Learn about secure practices through conversation:

```
User: "Why did the scanner flag this line? It's not a real secret."

AI: [explains the detection]
    The pattern `AKIA[0-9A-Z]{16}` matched because it looks like
    an AWS Access Key ID format.

    This is a false positive because it's in a test file with
    a placeholder value. You can:
    1. Add a trufflehog:ignore comment
    2. Use obviously fake values like AKIAIOSFODNN7EXAMPLE
    3. Configure detector exclusions
```

## CLI Options

```bash
trufflehog mcp [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--concurrency` | CPU count | Number of concurrent workers |
| `--no-verify` | false | Disable secret verification (faster, no network calls) |
| `--max-results` | 1000 | Maximum results per scan |
| `--timeout` | 5m | Scan timeout duration |

### Examples

```bash
# Run with verification disabled (faster for large scans)
trufflehog mcp --no-verify

# Run with limited concurrency
trufflehog mcp --concurrency 4

# Run with higher result limit
trufflehog mcp --max-results 5000
```

## Tool Reference

### list_detectors

List all available secret detector types.

**Parameters:**
- `filter` (optional): Substring to filter detector names

**Example response:**
```json
{
  "detectors": ["AWS", "GitHub", "Stripe", "Slack", ...],
  "total": 847
}
```

### get_detector_info

Get detailed information about a specific detector.

**Parameters:**
- `detector_type` (required): Detector name (e.g., "AWS", "GitHub")

**Example response:**
```json
{
  "name": "AWS",
  "description": "AWS Access Key ID and Secret Access Key",
  "keywords": ["AKIA", "aws_access_key", "aws_secret"],
  "supports_verification": true
}
```

### scan_text

Scan arbitrary text for secrets.

**Parameters:**
- `text` (required): Text content to scan
- `verify` (optional, default: true): Verify found secrets
- `include_detectors` (optional): Only use these detectors
- `exclude_detectors` (optional): Exclude these detectors

### scan_file

Scan a local file for secrets.

**Parameters:**
- `path` (required): Absolute path to file
- `verify` (optional, default: true): Verify found secrets
- `include_detectors` / `exclude_detectors` (optional)

### scan_directory

Scan a directory recursively for secrets.

**Parameters:**
- `path` (required): Absolute path to directory
- `verify` (optional, default: true): Verify found secrets
- `include_detectors` / `exclude_detectors` (optional)

### scan_git_repo

Scan git repository history for secrets.

**Parameters:**
- `uri` (required): Git repository URI (local path or remote URL)
- `branch` (optional): Specific branch to scan
- `since_commit` (optional): Only scan commits after this hash
- `max_depth` (optional): Maximum commit depth (0 = unlimited)
- `verify` (optional, default: true): Verify found secrets
- `include_detectors` / `exclude_detectors` (optional)

### verify_secret

Verify if a specific secret is valid and active.

**Parameters:**
- `detector_type` (required): Detector type (e.g., "AWS", "GitHub")
- `secret` (required): Secret value to verify
- `extra_data` (optional): Additional data for multi-part secrets

**Example:**
```json
{
  "detector_type": "AWS",
  "secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "extra_data": "AKIAIOSFODNN7EXAMPLE"
}
```

## Response Format

All scan tools return results in this format:

```json
{
  "results": [
    {
      "detector_type": "AWS",
      "decoder_type": "PLAIN",
      "verified": true,
      "raw": "[REDACTED]",
      "raw_v2": "[REDACTED]",
      "redacted": "AKIA****EXAMPLE",
      "extra_data": {
        "account": "123456789012",
        "resource_type": "Access key"
      },
      "source_metadata": {
        "file": "config/aws.yml",
        "line": 42
      }
    }
  ],
  "summary": {
    "chunks_scanned": 150,
    "bytes_scanned": 45000,
    "verified_secrets": 2,
    "unverified_secrets": 5,
    "duration": "1.234s",
    "total_results": 7,
    "truncated": false
  }
}
```

## Security Considerations

1. **Verification makes network calls**: When `verify` is enabled, TruffleHog attempts to authenticate with the secret. Disable with `--no-verify` if you don't want this.

2. **File access**: The `scan_file` and `scan_directory` tools require absolute paths and validate that paths exist before scanning.

3. **Git repository access**: Remote repositories may require authentication. Currently only unauthenticated access is supported.

4. **Result limits**: To prevent memory issues, results are capped at `--max-results` (default 1000).

## Architecture

```
pkg/mcp/
├── server.go              # MCP server setup and tool registration
├── config.go              # Server configuration
├── tools/
│   ├── list_detectors.go  # Detector listing tool
│   ├── get_detector_info.go # Detector info tool
│   ├── scan_text.go       # Text scanning tool
│   ├── scan_file.go       # File scanning tool
│   ├── scan_directory.go  # Directory scanning tool
│   ├── scan_git.go        # Git repository scanning tool
│   └── verify_secret.go   # Secret verification tool
└── internal/
    ├── scanner.go         # TruffleHog engine wrapper
    ├── result_collector.go # Collects scan results
    ├── detector_registry.go # Detector metadata
    ├── bytes_source.go    # In-memory source for text scanning
    └── types.go           # Shared types
```

## Contributing

Contributions are welcome! Some ideas for improvements:

- [ ] Authentication support for private git repositories
- [ ] Cloud source scanning (S3, GCS, Azure Blob)
- [ ] MCP Resources for browsable detector catalog
- [ ] MCP Prompts for common security workflows
- [ ] Progress reporting for long-running scans
- [ ] Remediation guidance tool
- [ ] SARIF export format

## License

This project is licensed under the AGPL-3.0 License - see the [LICENSE](../../LICENSE) file for details.

## Acknowledgments

- [TruffleHog](https://github.com/trufflesecurity/trufflehog) by Truffle Security
- [mcp-go](https://github.com/mark3labs/mcp-go) MCP SDK for Go
- [Model Context Protocol](https://modelcontextprotocol.io/) specification

# Operations Guide

Operational guidance for running mcp-protector in production environments.

## File permissions

The configuration file may contain a bearer token in plaintext. Restrict read access to the process owner:

```bash
chmod 600 config.toml
```

Verify with:

```bash
ls -la config.toml
# -rw------- 1 mcp-protector mcp-protector 312 Feb 20 10:00 config.toml
```

## Configuration lifecycle

mcp-protector reads the configuration file **once at startup**. There is no hot-reload. To apply configuration changes:

1. Stop the process (SIGTERM or Ctrl-C)
2. Edit `config.toml`
3. Validate: `mcp-protector validate-config --config config.toml`
4. Restart the process

## Bearer token rotation

To rotate an upstream bearer token with minimal downtime:

1. Obtain the new token from the upstream service
2. Stop mcp-protector (SIGTERM — the process drains in-flight requests and flushes audit logs before exiting)
3. Update the `token` field in `config.toml`
4. Set file permissions: `chmod 600 config.toml`
5. Restart mcp-protector

There is no way to rotate the token without a restart.

## systemd unit file

Example unit file for running mcp-protector as a system service:

```ini
[Unit]
Description=mcp-protector MCP security proxy
After=network.target

[Service]
Type=simple
User=mcp-protector
Group=mcp-protector
ExecStart=/usr/local/bin/mcp-protector proxy --config /etc/mcp-protector/config.toml
Restart=on-failure
RestartSec=5s

# Redirect audit log (stdout in HTTP mode) to a file
StandardOutput=append:/var/log/mcp-protector/audit.log
StandardError=journal

# Harden the service
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/mcp-protector

[Install]
WantedBy=multi-user.target
```

Install and enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable mcp-protector
sudo systemctl start mcp-protector
```

View logs:

```bash
# Tracing output (stderr → journal)
journalctl -u mcp-protector -f

# Audit log (stdout → file)
tail -f /var/log/mcp-protector/audit.log | jq .
```

## Docker / container deployments

Pass the configuration file via a volume mount or Docker secret — **not** via environment variables (mcp-protector does not read config from the environment).

```dockerfile
# Dockerfile example
FROM debian:bookworm-slim
COPY mcp-protector /usr/local/bin/
ENTRYPOINT ["mcp-protector", "proxy", "--config", "/config/config.toml"]
```

```bash
docker run \
  -v /path/to/config:/config:ro \
  -p 3000:3000 \
  mcp-protector-image
```

For Kubernetes, use a `Secret` mounted as a volume:

```yaml
volumes:
  - name: mcp-config
    secret:
      secretName: mcp-protector-config
containers:
  - name: mcp-protector
    image: mcp-protector:latest
    args: ["proxy", "--config", "/config/config.toml"]
    volumeMounts:
      - name: mcp-config
        mountPath: /config
        readOnly: true
    readinessProbe:
      httpGet:
        path: /health
        port: 3000
      initialDelaySeconds: 5
      periodSeconds: 10
```

The `/health` endpoint returns 200 once the upstream MCP handshake completes, making it suitable for Kubernetes readiness probes. See [`agent-integration.md`](agent-integration.md#health-checks) for details.

## Logging and audit log rotation

In HTTP mode, audit logs are written to stdout as JSON-Lines. Use a process manager or container runtime to handle rotation.

With systemd (as shown above), `StandardOutput=append:/var/log/mcp-protector/audit.log` writes audit entries to a file. Rotate with logrotate:

```
/var/log/mcp-protector/audit.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        # mcp-protector does not reopen stdout on signal; restart to pick up new file
        systemctl restart mcp-protector
    endscript
}
```

## Monitoring

Key signals to monitor:

| Signal | Source | Meaning |
|--------|--------|---------|
| Exit code 1 | Process exit | Configuration error — check stderr |
| Exit code 2 | Process exit | Runtime error — check tracing logs |
| `warn` log: "audit log channel full" | Tracing stderr | Audit consumer too slow; entries dropped |
| `GET /health` → 503 | HTTP | Upstream not yet connected or connection failed |
| `GET /health` → 200 | HTTP | Proxy ready |

# mcp-securitytrails

SecurityTrails MCP — wraps SecurityTrails API (securitytrails.com)

Part of [Pipeworx](https://pipeworx.io) — an MCP gateway connecting AI agents to 1394+ live data sources.

## Tools

| Tool | Description |
|------|-------------|
| `securitytrails_domain` | Domain intel (DNS, subdomain count) for <hostname>. Returns current A/MX/NS records, subdomain count, and Alexa rank. Example: securitytrails_domain({ hostname: "github.com", _apiKey: "your-key" }) |
| `securitytrails_subdomains` | Enumerate subdomains of <hostname>. Returns the subdomain labels plus fully-qualified domains. Example: securitytrails_subdomains({ hostname: "github.com", _apiKey: "your-key" }) |
| `securitytrails_dns_history` | Historical DNS records for <hostname>. Returns past record values with first/last-seen dates for a given record type (a, aaaa, mx, ns, soa, txt). Example: securitytrails_dns_history({ hostname: "github.com", type: "a", _apiKey: "your-key" }) |
| `securitytrails_whois` | WHOIS for <hostname>. Returns registrar, creation/expiration dates, and registration contacts. Example: securitytrails_whois({ hostname: "github.com", _apiKey: "your-key" }) |

## Quick Start

Add to your MCP client (Claude Desktop, Cursor, Windsurf, etc.):

```json
{
  "mcpServers": {
    "securitytrails": {
      "url": "https://gateway.pipeworx.io/securitytrails/mcp"
    }
  }
}
```

Or connect to the full Pipeworx gateway for access to all 1394+ data sources:

```json
{
  "mcpServers": {
    "pipeworx": {
      "url": "https://gateway.pipeworx.io/mcp"
    }
  }
}
```

## Using with ask_pipeworx

Instead of calling tools directly, you can ask questions in plain English:

```
ask_pipeworx({ question: "your question about Securitytrails data" })
```

The gateway picks the right tool and fills the arguments automatically.

## More

- [Docs and guides](https://pipeworx.io/docs)
- [pipeworx.io](https://pipeworx.io)

## License

MIT

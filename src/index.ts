interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
  };
}

interface McpToolExport {
  tools: McpToolDefinition[];
  callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>;
  meter?: { credits: number };
  cost?: Record<string, unknown>;
  provider?: string;
}

/**
 * SecurityTrails MCP — wraps SecurityTrails API (securitytrails.com)
 *
 * Passive DNS intelligence: domain details, subdomain enumeration,
 * historical DNS records, and WHOIS lookups.
 *
 * Tools:
 * - securitytrails_domain: domain intel (current DNS, subdomain count)
 * - securitytrails_subdomains: enumerate subdomains of a hostname
 * - securitytrails_dns_history: historical DNS records by type
 * - securitytrails_whois: WHOIS registration data
 *
 * Requires a SecurityTrails API key via the `_apiKey` parameter, sent as
 * the `APIKEY` request header. Free tier is 50 lookups/month.
 */


const BASE_URL = 'https://api.securitytrails.com/v1';

const tools: McpToolExport['tools'] = [
  {
    name: 'securitytrails_domain',
    description:
      'Domain intel (DNS, subdomain count) for <hostname>. Returns current A/MX/NS records, subdomain count, and Alexa rank. Example: securitytrails_domain({ hostname: "github.com", _apiKey: "your-key" })',
    inputSchema: {
      type: 'object',
      properties: {
        hostname: {
          type: 'string',
          description: 'Apex domain / hostname, e.g. "github.com"',
        },
        _apiKey: {
          type: 'string',
          description: 'SecurityTrails API key (get one free at securitytrails.com — 50 lookups/mo)',
        },
      },
      required: ['hostname', '_apiKey'],
    },
  },
  {
    name: 'securitytrails_subdomains',
    description:
      'Enumerate subdomains of <hostname>. Returns the subdomain labels plus fully-qualified domains. Example: securitytrails_subdomains({ hostname: "github.com", _apiKey: "your-key" })',
    inputSchema: {
      type: 'object',
      properties: {
        hostname: {
          type: 'string',
          description: 'Apex domain / hostname to enumerate, e.g. "github.com"',
        },
        _apiKey: {
          type: 'string',
          description: 'SecurityTrails API key',
        },
      },
      required: ['hostname', '_apiKey'],
    },
  },
  {
    name: 'securitytrails_dns_history',
    description:
      'Historical DNS records for <hostname>. Returns past record values with first/last-seen dates for a given record type (a, aaaa, mx, ns, soa, txt). Example: securitytrails_dns_history({ hostname: "github.com", type: "a", _apiKey: "your-key" })',
    inputSchema: {
      type: 'object',
      properties: {
        hostname: {
          type: 'string',
          description: 'Apex domain / hostname, e.g. "github.com"',
        },
        type: {
          type: 'string',
          description: 'DNS record type: a, aaaa, mx, ns, soa, or txt (default "a")',
          enum: ['a', 'aaaa', 'mx', 'ns', 'soa', 'txt'],
        },
        _apiKey: {
          type: 'string',
          description: 'SecurityTrails API key',
        },
      },
      required: ['hostname', '_apiKey'],
    },
  },
  {
    name: 'securitytrails_whois',
    description:
      'WHOIS for <hostname>. Returns registrar, creation/expiration dates, and registration contacts. Example: securitytrails_whois({ hostname: "github.com", _apiKey: "your-key" })',
    inputSchema: {
      type: 'object',
      properties: {
        hostname: {
          type: 'string',
          description: 'Apex domain / hostname, e.g. "github.com"',
        },
        _apiKey: {
          type: 'string',
          description: 'SecurityTrails API key',
        },
      },
      required: ['hostname', '_apiKey'],
    },
  },
];

// Shared GET helper — SecurityTrails authenticates via the `APIKEY` header
// (literally named "APIKEY", not "Authorization"). Free tier is 50/mo so 429
// is common; surface it (and 401 auth failures) as actionable messages.
async function stGet(
  path: string,
  params: Record<string, string>,
  apiKey: string,
  tool: string,
): Promise<any> {
  const qs = new URLSearchParams(params).toString();
  const url = `${BASE_URL}${path}${qs ? `?${qs}` : ''}`;
  const res = await fetch(url, { headers: { APIKEY: apiKey } });

  if (res.status === 401) {
    throw new Error(
      `SecurityTrails ${tool}: unauthorized (HTTP 401) — check your SecurityTrails _apiKey.`,
    );
  }
  if (res.status === 429) {
    throw new Error(
      `SecurityTrails ${tool}: rate limited (HTTP 429). The free tier is 50/mo — wait for the quota to reset or upgrade your plan.`,
    );
  }
  if (!res.ok) {
    throw new Error(`SecurityTrails ${tool} error: HTTP ${res.status}`);
  }

  return res.json();
}

function requireHostname(args: Record<string, unknown>, tool: string): string {
  const hostname = args.hostname as string | undefined;
  if (!hostname) {
    throw new Error(
      `SecurityTrails ${tool} requires a hostname (e.g. "github.com"). Pass via the \`hostname\` argument.`,
    );
  }
  return hostname;
}

async function callTool(name: string, args: Record<string, unknown>): Promise<unknown> {
  const apiKey = args._apiKey as string | undefined;
  delete args._apiKey;

  if (!apiKey) {
    throw new Error(
      'SecurityTrails requires an API key. Pass your key via `_apiKey` — get one free at securitytrails.com (50 lookups/month).',
    );
  }

  switch (name) {
    case 'securitytrails_domain':
      return domainIntel(requireHostname(args, 'securitytrails_domain'), apiKey);
    case 'securitytrails_subdomains':
      return subdomains(requireHostname(args, 'securitytrails_subdomains'), apiKey);
    case 'securitytrails_dns_history':
      return dnsHistory(
        requireHostname(args, 'securitytrails_dns_history'),
        (args.type as string | undefined) || 'a',
        apiKey,
      );
    case 'securitytrails_whois':
      return whois(requireHostname(args, 'securitytrails_whois'), apiKey);
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// Summarize a nested current_dns record group (e.g. current_dns.a.values[])
// down to an array of the underlying values (IPs / hostnames).
function dnsValues(group: any): unknown[] {
  const values = group?.values;
  if (!Array.isArray(values)) return [];
  return values.map((v: any) => v?.ip ?? v?.hostname ?? v?.value ?? v);
}

async function domainIntel(hostname: string, apiKey: string) {
  const data = await stGet(`/domain/${encodeURIComponent(hostname)}`, {}, apiKey, 'securitytrails_domain');
  const currentDns = data?.current_dns ?? {};

  return {
    hostname: data?.hostname ?? hostname,
    apex_domain: data?.apex_domain,
    subdomain_count: data?.subdomain_count,
    current_dns: {
      a: dnsValues(currentDns.a),
      mx: dnsValues(currentDns.mx),
      ns: dnsValues(currentDns.ns),
    },
    alexa_rank: data?.alexa_rank,
  };
}

async function subdomains(hostname: string, apiKey: string) {
  const data = await stGet(
    `/domain/${encodeURIComponent(hostname)}/subdomains`,
    { children_only: 'false' },
    apiKey,
    'securitytrails_subdomains',
  );
  const subs: string[] = Array.isArray(data?.subdomains) ? data.subdomains : [];

  return {
    hostname,
    subdomain_count: data?.subdomain_count ?? subs.length,
    subdomains: subs.slice(0, 200),
    full_domains: subs.slice(0, 200).map((s) => `${s}.${hostname}`),
  };
}

async function dnsHistory(hostname: string, type: string, apiKey: string) {
  const data = await stGet(
    `/history/${encodeURIComponent(hostname)}/dns/${encodeURIComponent(type)}`,
    {},
    apiKey,
    'securitytrails_dns_history',
  );
  const records: any[] = Array.isArray(data?.records) ? data.records : [];

  return {
    hostname,
    type,
    count: records.length,
    records: records.slice(0, 50).map((r) => ({
      values: r?.values,
      first_seen: r?.first_seen,
      last_seen: r?.last_seen,
      organizations: r?.organizations,
    })),
  };
}

async function whois(hostname: string, apiKey: string) {
  const data = await stGet(`/domain/${encodeURIComponent(hostname)}/whois`, {}, apiKey, 'securitytrails_whois');
  const result = data?.result ?? data ?? {};
  const contacts: any[] = Array.isArray(result?.contacts) ? result.contacts : [];

  return {
    hostname,
    registrar: result?.registrarName,
    created: result?.createdDate,
    expires: result?.expiresDate,
    contacts: contacts.slice(0, 3),
  };
}

export default { tools, callTool, meter: { credits: 1 } } satisfies McpToolExport;

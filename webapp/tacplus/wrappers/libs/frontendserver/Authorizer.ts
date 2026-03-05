// Copyright (c) 2024 Second Star Cavalier, LLC.

/**
 * Authorizer performs rule-based authorization for requests.
 *
 * Rules are processed in key order (lowest first):
 *   ACTION_DENY (2)    — request denied, processing stops.
 *   ACTION_PERMIT (1)  — request permitted, processing stops.
 *   ACTION_CONTINUE (3) — processing continues to the next rule.
 * If no rule permits, the request is implicitly denied.
 */

interface AuthRule {
  action: number; // 1 = PERMIT, 2 = DENY, 3 = CONTINUE
  issuer: string;
  serviceName: string;
  audience: string;
  method: string;
  tenantId: string;
  tenantMask: string;
}

interface AuthConfig {
  rules?: Record<number, AuthRule>;
  includeRequest?: boolean;
}

interface SortedRule {
  key: number;
  rule: AuthRule;
}

export class Authorizer {
  private sortedRules: SortedRule[];

  constructor(config: any) {
    if (config?.disableAuth || config?.disable_auth) {
      this.sortedRules = [];
      return;
    }
    const rulesMap = config?.authRules || config?.auth_rules || {};

    // Sort rules by map key (numeric order)
    this.sortedRules = Object.entries(rulesMap)
      .map(([key, rule]) => ({ key: Number(key), rule: rule as AuthRule }))
      .sort((a, b) => a.key - b.key);

    // Strip leading / from method values
    for (const sr of this.sortedRules) {
      if (sr.rule.method && sr.rule.method.startsWith("/")) {
        sr.rule.method = sr.rule.method.substring(1);
      }
    }

    // Validate: at least one rule must have ACTION_PERMIT
    if (this.sortedRules.length > 0) {
      const hasPermit = this.sortedRules.some((sr) => sr.rule.action === 1);
      if (!hasPermit) {
        throw new Error(
          "auth config invalid: no rule with ACTION_PERMIT — all requests would be denied",
        );
      }
    }
  }

  /**
   * Authorizes a request by evaluating rules in key order.
   */
  async authorize(
    metadata: Record<string, string>,
    fullMethod: string,
  ): Promise<void> {
    if (this.sortedRules.length === 0) {
      return;
    }

    // Strip leading /
    if (fullMethod.startsWith("/")) {
      fullMethod = fullMethod.substring(1);
    }

    const { service, method } = parseFullMethod(fullMethod);
    const claims = parseJwtClaims(metadata["authorization"] || "");

    for (const sr of this.sortedRules) {
      if (!ruleMatches(sr.rule, service, method, claims, fullMethod)) {
        continue;
      }
      switch (sr.rule.action) {
        case 2: // DENY
          throw new Error("authorization denied");
        case 1: // PERMIT
          return;
        case 3: // CONTINUE
          continue;
      }
    }

    // Implicit deny
    throw new Error("authorization denied");
  }

  close(): void {
    // No resources to clean up for rule-based auth
  }
}

function parseFullMethod(fullMethod: string): {
  service: string;
  method: string;
} {
  const lastSlash = fullMethod.lastIndexOf("/");
  if (lastSlash >= 0) {
    return {
      service: fullMethod.substring(0, lastSlash),
      method: fullMethod.substring(lastSlash + 1),
    };
  }
  return { service: fullMethod, method: "" };
}

/**
 * Checks if a rule's method pattern matches the full method.
 * "*" matches everything, "prefix/*" matches prefix, otherwise exact match.
 */
function methodMatches(ruleMethod: string, fullMethod: string): boolean {
  if (ruleMethod === "*") return true;
  if (ruleMethod.endsWith("*")) {
    const prefix = ruleMethod.substring(0, ruleMethod.length - 1);
    return fullMethod.startsWith(prefix);
  }
  return ruleMethod === fullMethod;
}

function ruleMatches(
  rule: AuthRule,
  service: string,
  method: string,
  claims: Record<string, string>,
  fullMethod: string,
): boolean {
  // Method match (required, supports wildcards)
  let ruleMethod = rule.method || "";
  if (ruleMethod.startsWith("/")) ruleMethod = ruleMethod.substring(1);
  if (!methodMatches(ruleMethod, fullMethod)) return false;

  // Service name match
  if (rule.serviceName) {
    if (rule.serviceName.endsWith("/")) {
      if (!service.startsWith(rule.serviceName)) return false;
    } else if (service !== rule.serviceName) {
      return false;
    }
  }

  if (rule.issuer && (claims["iss"] || "") !== rule.issuer) return false;
  if (rule.audience && (claims["aud"] || "") !== rule.audience) return false;
  if (rule.tenantMask) {
    if (!tenantMatch(rule.tenantId, claims["tenant_id"] || "", rule.tenantMask))
      return false;
  }
  return true;
}

function tenantMatch(
  ruleTenant: string,
  reqTenant: string,
  mask: string,
): boolean {
  try {
    const m = hexToBytes(mask);
    const a = hexToBytes(ruleTenant.padEnd(m.length * 2, "0"));
    const b = hexToBytes(reqTenant.padEnd(m.length * 2, "0"));
    for (let i = 0; i < m.length; i++) {
      if ((a[i] & m[i]) !== (b[i] & m[i])) return false;
    }
    return true;
  } catch {
    return false;
  }
}

function hexToBytes(hex: string): number[] {
  const bytes: number[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substring(i, i + 2), 16));
  }
  return bytes;
}

function parseJwtClaims(authHeader: string): Record<string, string> {
  const claims: Record<string, string> = {};
  try {
    let token = authHeader;
    if (token.toLowerCase().startsWith("bearer ")) {
      token = token.substring(7);
    }
    const parts = token.split(".");
    if (parts.length < 2) return claims;

    const payload = Buffer.from(parts[1], "base64url").toString("utf-8");
    const parsed = JSON.parse(payload);
    for (const [key, value] of Object.entries(parsed)) {
      if (typeof value === "string") {
        claims[key] = value;
      } else if (value !== null && value !== undefined) {
        claims[key] = String(value);
      }
    }
  } catch {
    // Failed to parse JWT - return empty claims
  }
  return claims;
}

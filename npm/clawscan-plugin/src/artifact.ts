export type InstallFinding = {
  ruleId: string;
  severity: "info" | "warn" | "critical";
  file: string;
  line: number;
  message: string;
};

export type BeforeInstallResult = {
  findings?: InstallFinding[];
  block?: boolean;
  blockReason?: string;
};

const MAX_GATE_RULES = 100;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function scannerCompleted(value: unknown): value is Record<string, unknown> {
  return isRecord(value) && value.status === "completed" && cleanText(value.error, 1) === "";
}

function skillSpectorEvidenceUsable(raw: unknown): boolean {
  if (!isRecord(raw) || raw.execution_successful === false || cleanText(raw.error, 1) !== "") {
    return false;
  }
  const status = cleanText(raw.status, 40).toLowerCase();
  if (["benign", "safe", "clean", "suspicious", "malicious"].includes(status)) {
    return true;
  }
  const assessment = isRecord(raw.risk_assessment)
    ? raw.risk_assessment
    : isRecord(raw.riskAssessment)
      ? raw.riskAssessment
      : {};
  if (
    cleanText(raw.recommendation, 1) !== "" ||
    cleanText(assessment.recommendation, 1) !== "" ||
    typeof raw.score === "number" ||
    typeof assessment.score === "number"
  ) {
    return true;
  }
  return ["filtered_findings", "filteredFindings", "findings", "issues", "vulnerabilities"].some(
    (key) => Array.isArray(raw[key]),
  );
}

function scannerEvidenceUsable(scanner: string, result: Record<string, unknown>): boolean {
  if (scanner === "clawscan-static") {
    return (
      isRecord(result.raw) &&
      result.raw.schemaVersion === "clawscan-static-v1" &&
      Array.isArray(result.raw.findings)
    );
  }
  return scanner !== "skillspector" || skillSpectorEvidenceUsable(result.raw);
}

function cleanText(value: unknown, limit: number): string {
  if (typeof value !== "string") {
    return "";
  }
  return value
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, limit);
}

function cleanRuleSegment(value: unknown, fallback: string): string {
  const cleaned = cleanText(value, 64)
    .replace(/[^a-zA-Z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return cleaned || fallback;
}

function cleanFindingFile(value: unknown): string {
  const raw = cleanText(value, 1_000).replaceAll("\\", "/");
  const segments = raw
    .split("/")
    .filter((segment) => segment !== "" && segment !== "." && segment !== "..")
    .map((segment) =>
      segment
        .replace(/[^a-zA-Z0-9._ -]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .trim(),
    )
    .filter(Boolean);
  return segments.join("/").slice(0, 240) || ".";
}

function cleanFindingLine(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return 1;
  }
  return Math.min(1_000_000, Math.max(1, Math.trunc(value)));
}

function findingFromRule(rule: Record<string, unknown>): InstallFinding | undefined {
  if (
    typeof rule.scanner !== "string" ||
    typeof rule.rule !== "string" ||
    (rule.action !== "warn" && rule.action !== "block")
  ) {
    return undefined;
  }
  const scanner = cleanRuleSegment(rule.scanner, "unknown-scanner");
  const ruleName = cleanRuleSegment(rule.findingCode ?? rule.rule, "gate-rule");
  const title =
    cleanText(rule.findingTitle, 240) ||
    `${cleanText(rule.scanner, 80)} fired ${cleanText(rule.rule, 80)}`;
  const severity = cleanText(rule.findingSeverity, 40);
  return {
    ruleId: `clawscan/${scanner}/${ruleName}`,
    severity: rule.action === "block" ? "critical" : "warn",
    file: cleanFindingFile(rule.file),
    line: cleanFindingLine(rule.line),
    message: severity ? `${severity}: ${title}` : title,
  };
}

function ruleReferencesAvailableScanner(
  rule: Record<string, unknown>,
  scanners: Record<string, unknown>,
): boolean {
  return typeof rule.scanner === "string" && Object.hasOwn(scanners, rule.scanner);
}

function blockForInvalidArtifact(reason: string): BeforeInstallResult {
  return {
    block: true,
    blockReason: `ClawScan blocked installation: ${reason}`,
    findings: [
      {
        ruleId: "clawscan/artifact-invalid",
        severity: "critical",
        file: ".",
        line: 1,
        message: reason,
      },
    ],
  };
}

export function gateResultFromArtifact(
  stdout: string,
  requiredScanners: readonly string[],
): BeforeInstallResult | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return blockForInvalidArtifact("scanner output was not valid JSON");
  }

  if (!isRecord(parsed) || parsed.schemaVersion !== "clawscan-run-v1") {
    return blockForInvalidArtifact("scanner output was not a clawscan-run-v1 artifact");
  }
  if (!isRecord(parsed.scanners)) {
    return blockForInvalidArtifact("scanner artifact did not contain scanner results");
  }
  if (Object.keys(parsed.scanners).length === 0) {
    return blockForInvalidArtifact("scanner artifact did not contain any scanner results");
  }
  for (const scanner of requiredScanners) {
    const result = parsed.scanners[scanner];
    if (!scannerCompleted(result)) {
      return blockForInvalidArtifact(`required scanner ${scanner} did not complete`);
    }
    if (!scannerEvidenceUsable(scanner, result)) {
      return blockForInvalidArtifact(`required scanner ${scanner} returned unusable evidence`);
    }
  }
  for (const [scanner, result] of Object.entries(parsed.scanners)) {
    if (!scannerCompleted(result)) {
      const scannerName = cleanRuleSegment(scanner, "unknown-scanner");
      return blockForInvalidArtifact(`scanner ${scannerName} did not complete`);
    }
  }

  if (!Array.isArray(parsed.gateRules)) {
    return blockForInvalidArtifact("scanner artifact did not contain fired gate rules");
  }
  if (parsed.gateRules.length > MAX_GATE_RULES) {
    return blockForInvalidArtifact("scanner artifact contained too many fired gate rules");
  }
  if (parsed.gate === "pass") {
    if (parsed.gateRules.length !== 0) {
      return blockForInvalidArtifact("pass artifact unexpectedly contained fired gate rules");
    }
    return undefined;
  }
  if (parsed.gate === "warn") {
    const findings: InstallFinding[] = [];
    for (const rule of parsed.gateRules) {
      if (!isRecord(rule) || rule.action !== "warn") {
        return blockForInvalidArtifact("warn artifact contained an invalid fired gate rule");
      }
      if (!ruleReferencesAvailableScanner(rule, parsed.scanners)) {
        return blockForInvalidArtifact("fired gate rule referenced an unavailable scanner");
      }
      const finding = findingFromRule(rule);
      if (!finding) {
        return blockForInvalidArtifact("warn artifact contained an invalid fired gate rule");
      }
      findings.push(finding);
    }
    if (findings.length === 0) {
      return blockForInvalidArtifact("warn artifact did not contain a fired warning rule");
    }
    return { findings };
  }
  if (parsed.gate === "block") {
    const findings: InstallFinding[] = [];
    for (const rule of parsed.gateRules) {
      if (!isRecord(rule)) {
        return blockForInvalidArtifact("block artifact contained an invalid fired gate rule");
      }
      if (!ruleReferencesAvailableScanner(rule, parsed.scanners)) {
        return blockForInvalidArtifact("fired gate rule referenced an unavailable scanner");
      }
      const finding = findingFromRule(rule);
      if (!finding) {
        return blockForInvalidArtifact("block artifact contained an invalid fired gate rule");
      }
      findings.push(finding);
    }
    const blockingMessages = findings
      .filter((finding) => finding.severity === "critical")
      .map((finding) => finding.message);
    if (blockingMessages.length === 0) {
      return blockForInvalidArtifact("block artifact did not contain a fired blocking rule");
    }
    return {
      block: true,
      blockReason: cleanText(
        `ClawScan gate blocked installation: ${blockingMessages.join("; ")}`,
        1_000,
      ),
      findings,
    };
  }
  return blockForInvalidArtifact("scanner artifact contained an unknown gate verdict");
}

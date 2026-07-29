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
  return isRecord(value) && value.status === "completed";
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

function firstText(
  record: Record<string, unknown>,
  keys: readonly string[],
  limit: number,
): string {
  for (const key of keys) {
    const value = cleanText(record[key], limit);
    if (value !== "") {
      return value;
    }
  }
  return "";
}

function firstNumber(record: Record<string, unknown>, keys: readonly string[]): number {
  for (const key of keys) {
    if (typeof record[key] === "number") {
      return cleanFindingLine(record[key]);
    }
  }
  return 1;
}

function normalizeIdentifier(value: string): string {
  return value.trim().toUpperCase().replaceAll(" ", "_").replaceAll("-", "_");
}

function evidenceRecordsForRule(
  scanner: string,
  raw: unknown,
  rule: Record<string, unknown>,
): Record<string, unknown>[] {
  if (!isRecord(raw)) {
    return [];
  }
  const path = cleanText(rule.path, 240);
  const pathRoot = path.includes("[]") ? path.slice(0, path.indexOf("[]")) : "";
  const keys =
    scanner === "clawscan-static"
      ? ["findings"]
      : ["filtered_findings", "filteredFindings", "findings", "issues", "vulnerabilities"];
  const orderedKeys = pathRoot === "" ? keys : [pathRoot, ...keys.filter((key) => key !== pathRoot)];
  for (const key of orderedKeys) {
    const value = raw[key];
    if (Array.isArray(value)) {
      return value.filter(isRecord);
    }
  }
  return [];
}

function findingFromEvidence(
  rule: Record<string, unknown>,
  evidence: Record<string, unknown>,
): InstallFinding {
  const scanner = cleanRuleSegment(rule.scanner, "unknown-scanner");
  const evidenceId = firstText(evidence, ["id", "rule_id", "ruleId", "issueId", "code"], 64);
  const ruleName = cleanRuleSegment(evidenceId || rule.rule, "gate-rule");
  const title =
    firstText(evidence, ["title", "description", "explanation", "message"], 240) ||
    `${cleanText(rule.scanner, 80)} finding ${evidenceId || cleanText(rule.rule, 80)}`;
  const severity = firstText(evidence, ["severity", "risk_severity", "riskSeverity", "level"], 40);
  return {
    ruleId: `clawscan/${scanner}/${ruleName}`,
    severity: rule.action === "block" ? "critical" : "warn",
    file: cleanFindingFile(firstText(evidence, ["path", "file_path", "filePath", "file"], 1_000)),
    line: firstNumber(evidence, ["line", "start_line", "startLine"]),
    message: severity ? `${severity}: ${title}` : title,
  };
}

function findingFromRule(rule: Record<string, unknown>): InstallFinding {
  const scanner = cleanRuleSegment(rule.scanner, "unknown-scanner");
  const ruleName = cleanRuleSegment(rule.rule, "gate-rule");
  const path = cleanText(rule.path, 240);
  const value =
    rule.value === undefined ? "" : cleanText(JSON.stringify(rule.value), 120);
  const matched = path === "" ? "" : ` matched ${path}${value === "" ? "" : `=${value}`}`;
  const title = `${cleanText(rule.scanner, 80)} fired ${cleanText(rule.rule, 80)}${matched}`;
  return {
    ruleId: `clawscan/${scanner}/${ruleName}`,
    severity: rule.action === "block" ? "critical" : "warn",
    file: ".",
    line: 1,
    message: title,
  };
}

function findingsFromRule(
  rule: Record<string, unknown>,
  scanners: Record<string, unknown>,
): InstallFinding[] | undefined {
  if (
    typeof rule.scanner !== "string" ||
    typeof rule.rule !== "string" ||
    (rule.action !== "warn" && rule.action !== "block")
  ) {
    return undefined;
  }
  const scannerResult = scanners[rule.scanner];
  const raw = isRecord(scannerResult) ? scannerResult.raw : undefined;
  const expectedSeverity = typeof rule.value === "string" ? normalizeIdentifier(rule.value) : "";
  const evidence = evidenceRecordsForRule(rule.scanner, raw, rule).filter((entry) => {
    if (expectedSeverity === "") {
      return true;
    }
    const severity = firstText(
      entry,
      ["severity", "risk_severity", "riskSeverity", "level"],
      40,
    );
    return severity !== "" && normalizeIdentifier(severity) === expectedSeverity;
  });
  if (evidence.length === 0) {
    return [findingFromRule(rule)];
  }
  return evidence.map((entry) => findingFromEvidence(rule, entry));
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
      const ruleFindings = findingsFromRule(rule, parsed.scanners);
      if (!ruleFindings) {
        return blockForInvalidArtifact("warn artifact contained an invalid fired gate rule");
      }
      findings.push(...ruleFindings);
      findings.length = Math.min(findings.length, MAX_GATE_RULES);
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
      const ruleFindings = findingsFromRule(rule, parsed.scanners);
      if (!ruleFindings) {
        return blockForInvalidArtifact("block artifact contained an invalid fired gate rule");
      }
      findings.push(...ruleFindings);
      findings.length = Math.min(findings.length, MAX_GATE_RULES);
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

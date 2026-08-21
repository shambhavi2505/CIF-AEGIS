import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { redTeamTests as seededRedTeamTests } from "../src/data/redTeamData.js";

const here = dirname(fileURLToPath(import.meta.url));
const dataDirectory = join(here, "data");
mkdirSync(dataDirectory, { recursive: true });

export const databasePath = join(dataDirectory, "watchtower.db");
export const db = new DatabaseSync(databasePath);
db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    department TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS prompt_scans (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    prompt TEXT NOT NULL,
    sanitized_text TEXT,
    status TEXT NOT NULL,
    label TEXT NOT NULL,
    category TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    confidence REAL NOT NULL,
    policy TEXT NOT NULL,
    response TEXT NOT NULL,
    detected_department TEXT NOT NULL DEFAULT 'General',
    incident_id TEXT,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    scenario_key TEXT NOT NULL,
    scan_id TEXT REFERENCES prompt_scans(id),
    user_id TEXT REFERENCES users(id),
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'UNREVIEWED',
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS red_team_runs (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    total_tests INTEGER NOT NULL DEFAULT 0,
    passed_tests INTEGER NOT NULL DEFAULT 0,
    started_at TEXT NOT NULL,
    completed_at TEXT
  );
  CREATE TABLE IF NOT EXISTS red_team_tests (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    prompt TEXT NOT NULL,
    expected_action TEXT NOT NULL,
    is_threat INTEGER NOT NULL,
    direction TEXT NOT NULL DEFAULT 'INPUT',
    enabled INTEGER NOT NULL DEFAULT 1,
    source TEXT NOT NULL DEFAULT 'CUSTOM',
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS red_team_results (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES red_team_runs(id),
    test_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    passed INTEGER NOT NULL,
    outcome TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_scans_created ON prompt_scans(created_at);
  CREATE INDEX IF NOT EXISTS idx_scans_status ON prompt_scans(status);
  CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at);
  CREATE INDEX IF NOT EXISTS idx_results_run ON red_team_results(run_id);
`);

const scanColumns = db.prepare("PRAGMA table_info(prompt_scans)").all();
if (!scanColumns.some(column => column.name === "detected_department")) {
  db.exec("ALTER TABLE prompt_scans ADD COLUMN detected_department TEXT NOT NULL DEFAULT 'General'");
}
db.exec(`UPDATE prompt_scans SET detected_department = CASE
  WHEN lower(prompt) LIKE '%cvv%' OR lower(prompt) LIKE '%card number%' OR lower(prompt) LIKE '%pan %' OR lower(prompt) LIKE '%payment%' OR lower(prompt) LIKE '%bank%' OR lower(prompt) LIKE '%salary%' OR lower(prompt) LIKE '%tax%' THEN 'Finance'
  WHEN lower(prompt) LIKE '%api key%' OR lower(prompt) LIKE '%password%' OR lower(prompt) LIKE '%token%' OR lower(prompt) LIKE '%aws%' OR lower(prompt) LIKE '%database%' OR lower(prompt) LIKE '%server%' OR lower(prompt) LIKE '%github%' OR lower(prompt) LIKE '%jailbreak%' THEN 'IT'
  WHEN lower(prompt) LIKE '%aadhaar%' OR lower(prompt) LIKE '%aadhar%' OR lower(prompt) LIKE '%employee%' OR lower(prompt) LIKE '%candidate%' OR lower(prompt) LIKE '%resume%' OR lower(prompt) LIKE '%onboarding%' THEN 'HR'
  WHEN lower(prompt) LIKE '%contract%' OR lower(prompt) LIKE '%legal%' OR lower(prompt) LIKE '%nda%' OR lower(prompt) LIKE '%compliance%' THEN 'Legal'
  WHEN lower(prompt) LIKE '%vendor%' OR lower(prompt) LIKE '%inventory%' OR lower(prompt) LIKE '%logistics%' OR lower(prompt) LIKE '%shipment%' THEN 'Operations'
  WHEN lower(prompt) LIKE '%campaign%' OR lower(prompt) LIKE '%marketing%' OR lower(prompt) LIKE '%advertisement%' OR lower(prompt) LIKE '%lead list%' THEN 'Marketing'
  ELSE 'General' END
  WHERE detected_department = 'General'`);

const now = () => new Date().toISOString();
<<<<<<< Updated upstream
const defaultUsers = [
  ["demo-user", "analyst@finserve-demo.in", "Demo Analyst", "Finance", "Security Analyst"],
  ["hr-user", "hr@finserve-demo.in", "HR Reviewer", "HR", "HR Manager"],
  ["engineering-user", "engineer@finserve-demo.in", "Demo Engineer", "Engineering", "Developer"],
=======

function hashPassword(password) { const salt = randomBytes(16).toString("hex"); return `${salt}:${scryptSync(String(password), salt, 64).toString("hex")}`; }
const defaultUsers = [
  ["demo-user", "user@finserve-demo.in", "Demo User", "Finance", "USER", "User@123"],
  ["admin-user", "admin@finserve-demo.in", "Security Admin", "Security", "ADMIN", "Admin@123"],
  ["user-hr", "hr@finserve-demo.in", "Priya Sharma", "HR", "USER", "Hr@1234"],
  ["user-it", "it@finserve-demo.in", "Rahul Mehta", "IT", "USER", "It@1234"],
  ["user-marketing", "marketing@finserve-demo.in", "Ananya Rao", "Marketing", "USER", "Marketing@1234"],
>>>>>>> Stashed changes
];
const insertUser = db.prepare("INSERT OR IGNORE INTO users (id,email,name,department,role,created_at) VALUES (?,?,?,?,?,?)");
for (const user of defaultUsers) insertUser.run(...user, now());
const insertRedTeamTest = db.prepare(`INSERT OR IGNORE INTO red_team_tests
  (id,name,category,severity,prompt,expected_action,is_threat,direction,enabled,source,created_at)
  VALUES (?,?,?,?,?,?,?,?,1,'SEEDED',?)`);
for (const test of seededRedTeamTests) {
  insertRedTeamTest.run(test.id, test.name, test.category, test.severity, test.prompt, test.expectedAction, test.isThreat ? 1 : 0, test.direction || "INPUT", now());
}
db.exec(`UPDATE red_team_tests SET expected_action = 'SANITIZE'
  WHERE source = 'SEEDED' AND id IN ('aadhaar-leakage','pan-leakage','vernacular-pii','sensitive-output')`);

export function getUser(id = "demo-user") {
  return db.prepare("SELECT * FROM users WHERE id = ?").get(id) || db.prepare("SELECT * FROM users LIMIT 1").get();
}

export function saveScan(scan, userId = "demo-user") {
<<<<<<< Updated upstream
  db.prepare(`INSERT INTO prompt_scans
    (id,user_id,prompt,sanitized_text,status,label,category,risk_score,confidence,policy,response,detected_department,incident_id,created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    scan.id, userId, scan.prompt, scan.sanitizedText, scan.status, scan.label,
    scan.category, scan.riskScore, scan.confidence, scan.policy, scan.response,
    scan.department, scan.incidentId, scan.inspectedAt
=======
  if (!scan) {
    throw new Error("Cannot save scan: scan object is missing.");
  }

  const id = scan.id || randomUUID();

  const prompt =
    typeof scan.prompt === "string"
      ? scan.prompt
      : typeof scan.extractedText === "string"
        ? scan.extractedText
        : "";

  if (!prompt.trim()) {
    throw new Error("Cannot save scan: document contains no text.");
  }

  const status = scan.status || "allowed";

  const sanitizedText =
    scan.sanitizedText == null
      ? null
      : String(scan.sanitizedText);

  // Never persist raw sensitive content in the DB. What we store depends
  // on outcome:
  // - blocked: sanitizedText isn't actually redacted for blocked requests
  //   (honeytoken/prompt-injection paths skip sanitize()), so it still
  //   contains raw text. Store a placeholder instead.
  // - cleaned: the already-redacted sanitizedText is safe to store.
  // - allowed: nothing was detected, so it's non-sensitive by definition.
  const safeToStore =
    status === "blocked"
      ? "[BLOCKED — CONTENT NOT STORED]"
      : sanitizedText == null
        ? ""
        : sanitizedText;

  const label = scan.label || "Allowed";
  const category = scan.category || "Business Request";

  const riskScore = Number.isFinite(Number(scan.riskScore))
    ? Number(scan.riskScore)
    : 5;

  const confidence = Number.isFinite(Number(scan.confidence))
    ? Number(scan.confidence)
    : 96;

  const policy =
    scan.policy || "Acceptable AI Usage";

  const response =
    scan.response ||
    "Your request passed all security checks and was processed successfully.";

  const department =
    scan.department || "General";

  const incidentId =
    scan.incidentId || null;

  const createdAt =
    scan.inspectedAt || now();

  db.prepare(`
    INSERT INTO prompt_scans
    (
      id,
      user_id,
      prompt,
      sanitized_text,
      status,
      label,
      category,
      risk_score,
      confidence,
      policy,
      response,
      detected_department,
      incident_id,
      source,
      created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    String(id),
    String(userId || "demo-user"),
    safeToStore,
    safeToStore,
    String(status),
    String(label),
    String(category),
    riskScore,
    confidence,
    String(policy),
    String(response),
    String(department),
    incidentId == null ? null : String(incidentId),
    String(scan.source || "chat"),
    String(createdAt)
>>>>>>> Stashed changes
  );
}

export function saveIncident(incident, scanId, userId = "demo-user") {
  db.prepare(`INSERT INTO incidents
    (id,scenario_key,scan_id,user_id,title,severity,category,status,payload_json,created_at,updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(
    incident.id, incident.scenarioKey, scanId, userId, incident.title, incident.severity,
    incident.category, "UNREVIEWED", JSON.stringify(incident), incident.createdAt, incident.createdAt
  );
}

export function listIncidents() {
<<<<<<< Updated upstream
  return db.prepare("SELECT * FROM incidents ORDER BY created_at DESC").all().map(row => ({
    ...JSON.parse(row.payload_json), id: row.id, reviewStatus: row.status, timestamp: new Date(row.created_at).toLocaleString("en-IN", { timeZone: "Asia/Kolkata" }),
  }));
}

export function updateIncidentStatus(id, status) {
  const result = db.prepare("UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?").run(status, now(), id);
=======
  const userRows = db
    .prepare("SELECT id, name, email, department FROM users")
    .all();

  const userMap = {};
  for (const u of userRows) {
    userMap[u.id] = {
      name: u.name,
      email: u.email,
      department: u.department,
    };
  }

  return db
    .prepare(
      "SELECT * FROM incidents ORDER BY created_at DESC"
    )
    .all()
    .map(row => {
      let payload = {};

      try {
        payload =
          JSON.parse(
            row.payload_json || "{}"
          );
      } catch {
        payload = {};
      }

      const mapped =
        buildIncidentUiMapping(
          {
            ...payload,
            id: row.id,
            title: payload.title || row.title,
            severity: payload.severity || row.severity,
            category: payload.category || row.category,
          },
          row.id
        );

      const triggeredBy =
        userMap[row.user_id] || null;

      return {
        ...mapped,
        id: row.id,
        reviewStatus: row.status,
        timestamp:
          new Date(row.created_at).toLocaleString(
            "en-IN",
            { timeZone: "Asia/Kolkata" }
          ),
        triggeredByUserId: row.user_id || null,
        triggeredByName: triggeredBy?.name || "Unknown User",
        triggeredByEmail: triggeredBy?.email || null,
        triggeredByDepartment: triggeredBy?.department || null,
      };
    });
}

export function updateIncidentStatus(
  id,
  status
) {
  const result =
    db
      .prepare(`
        UPDATE incidents
        SET
          status = ?,
          updated_at = ?
        WHERE id = ?
      `)
      .run(
        String(status),
        now(),
        String(id)
      );

>>>>>>> Stashed changes
  return result.changes > 0;
}

export function ensureRun(runId, totalTests) {
  db.prepare("INSERT OR IGNORE INTO red_team_runs (id,status,total_tests,started_at) VALUES (?,?,?,?)").run(runId, "RUNNING", totalTests, now());
}

function mapRedTeamTest(row) {
  return { id: row.id, name: row.name, category: row.category, severity: row.severity,
    prompt: row.prompt, expectedAction: row.expected_action, isThreat: Boolean(row.is_threat),
    direction: row.direction, enabled: Boolean(row.enabled), source: row.source, createdAt: row.created_at };
}

export function listRedTeamTests() {
  return db.prepare("SELECT * FROM red_team_tests WHERE enabled = 1 ORDER BY source DESC, created_at").all().map(mapRedTeamTest);
}

export function createRedTeamTest(input) {
  const test = { id: randomUUID(), name: input.name.trim(), category: input.category.trim(), severity: input.severity,
    prompt: input.prompt.trim(), expectedAction: input.expectedAction, isThreat: input.expectedAction !== "ALLOW",
    direction: input.direction || "INPUT", source: "CUSTOM", createdAt: now() };
  db.prepare(`INSERT INTO red_team_tests
    (id,name,category,severity,prompt,expected_action,is_threat,direction,enabled,source,created_at)
    VALUES (?,?,?,?,?,?,?,?,1,?,?)`).run(test.id, test.name, test.category, test.severity, test.prompt,
    test.expectedAction, test.isThreat ? 1 : 0, test.direction, test.source, test.createdAt);
  audit("RED_TEAM_TEST_CREATED", "red_team_test", test.id, { name: test.name, expectedAction: test.expectedAction });
  return test;
}

export function saveRedTeamResult(result) {
  db.prepare(`INSERT OR REPLACE INTO red_team_results
    (id,run_id,test_id,payload_json,passed,outcome,risk_score,created_at) VALUES (?,?,?,?,?,?,?,?)`).run(
    result.id, result.simulationRunId, result.testId, JSON.stringify(result), result.passed ? 1 : 0,
    result.outcome, result.riskScore, result.completedAt
  );
  const stats = db.prepare("SELECT COUNT(*) total, SUM(passed) passed FROM red_team_results WHERE run_id = ?").get(result.simulationRunId);
  db.prepare("UPDATE red_team_runs SET passed_tests = ?, status = CASE WHEN ? >= total_tests THEN 'COMPLETED' ELSE 'RUNNING' END, completed_at = CASE WHEN ? >= total_tests THEN ? ELSE NULL END WHERE id = ?")
    .run(Number(stats.passed || 0), Number(stats.total), Number(stats.total), now(), result.simulationRunId);
}

export function audit(eventType, entityType, entityId, payload = {}, actor = "demo-user") {
  db.prepare("INSERT INTO audit_events (id,event_type,entity_type,entity_id,actor,payload_json,created_at) VALUES (?,?,?,?,?,?,?)")
    .run(randomUUID(), eventType, entityType, entityId, actor, JSON.stringify(payload), now());
}

export function getAuditLog() {
  return db.prepare("SELECT * FROM audit_events ORDER BY created_at DESC LIMIT 250").all().map(row => ({
    id: row.id, type: row.event_type, entityType: row.entity_type, entityId: row.entity_id,
    actor: row.actor, ...JSON.parse(row.payload_json), at: row.created_at,
  }));
}

const CATEGORY_PENALTY_LAKH = {
  "Honeytoken": 10,
  "Sensitive Personal Data": 50,
  "Credentials": 15,
  "Personal Identity": 25,
  "AI Security": 8,
  "Financial Identity": 20,
  "Financial Data": 20,
  "Personal Contact Data": 5,
  "Safe Business Request": 0,
  "Business Confidential": 30,
};

function penaltyForCategory(category) {
  return CATEGORY_PENALTY_LAKH[category] ?? 3;
}

export function getDashboard() {
<<<<<<< Updated upstream
  const totals = db.prepare(`SELECT COUNT(*) scanned,
    SUM(CASE WHEN status='blocked' THEN 1 ELSE 0 END) blocked,
    SUM(CASE WHEN status='cleaned' THEN 1 ELSE 0 END) sanitized,
    AVG(risk_score) average_risk FROM prompt_scans`).get();
  const redTeam = db.prepare("SELECT COUNT(*) total, SUM(passed) passed FROM red_team_results").get();
  const departments = db.prepare(`SELECT detected_department department, COUNT(*) scans,
    ROUND(AVG(risk_score)) score,
    SUM(CASE WHEN status='blocked' THEN 1 ELSE 0 END) blocked,
    SUM(CASE WHEN status='cleaned' THEN 1 ELSE 0 END) sanitized
    FROM prompt_scans GROUP BY detected_department ORDER BY score DESC, scans DESC`).all();
  const categoryCounts = db.prepare("SELECT category name, COUNT(*) count FROM prompt_scans GROUP BY category ORDER BY count DESC").all();
  const recentEvents = db.prepare(`SELECT created_at, status FROM prompt_scans ORDER BY created_at DESC LIMIT 60`).all().reverse();
  const running = { allowed: 0, blocked: 0, sanitized: 0 };
  const hourlyActivity = recentEvents.map((event, index) => {
    if (event.status === "allowed") running.allowed += 1;
    if (event.status === "blocked") running.blocked += 1;
    if (event.status === "cleaned") running.sanitized += 1;
    const eventTime = new Date(event.created_at);
    return { time: `${eventTime.toLocaleTimeString("en-IN", { hour: "2-digit", minute: "2-digit" })} #${index + 1}`,
      allowed: running.allowed, blocked: running.blocked, sanitized: running.sanitized };
  });
  const dailyActivity = db.prepare(`SELECT substr(created_at,1,10) time,
    SUM(CASE WHEN status='allowed' THEN 1 ELSE 0 END) allowed,
    SUM(CASE WHEN status='blocked' THEN 1 ELSE 0 END) blocked,
    SUM(CASE WHEN status='cleaned' THEN 1 ELSE 0 END) sanitized
    FROM prompt_scans GROUP BY substr(created_at,1,10) ORDER BY time DESC LIMIT 30`).all().reverse();
  const activity = { "24H": hourlyActivity, "7D": dailyActivity.slice(-7), "30D": dailyActivity };
  const scanned = Number(totals.scanned || 0);
  const blocked = Number(totals.blocked || 0);
  const sanitized = Number(totals.sanitized || 0);
  const categories = categoryCounts.map(item => ({ name: item.name, value: scanned ? Math.round(Number(item.count) / scanned * 100) : 0 }));
  const securityScore = Number(redTeam.total || 0) ? Math.round(Number(redTeam.passed || 0) / Number(redTeam.total) * 100) : 100;
  return { kpis: { scanned, blocked, sanitized, securityScore, riskPrevented: `₹${((blocked * 2.5 + sanitized * 0.5) || 0).toFixed(1)}L` }, departments, categories, activity, generatedAt: now() };
}
=======
  const totals = db
    .prepare(`
      SELECT
        COUNT(*) AS scanned,
        SUM(
          CASE
            WHEN status = 'blocked'
            THEN 1
            ELSE 0
          END
        ) AS blocked,
        SUM(
          CASE
            WHEN status = 'cleaned'
            THEN 1
            ELSE 0
          END
        ) AS sanitized,
        AVG(risk_score) AS average_risk
      FROM prompt_scans
      WHERE source IN ('chat', 'document')
    `)
    .get();

  const scanned =
    Number(totals.scanned) || 0;

  const blocked =
    Number(totals.blocked) || 0;

  const sanitized =
    Number(totals.sanitized) || 0;

  const averageRisk =
    Number(totals.average_risk) || 0;

  const categoryLoss = db
    .prepare(`
      SELECT
        category,
        status,
        COUNT(*) AS count
      FROM prompt_scans
      WHERE source IN ('chat', 'document')
        AND status IN ('blocked', 'cleaned')
      GROUP BY category, status
    `)
    .all();

  const riskPreventedLakh = categoryLoss.reduce((sum, row) => {
    const base = penaltyForCategory(row.category);
    const multiplier = row.status === "blocked" ? 1 : 0.4;
    return sum + base * multiplier * Number(row.count);
  }, 0);

  const departments = db
    .prepare(`
      SELECT
        detected_department AS department,
        COUNT(*) AS scans,
        ROUND(AVG(risk_score)) AS score,
        SUM(
          CASE
            WHEN status = 'blocked'
            THEN 1
            ELSE 0
          END
        ) AS blocked,
        SUM(
          CASE
            WHEN status = 'cleaned'
            THEN 1
            ELSE 0
          END
        ) AS sanitized
      FROM prompt_scans
      WHERE source IN ('chat', 'document')
      GROUP BY detected_department
      ORDER BY score DESC, scans DESC
    `)
    .all()
    .map((row) => ({
      department: row.department,
      scans: Number(row.scans) || 0,
      score: Number(row.score) || 0,
      blocked: Number(row.blocked) || 0,
      sanitized: Number(row.sanitized) || 0,
    }));

  const categoryCounts = db
    .prepare(`
      SELECT
        category AS name,
        COUNT(*) AS count,
        ROUND(AVG(risk_score)) AS risk
      FROM prompt_scans
      WHERE source IN ('chat', 'document')
      GROUP BY category
      ORDER BY count DESC
    `)
    .all();

  const categories = categoryCounts.map(
    (item) => ({
      name: item.name,
      count: Number(item.count) || 0,
      value: scanned
        ? Math.round(
            (Number(item.count) / scanned) * 100
          )
        : 0,
      risk: Number(item.risk) || 0,
    })
  );

  const recentEvents = db
    .prepare(`
      SELECT
        created_at,
        status
      FROM prompt_scans
      WHERE source IN ('chat', 'document')
      ORDER BY created_at DESC
      LIMIT 60
    `)
    .all()
    .reverse();

  const running = {
    allowed: 0,
    blocked: 0,
    sanitized: 0,
  };

  const hourlyActivity = recentEvents.map(
    (event, index) => {
      if (event.status === "allowed") {
        running.allowed += 1;
      }

      if (event.status === "blocked") {
        running.blocked += 1;
      }

      if (event.status === "cleaned") {
        running.sanitized += 1;
      }

      const eventTime =
        new Date(event.created_at);

      return {
        time: `${eventTime.toLocaleTimeString(
          "en-IN",
          {
            hour: "2-digit",
            minute: "2-digit",
          }
        )} #${index + 1}`,
        allowed: running.allowed,
        blocked: running.blocked,
        sanitized: running.sanitized,
      };
    }
  );

  const dailyActivity = db
    .prepare(`
      SELECT
        substr(created_at, 1, 10) AS time,

        SUM(
          CASE
            WHEN status = 'allowed'
            THEN 1
            ELSE 0
          END
        ) AS allowed,

        SUM(
          CASE
            WHEN status = 'blocked'
            THEN 1
            ELSE 0
          END
        ) AS blocked,

        SUM(
          CASE
            WHEN status = 'cleaned'
            THEN 1
            ELSE 0
          END
        ) AS sanitized

      FROM prompt_scans

      GROUP BY substr(created_at, 1, 10)

      ORDER BY time DESC

      LIMIT 30
    `)
    .all()
    .reverse()
    .map((item) => ({
      time: item.time,
      allowed: Number(item.allowed) || 0,
      blocked: Number(item.blocked) || 0,
      sanitized: Number(item.sanitized) || 0,
    }));

  const activity = {
    "24H": hourlyActivity,
    "7D": dailyActivity.slice(-7),
    "30D": dailyActivity,
  };

  const redTeam = db
    .prepare(`
      SELECT
        COUNT(*) AS total,
        SUM(passed) AS passed
      FROM red_team_results
    `)
    .get();

  const redTeamTotal =
    Number(redTeam.total) || 0;

  const redTeamPassed =
    Number(redTeam.passed) || 0;

  const redTeamScore =
    redTeamTotal > 0
      ? Math.round(
          (redTeamPassed / redTeamTotal) * 100
        )
      : null;

  const operationalScore =
    scanned > 0
     ? Math.max(
        0,
        Math.min(
          100,
          Math.round(100 - averageRisk)
        )
      )
    : 100;

  const securityScore =
   redTeamScore === null
      ? operationalScore
      : Math.max(
        0,
        Math.min(
          100,
          Math.round(
            operationalScore * 0.6 +
            redTeamScore * 0.4
          )
        )
      );
  return {
    kpis: {
      scanned,
      blocked,
      sanitized,
      securityScore,
      riskPrevented: `₹${riskPreventedLakh.toFixed(1)}L`,
    },

    departments,

    categories,

    activity,

    threatMap: getThreatMap(),

    dpdp: getDPDPCompliance(),

    insights: getAIInsights(),

    generatedAt: now(),
  };
}
>>>>>>> Stashed changes

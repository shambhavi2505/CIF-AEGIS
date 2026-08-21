import { randomUUID } from "node:crypto";
import { saveScan, saveIncident } from "./database.js";

const ML_URL =
  process.env.ML_SERVICE_URL || "http://127.0.0.1:8000";

/* =========================================================
   FUZZY MATCHING HELPERS
========================================================= */

function normalizeText(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function levenshtein(a, b) {
  a = String(a);
  b = String(b);

  const matrix = Array.from(
    { length: a.length + 1 },
    () => Array(b.length + 1).fill(0)
  );

  for (let i = 0; i <= a.length; i++) matrix[i][0] = i;
  for (let j = 0; j <= b.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      matrix[i][j] =
        a[i - 1] === b[j - 1]
          ? matrix[i - 1][j - 1]
          : Math.min(
              matrix[i - 1][j] + 1,
              matrix[i][j - 1] + 1,
              matrix[i - 1][j - 1] + 1
            );
    }
  }

  return matrix[a.length][b.length];
}

function fuzzyContains(text, variants, maxDistance = 1) {
  const normalized = normalizeText(text);

  for (const variant of variants) {
    const target = normalizeText(variant);

    if (normalized.includes(target)) {
      return true;
    }

    const words = normalized.split(/\s+/);
    const targetWords = target.split(/\s+/);

    if (targetWords.length !== 1) continue;

    /*
     * Do not fuzzy-match tiny words.
     * "api" is handled explicitly below.
     */
    if (target.length < 4) continue;

    for (const word of words) {
      if (levenshtein(word, target) <= maxDistance) {
        return true;
      }
    }
  }

  return false;
}

/* =========================================================
   FUZZY SECURITY TERMINOLOGY
========================================================= */

const fuzzyTerms = {
  pan: [
    "pan",
    "pan number",
    "pan no",
    "pan num",
    "pna",
    "pna number",
    "pna no",
    "pann",
    "pann number",
    "paan",
  ],

  aadhaar: [
    "aadhaar",
    "aadhar",
    "adhar",
    "adhaar",
    "aadhaar number",
    "aadhar number",
    "adhar number",
    "aadhaar no",
    "aadhar no",
    "aadhar num",
    "aadhr",
  ],

  api: [
    "api",
    "api key",
    "apikey",
    "api-key",
    "api kay",
    "api kye",
    "api k ey",
    "a pi key",
    "api number",
  ],

  cvv: [
    "cvv",
    "cvc",
    "cvv number",
    "cvv no",
    "cvv num",
    "security code",
    "securty code",
    "security cod",
  ],

  password: [
    "password",
    "passwd",
    "pass word",
    "pasword",
    "paswrd",
    "passwrod",
    "pwd",
    "passcode",
  ],

  phone: [
    "phone",
    "phone number",
    "phon",
    "phon number",
    "mobile",
    "mobile number",
    "mobile no",
    "mob number",
    "telephone",
    "tel number",
  ],

  email: [
    "email",
    "e-mail",
    "email address",
    "emial",
    "eamil",
    "mail address",
  ],

  bank: [
    "bank account",
    "bank account number",
    "account number",
    "account no",
    "account num",
    "acc number",
    "acc no",
    "bank acc",
  ],

  token: [
    "token",
    "access token",
    "bearer token",
    "auth token",
    "authentication token",
  ],
};

/* =========================================================
   EXACT VALUE PATTERNS
========================================================= */

const VALUE_PATTERNS = {
  pan:
    /\b[A-Z]{5}\d{4}[A-Z]\b/gi,

  aadhaar:
    /\b(?:\d{4}[\s-]?){2}\d{4}\b/g,

  phone:
    /(?<![A-Za-z0-9_-])(?:\+91[\s-]?)?[6-9]\d{9}(?![A-Za-z0-9_-])/g,

  email:
    /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,

  card:
    /\b(?:\d[ -]*?){13,19}\b/g,

  cvv:
    /\b(?:cvv|cvc|security\s+code)\s*[:=-]?\s*(?:is\s+)?\d{3,4}\b/gi,

  apiLabel:
    /\b(?:api[\s_-]*key|apikey)\s*(?::|=|\bis\b)?\s*[A-Za-z0-9._-]{8,}\b/gi,

  apiStandalone:
    /\bsk[-]?[A-Za-z0-9_-]{7,}\b/gi,

  token:
    /\b(?:ghp_[A-Za-z0-9]{10,}|bearer\s+token\s+[A-Za-z0-9._-]{8,}|access\s+token\s+[A-Za-z0-9._-]{8,})\b/gi,

  password:
    /\b(?:password|passwd|pwd|passcode)\s*[:=]?\s*(?:is\s+)?\S+/gi,

  privateKey:
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,

  promptInjection:
    /\b(?:ignore\s+(?:all|any|the|previous)\s+instructions|jailbreak|system\s+prompt|bypass\s+(?:the\s+)?(?:security|policy|guardrail)s?|disable\s+(?:security|watchtower|guardrails?)|reveal\s+(?:the\s+)?system\s+prompt)\b/gi,
      gst:
    /\b\d{2}[A-Z]{5}\d{4}[A-Z]\d[Z][A-Z\d]\b/g,

  upi:
    /\b[a-zA-Z0-9.\-]{2,256}@(?:ok(?:hdfcbank|icici|axis|sbi)|ybl|paytm|upi|apl|ibl|axl|hdfcbank|icici|sbi|freecharge|jio)\b/gi,

  passport:
    /\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b/g,

  voterId:
    /\b[A-Z]{3}[0-9]{7}\b/g,

  cogs:
    /\b(?:cost of goods sold|cogs|unit cost|cost price|purchase price|vendor cost|supplier cost|profit margin|margin\s*%|wholesale price|internal pricing|manufacturing cost|landed cost)\b/gi,

  sourcingInfo:
    /\b(?:supplier name|vendor name|sourcing partner|manufacturing partner|raw material source|supply chain contract|vendor agreement)\b/gi,

  financialTransaction:
    /\b(?:bank statement|wire transfer|account balance|internal revenue figures|unpublished financial results|quarterly earnings before release)\b/gi,
  };
/* =========================================================
   CATEGORY RISK WEIGHTS
   Used for risk score AND for DPDP loss estimation below.
========================================================= */

const CATEGORY_RISK_WEIGHT = {
  "Honeytoken": 99,
  "Sensitive Personal Data": 95,
  "Credentials": 92,
  "Personal Identity": 90,
  "AI Security": 88,
  "Financial Identity": 85,
  "Financial Data": 85,
  "Personal Contact Data": 55,
  "Safe Business Request": 5,
  "Business Confidential": 88,
};

function riskWeightForCategory(category) {
  return CATEGORY_RISK_WEIGHT[category] ?? 70;
}

/* =========================================================
   HONEYTOKENS
========================================================= */

function getConfiguredHoneytokens() {
  return (process.env.HONEYTOKENS || "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
}

function detectHoneytoken(text) {
  const configured = getConfiguredHoneytokens();

  for (const token of configured) {
    if (token && text.includes(token)) {
      return true;
    }
  }

  return /\b(?:AWS_TEST_SECRET_001|HONEYTOKEN_[A-Z0-9_-]+)\b/g.test(
    text
  );
}

/* =========================================================
   DEPARTMENT
========================================================= */

function departmentFromText(text) {
  const t = normalizeText(text);

  if (
    /(cvv|cvc|card|credit card|bank|salary|tax|payment|invoice|pan|pna|pann)/i.test(
      t
    )
  ) {
    return "Finance";
  }

  if (
    /(api|apikey|password|passwd|pwd|token|aws|database|server|github|jailbreak|credential|prompt injection|system prompt|private key)/i.test(
      t
    )
  ) {
    return "IT";
  }

  if (
    /(aadhaar|aadhar|adhar|employee|candidate|resume|onboarding|leave|dob|phone|email|mobile)/i.test(
      t
    )
  ) {
    return "HR";
  }

  if (
    /(contract|legal|nda|compliance|agreement|litigation)/i.test(
      t
    )
  ) {
    return "Legal";
  }

  if (
    /(vendor|inventory|logistics|shipment|procurement|supply chain)/i.test(
      t
    )
  ) {
    return "Operations";
  }

  if (
    /(campaign|marketing|advertisement|lead list|social media|promotion)/i.test(
      t
    )
  ) {
    return "Marketing";
  }

  return "General";
}

/* =========================================================
   SECURITY DETECTION
========================================================= */

function applyRules(originalText) {
  let sanitizedText = originalText;

  const detectedItems = [];

  let blocked = false;
  let cleaned = false;

  let department = departmentFromText(originalText);
  let category = "Safe Business Request";
  let blockReason = null;

  const addDetected = (item) => {
    if (!detectedItems.includes(item)) {
      detectedItems.push(item);
    }
  };

  const sanitize = (
    regex,
    replacement,
    item,
    itemCategory,
    itemDepartment
  ) => {
    regex.lastIndex = 0;

    if (!regex.test(originalText)) {
      regex.lastIndex = 0;
      return;
    }

    regex.lastIndex = 0;

    sanitizedText = sanitizedText.replace(
      regex,
      replacement
    );

    addDetected(item);

    cleaned = true;

    category = itemCategory;

    if (department === "General") {
      department = itemDepartment;
    }
  };

  /* =======================================================
     BLOCK FIRST
  ======================================================= */

  if (detectHoneytoken(originalText)) {
    blocked = true;

    addDetected("Honeytoken");

    category = "Honeytoken";
    department = "IT";

    blockReason =
      "A known honeytoken was detected. The request was blocked to prevent credential or security-secret exposure.";

    return {
      sanitizedText,
      detectedItems,
      blocked,
      cleaned,
      department,
      category,
      blockReason,
    };
  }

  VALUE_PATTERNS.privateKey.lastIndex = 0;

  if (
    VALUE_PATTERNS.privateKey.test(
      originalText
    )
  ) {
    blocked = true;

    addDetected("Private key");

    category = "Credentials";
    department = "IT";

    blockReason =
      "A private cryptographic key was detected. Private keys cannot be processed.";

    return {
      sanitizedText,
      detectedItems,
      blocked,
      cleaned,
      department,
      category,
      blockReason,
    };
  }

  VALUE_PATTERNS.promptInjection.lastIndex = 0;

  if (
    VALUE_PATTERNS.promptInjection.test(
      originalText
    )
  ) {
    blocked = true;

    addDetected("Prompt injection");

    category = "AI Security";
    department = "IT";

    blockReason =
      "The request contains language attempting to bypass, disable, or manipulate the AI security controls.";

    return {
      sanitizedText,
      detectedItems,
      blocked,
      cleaned,
      department,
      category,
      blockReason,
    };
  }

  /* =======================================================
     API KEYS
  ======================================================= */

  /*
   * IMPORTANT:
   * Detect API credentials BEFORE phone/card rules.
   */

  sanitize(
    VALUE_PATTERNS.apiLabel,
    "[API KEY REDACTED]",
    "API key",
    "Credentials",
    "IT"
  );

  sanitize(
    VALUE_PATTERNS.apiStandalone,
    "[API KEY REDACTED]",
    "API key",
    "Credentials",
    "IT"
  );

  /* =======================================================
     TOKENS
  ======================================================= */

  sanitize(
    VALUE_PATTERNS.token,
    "[ACCESS TOKEN REDACTED]",
    "Access token",
    "Credentials",
    "IT"
  );

  /* =======================================================
     PASSWORD
  ======================================================= */

  sanitize(
    VALUE_PATTERNS.password,
    "[PASSWORD REDACTED]",
    "Password",
    "Credentials",
    "IT"
  );

  /* =======================================================
     PAN
  ======================================================= */

  sanitize(
    VALUE_PATTERNS.pan,
    "[PAN REDACTED]",
    "PAN",
    "Financial Identity",
    "Finance"
  );

  /* =======================================================
     AADHAAR
  ======================================================= */

  sanitize(
    VALUE_PATTERNS.aadhaar,
    "[AADHAAR REDACTED]",
    "Aadhaar",
    "Personal Identity",
    "HR"
  );

  /* =======================================================
     CVV
  ======================================================= */

  sanitize(
    VALUE_PATTERNS.cvv,
    "[CVV REDACTED]",
    "CVV",
    "Financial Data",
    "Finance"
  );

  /* =======================================================
     CARD
  ======================================================= */

  sanitize(
    VALUE_PATTERNS.card,
    "[CARD NUMBER REDACTED]",
    "Card number",
    "Financial Data",
    "Finance"
  );
    /* =======================================================
     GST NUMBER
  ======================================================= */

  sanitize(
    VALUE_PATTERNS.gst,
    "[GST NUMBER REDACTED]",
    "GST number",
    "Financial Identity",
    "Finance"
  );

  /* =======================================================
     UPI ID
  ======================================================= */

  sanitize(
    VALUE_PATTERNS.upi,
    "[UPI ID REDACTED]",
    "UPI ID",
    "Financial Identity",
    "Finance"
  );

  /* =======================================================
     PASSPORT
  ======================================================= */

  sanitize(
    VALUE_PATTERNS.passport,
    "[PASSPORT NUMBER REDACTED]",
    "Passport number",
    "Personal Identity",
    "HR"
  );

  /* =======================================================
     VOTER ID
  ======================================================= */

  sanitize(
    VALUE_PATTERNS.voterId,
    "[VOTER ID REDACTED]",
    "Voter ID",
    "Personal Identity",
    "HR"
  );

  /* =======================================================
     COST OF GOODS / PRICING (BUSINESS CONFIDENTIAL)
  ======================================================= */

  sanitize(
    VALUE_PATTERNS.cogs,
    "[COST DATA REDACTED]",
    "Cost/pricing data",
    "Business Confidential",
    "Finance"
  );

  /* =======================================================
     SOURCING / SUPPLIER INFO (BUSINESS CONFIDENTIAL)
  ======================================================= */

  sanitize(
    VALUE_PATTERNS.sourcingInfo,
    "[SOURCING INFO REDACTED]",
    "Sourcing/supplier info",
    "Business Confidential",
    "Operations"
  );

  /* =======================================================
     FINANCIAL TRANSACTIONS (BUSINESS CONFIDENTIAL)
  ======================================================= */

  sanitize(
    VALUE_PATTERNS.financialTransaction,
    "[FINANCIAL DATA REDACTED]",
    "Financial transaction data",
    "Business Confidential",
    "Finance"
  );

  /* =======================================================
     EMAIL
  ======================================================= */

  sanitize(
    VALUE_PATTERNS.email,
    "[EMAIL REDACTED]",
    "Email address",
    "Personal Contact Data",
    "HR"
  );

  /* =======================================================
     PHONE
  ======================================================= */

  sanitize(
    VALUE_PATTERNS.phone,
    "[PHONE REDACTED]",
    "Phone number",
    "Personal Contact Data",
    "HR"
  );

  /* =======================================================
     FUZZY PAN
  ======================================================= */

  if (
    fuzzyContains(
      originalText,
      fuzzyTerms.pan,
      1
    )
  ) {
    const match =
      originalText.match(
        VALUE_PATTERNS.pan
      );

    if (match) {
      for (const value of match) {
        sanitizedText =
          sanitizedText.replace(
            value,
            "[PAN REDACTED]"
          );
      }

      addDetected("PAN");

      cleaned = true;
      category = "Financial Identity";
      department = "Finance";
    }
  }

  /* =======================================================
     FUZZY AADHAAR
  ======================================================= */

  if (
    fuzzyContains(
      originalText,
      fuzzyTerms.aadhaar,
      2
    )
  ) {
    const match =
      originalText.match(
        VALUE_PATTERNS.aadhaar
      );

    if (match) {
      for (const value of match) {
        sanitizedText =
          sanitizedText.replace(
            value,
            "[AADHAAR REDACTED]"
          );
      }

      addDetected("Aadhaar");

      cleaned = true;
      category = "Personal Identity";
      department = "HR";
    }
  }

  /* =======================================================
     FUZZY API
  ======================================================= */

  if (
    fuzzyContains(
      originalText,
      fuzzyTerms.api,
      1
    )
  ) {
    const apiValues = [
      ...(originalText.match(
        VALUE_PATTERNS.apiStandalone
      ) || []),
    ];

    for (const value of apiValues) {
      sanitizedText =
        sanitizedText.replace(
          value,
          "[API KEY REDACTED]"
        );
    }

    if (apiValues.length) {
      addDetected("API key");

      cleaned = true;
      category = "Credentials";
      department = "IT";
    }
  }

  /* =======================================================
     FUZZY CVV
  ======================================================= */

  if (
    fuzzyContains(
      originalText,
      fuzzyTerms.cvv,
      1
    )
  ) {
    const match =
      originalText.match(
        /\b(?:cvv|cvc|security\s+code|securty\s+code|security\s+cod)\s*[:=-]?\s*(?:is\s+)?\d{3,4}\b/i
      );

    if (match) {
      sanitizedText =
        sanitizedText.replace(
          match[0],
          "[CVV REDACTED]"
        );

      addDetected("CVV");

      cleaned = true;
      category = "Financial Data";
      department = "Finance";
    }
  }

  /* =======================================================
     FUZZY PASSWORD
  ======================================================= */

  if (
    fuzzyContains(
      originalText,
      fuzzyTerms.password,
      1
    )
  ) {
    const match =
      originalText.match(
        /\b(?:password|passwd|pwd|pasword|paswrd|passwrod|passcode)\s*[:=]?\s*(?:is\s+)?\S+/i
      );

    if (match) {
      sanitizedText =
        sanitizedText.replace(
          match[0],
          "[PASSWORD REDACTED]"
        );

      addDetected("Password");

      cleaned = true;
      category = "Credentials";
      department = "IT";
    }
  }

  /* =======================================================
     FUZZY PHONE
  ======================================================= */

  if (
    fuzzyContains(
      originalText,
      fuzzyTerms.phone,
      1
    )
  ) {
    const matches =
      originalText.match(
        VALUE_PATTERNS.phone
      ) || [];

    for (const value of matches) {
      sanitizedText =
        sanitizedText.replace(
          value,
          "[PHONE REDACTED]"
        );
    }

    if (matches.length) {
      addDetected("Phone number");

      cleaned = true;
      category =
        "Personal Contact Data";
      department = "HR";
    }
  }

  /* =======================================================
     FUZZY EMAIL
  ======================================================= */

  if (
    fuzzyContains(
      originalText,
      fuzzyTerms.email,
      1
    )
  ) {
    const matches =
      originalText.match(
        VALUE_PATTERNS.email
      ) || [];

    for (const value of matches) {
      sanitizedText =
        sanitizedText.replace(
          value,
          "[EMAIL REDACTED]"
        );
    }

    if (matches.length) {
      addDetected("Email address");

      cleaned = true;
      category =
        "Personal Contact Data";
      department = "HR";
    }
  }

  /* =======================================================
     FUZZY BANK
  ======================================================= */

  if (
    fuzzyContains(
      originalText,
      fuzzyTerms.bank,
      1
    )
  ) {
    const account =
      originalText.match(
        /\b\d{9,18}\b/g
      ) || [];

    for (const value of account) {
      sanitizedText =
        sanitizedText.replace(
          value,
          "[BANK ACCOUNT REDACTED]"
        );
    }

    if (account.length) {
      addDetected("Bank account");

      cleaned = true;
      category = "Financial Data";
      department = "Finance";
    }
  }

  return {
    sanitizedText,
    detectedItems,
    blocked,
    cleaned,
    department,
    category,
    blockReason,
  };
}

/* =========================================================
   DISTILBERT
========================================================= */

async function callDistilBert(text) {
  const controller =
    new AbortController();

  const timer = setTimeout(
    () => controller.abort(),
    Number(
      process.env.ML_TIMEOUT_MS || 15000
    )
  );

  try {
    const response =
      await fetch(
        `${ML_URL}/predict`,
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/json",
          },
          body: JSON.stringify({
            text,
          }),
          signal:
            controller.signal,
        }
      );

    if (!response.ok) {
      throw new Error(
        `ML service returned ${response.status}`
      );
    }

    return await response.json();
  } finally {
    clearTimeout(timer);
  }
}

async function getMlResult(text) {
  const chunks = [];
  const chunkSize = 3500;

  for (
    let i = 0;
    i < text.length;
    i += chunkSize
  ) {
    chunks.push(
      text.slice(
        i,
        i + chunkSize
      )
    );
  }

  if (!chunks.length) {
    chunks.push("");
  }

  const results = [];

  for (
    const chunk of chunks.slice(
      0,
      12
    )
  ) {
    try {
      results.push(
        await callDistilBert(
          chunk
        )
      );
    } catch {
      // ML is optional.
    }
  }

  if (!results.length) {
    return {
      mlLabel: null,
      mlConfidence: null,
      mlModel:
        "distilbert-base-uncased-finetuned-sst-2-english",
      mlAvailable: false,
    };
  }

  const best =
    results.reduce(
      (a, b) =>
        Number(b.confidence) >
        Number(a.confidence)
          ? b
          : a
    );

  return {
    mlLabel: best.label,
    mlConfidence:
      Number(best.confidence),
    mlModel:
      best.model ||
      "distilbert-base-uncased-finetuned-sst-2-english",
    mlAvailable: true,
  };
}

/* =========================================================
   MAIN PIPELINE
========================================================= */

export async function inspectText(
  text,
  options = {}
) {
  const originalText =
    String(text || "").trim();

  if (!originalText) {
    throw new Error(
      "Text is required."
    );
  }

  /*
   * STEP 1
   * Security inspection.
   */
  const policyResult =
    applyRules(
      originalText
    );

  /*
   * STEP 2
   *
   * BLOCK:
   * Never send blocked content to ML.
   *
   * SANITIZE:
   * Only send sanitized text to ML.
   *
   * ALLOW:
   * Send original text to ML.
   */
  let ml = {
    mlLabel: null,
    mlConfidence: null,
    mlModel:
      "distilbert-base-uncased-finetuned-sst-2-english",
    mlAvailable: false,
  };

  if (!policyResult.blocked) {
    const textForML =
      policyResult.cleaned
        ? policyResult.sanitizedText
        : originalText;

    ml =
      await getMlResult(
        textForML
      );
  }

  /* =======================================================
     STATUS
  ======================================================= */
  let status = "allowed";
  let label = "Allowed";
  let riskScore = 5;

  let response =
    "Your request passed all security checks and was processed successfully.";

  if (policyResult.blocked) {
    status = "blocked";
    label = "Blocked";
    riskScore = riskWeightForCategory(policyResult.category);

    response =
      "This request was blocked because it matched a security protection policy.";
  } else if (policyResult.cleaned) {
    status = "cleaned";
    label =
      "Sensitive data sanitized";
    riskScore = Math.round(
      riskWeightForCategory(policyResult.category) * 0.75
    );

    response =
      "Sensitive information was detected and redacted before the content was processed.";
  }

  /*
   * DistilBERT is an additional signal.
   * It does NOT decide whether PII is present.
   */
  if (ml.mlAvailable) {
    const negative =
      String(
        ml.mlLabel || ""
      ).toUpperCase() ===
      "NEGATIVE";

    if (
      negative &&
      status === "allowed"
    ) {
      riskScore =
        Math.max(
          riskScore,
          35
        );
    }
  }

  /* =======================================================
     SCAN
  ======================================================= */

  const scan = {
    id: randomUUID(),

    prompt: originalText,

    originalText,

    extractedText:
      options.isDocument
        ? originalText
        : undefined,

    sanitizedText:
      policyResult.sanitizedText,

    status,

    label,

    category:
      policyResult.category,

    riskScore,

    confidence:
      status === "blocked"
        ? 99
        : status === "cleaned"
          ? 96
          : 95,

    policy:
      status === "blocked"
        ? "Security Protection Policy"
        : status === "cleaned"
          ? "Personal Data Protection Policy"
          : "Acceptable AI Usage",

    response,

    blockReason:
      policyResult.blockReason,

    department:
      policyResult.department,

    detectedItems:
      policyResult.detectedItems,

    aiProcessingAllowed:
      status !== "blocked",

    securityAction:
      status === "blocked"
        ? (policyResult.category === "Honeytoken"
            ? "ALERT"
            : "BLOCK")
        : status === "cleaned"
          ? "SANITIZE"
          : "ALLOW",

    ...ml,

    inspectedAt:
      new Date().toISOString(),
  };

  scan.source =
    options.source ||
    (options.isDocument
      ? "document"
      : "chat");

  /* =======================================================
     SAVE SCAN
  ======================================================= */

  const saved =
    saveScan(
      scan,
      options.userId ||
        "demo-user"
    );

  /* =======================================================
     SAVE INCIDENT
  ======================================================= */

  if (
    status === "blocked" ||
    status === "cleaned"
  ) {
    const incident =
      saveIncident(
        {
          scenarioKey:
            options.isDocument
              ? "document-security"
              : "prompt-security",

          title: label,

          severity:
            status === "blocked"
              ? "Critical"
              : "High",

          category:
            policyResult.category,

          detectedItems:
            policyResult.detectedItems,

          originalText,

          sanitizedText:
            policyResult.sanitizedText,

          mlLabel:
            ml.mlLabel,

          mlConfidence:
            ml.mlConfidence,

          blockReason:
            policyResult.blockReason,

          securityAction:
            status === "blocked"
              ? "BLOCK"
              : "SANITIZE",

          source:
            options.source ||
            (options.isDocument
              ? "document"
              : "chat"),
        },

        saved.id,

        options.userId ||
          "demo-user"
      );

    if (incident) {
      saved.incidentId =
        incident.id;
      // Keep the complete incident in the response so a USER can
      // open the explanation for this session without reloading
      // historical incidents from the database.
      saved.incidentDetails = incident;
    }
  }

  return saved;
}
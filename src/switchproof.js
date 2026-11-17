// Browser- and Node-compatible SwitchProof preview engine.
// No network, filesystem, persistence or target-database access.
async function sha256(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}
function parseCsv(text) {
  if (typeof text !== "string") throw new TypeError("CSV input must be text.");
  if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
  const rows = []; let row = [], cell = "", quoted = false, closedQuote = false;
  const push = () => { row.push(cell); if (row.some(v => v.trim() !== "")) rows.push(row); row = []; cell = ""; closedQuote = false; };
  for (let i = 0; i < text.length; i++) {
    const c = text[i], next = text[i + 1];
    if (quoted) {
      if (c === '"' && next === '"') { cell += '"'; i++; }
      else if (c === '"') { quoted = false; closedQuote = true; }
      else cell += c;
      continue;
    }
    if (closedQuote) {
      if (c === ",") { row.push(cell); cell = ""; closedQuote = false; }
      else if (c === " " || c === "\t") cell += c;
      else if (c === "\n" || c === "\r") { if (c === "\r" && next === "\n") i++; push(); }
      else throw new Error("CSV contains unexpected characters after a closing quote.");
      continue;
    }
    if (c === '"') {
      if (cell.length) throw new Error("CSV contains a quote inside an unquoted field.");
      quoted = true;
    } else if (c === ",") { row.push(cell); cell = ""; }
    else if (c === "\n" || c === "\r") { if (c === "\r" && next === "\n") i++; push(); }
    else cell += c;
  }
  if (quoted) throw new Error("CSV contains an unclosed quoted field.");
  row.push(cell); if (row.some(v => v.trim() !== "")) rows.push(row);
  if (!rows.length) return [];
  const headers = rows.shift().map(v => v.trim());
  const normalized = headers.map(v => v.toLocaleLowerCase("en"));
  if (headers.some(v => !v) || new Set(normalized).size !== headers.length) throw new Error("CSV contains empty or duplicate column headings.");
  return rows.map((cells, index) => {
    if (cells.length !== headers.length) throw new Error("CSV row " + (index + 2) + " has an inconsistent number of cells.");
    return Object.fromEntries(headers.map((header, i) => [header, cells[i].trim()]).concat([["__rowNumber", String(index + 2)]]));
  });
}
const safeKey = value => typeof value === "string" && /^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(value);
function validateSchema(schema) {
  if (!Array.isArray(schema) || schema.length < 1 || schema.length > 50) throw new TypeError("Target schema must contain 1–50 field definitions.");
  const keys = new Set();
  for (const field of schema) {
    if (!field || typeof field !== "object" || !safeKey(field.key) ||
        !["text", "decimal", "date", "currency", "boolean"].includes(field.type) ||
        typeof field.required !== "boolean" || keys.has(field.key)) throw new TypeError("Target schema contains an invalid or duplicate field definition.");
    if (field.type === "text" && field.maxLength !== undefined &&
        (!Number.isInteger(field.maxLength) || field.maxLength < 1 || field.maxLength > 1000)) throw new TypeError("Text maxLength must be an integer from 1 to 1000.");
    keys.add(field.key);
  }
  return keys;
}
function canonicalMoney(value) {
  if (typeof value !== "string" || value.length > 16 || !/^-?(?:0|[1-9]\d*)(?:\.\d{1,2})?$/.test(value)) return null;
  const negative = value.startsWith("-");
  const unsigned = negative ? value.slice(1) : value;
  const [whole, fraction = ""] = unsigned.split(".");
  const cents = BigInt(whole) * 100n + BigInt((fraction + "00").slice(0, 2));
  if (cents > 99999999999999n) return null;
  const absolute = cents;
  return (negative && absolute !== 0n ? "-" : "") + String(absolute / 100n) + "." + String(absolute % 100n).padStart(2, "0");
}
function validDate(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(value + "T00:00:00.000Z");
  return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === value;
}
function canonicalValue(value, field) {
  const raw = typeof value === "string" ? value.trim() : "";
  if (!raw) return {value: null, error: field.required ? "Required value is missing" : null};
  switch (field.type) {
    case "text":
      return raw.length > (field.maxLength ?? 1000)
        ? {value: null, error: "Text exceeds the target field length"} : {value: raw, error: null};
    case "decimal": {
      const canonical = canonicalMoney(raw);
      return canonical === null ? {value: null, error: "Expected a canonical decimal with at most two decimal places"} : {value: canonical, error: null};
    }
    case "date":
      return validDate(raw) ? {value: raw, error: null} : {value: null, error: "Expected a real ISO calendar date (YYYY-MM-DD)"};
    case "currency":
      return /^[A-Za-z]{3}$/.test(raw) ? {value: raw.toUpperCase(), error: null} : {value: null, error: "Expected a three-letter currency code"};
    case "boolean":
      return raw === "true" || raw === "false" ? {value: raw === "true", error: null} : {value: null, error: "Expected the explicit value true or false"};
    default: return {value: null, error: "Unsupported target type"};
  }
}

/** Profiles CSV structure and checksum without retaining source data. */
export async function profileSourceCsv(csvText) {
  if (typeof csvText !== "string" || csvText.length > 5_000_000) throw new TypeError("CSV source must be text no larger than 5 MB.");
  const rows = parseCsv(csvText);
  const columns = rows.length ? Object.keys(rows[0]).filter(key => key !== "__rowNumber") : [];
  const nonEmptyCounts = Object.fromEntries(columns.map(column => [column, rows.filter(row => row[column]?.trim() !== "").length]));
  const emptyCounts = Object.fromEntries(columns.map(column => [column, rows.length - nonEmptyCounts[column]]));
  return {
    sourceChecksum: await sha256(csvText), parsedRows: rows.length, columns, nonEmptyCounts, emptyCounts,
    duplicateHeadersRejected: true, parser: "switchproof-csv-1.0.0", storage: "none", writesPerformed: 0
  };
}

/** Creates a deterministic, reversible preview only. No target records are written. */
export async function previewMigration({csvText, mapping, targetSchema, sourceKeyField, mappingVersion} = {}) {
  if (typeof csvText !== "string" || csvText.length > 5_000_000) throw new TypeError("CSV source must be text no larger than 5 MB.");
  if (!mapping || typeof mapping !== "object" || Array.isArray(mapping)) throw new TypeError("An explicit source-to-target mapping is required.");
  if (typeof mappingVersion !== "string" || !/^\d+\.\d+\.\d+$/.test(mappingVersion)) throw new TypeError("Mapping version must use semantic version format.");
  const targetKeys = validateSchema(targetSchema);
  if (!safeKey(sourceKeyField) || !targetKeys.has(sourceKeyField)) throw new TypeError("sourceKeyField must identify a field in the target schema.");
  const rows = parseCsv(csvText);
  const sourceHeaders = rows.length ? Object.keys(rows[0]).filter(key => key !== "__rowNumber") : [];
  const entries = Object.entries(mapping);
  if (!entries.length) throw new TypeError("At least one explicit field mapping is required.");
  const targets = entries.map(([, target]) => target);
  if (entries.some(([source, target]) => !sourceHeaders.includes(source) || !safeKey(target) || !targetKeys.has(target)) || new Set(targets).size !== targets.length) {
    throw new TypeError("Mapping references an unknown source/target field or maps multiple source fields to one target.");
  }
  const mappedTargets = new Set(targets);
  for (const field of targetSchema) if (field.required && !mappedTargets.has(field.key)) throw new TypeError("Required target field is not mapped: " + field.key);
  if (!mappedTargets.has(sourceKeyField)) throw new TypeError("The source record key must be explicitly mapped.");
  const schemaByKey = new Map(targetSchema.map(field => [field.key, field]));
  const seenKeys = new Set();
  const records = await Promise.all(rows.map(async (row, index) => {
    const values = {}, errors = [];
    for (const [sourceHeader, targetKey] of entries) {
      const result = canonicalValue(row[sourceHeader], schemaByKey.get(targetKey));
      values[targetKey] = result.value;
      if (result.error) errors.push(targetKey + ": " + result.error);
    }
    const sourceRecordKey = values[sourceKeyField];
    if (typeof sourceRecordKey !== "string" || !sourceRecordKey) errors.push("Source record key is missing or invalid");
    else if (seenKeys.has(sourceRecordKey)) errors.push("Duplicate source record key");
    else seenKeys.add(sourceRecordKey);
    const sourceRowNumber = Number.parseInt(row.__rowNumber, 10) || index + 2;
    const rawValues = Object.fromEntries(Object.entries(row).filter(([key]) => key !== "__rowNumber"));
    return {
      sourceRowNumber, sourceRecordKey: typeof sourceRecordKey === "string" ? sourceRecordKey : null,
      sourceRowHash: await sha256(JSON.stringify({sourceRowNumber, values: rawValues})),
      values, status: errors.length ? "held" : "candidate", errors
    };
  }));
  const orderedMapping = Object.fromEntries(entries.slice().sort(([a], [b]) => a.localeCompare(b)));
  const orderedSchema = targetSchema.map(({key, type, required, maxLength}) => ({key, type, required, ...(maxLength === undefined ? {} : {maxLength})}));
  const unmappedSourceColumns = sourceHeaders.filter(header => !Object.hasOwn(mapping, header));
  const candidateRows = records.filter(row => row.status === "candidate").length;
  const heldRows = records.length - candidateRows;
  return {
    sourceChecksum: await sha256(csvText), mappingVersion,
    mappingFingerprint: await sha256(JSON.stringify({mapping: orderedMapping, targetSchema: orderedSchema, sourceKeyField})),
    sourceRowCount: rows.length, candidateRows, heldRows, unmappedSourceColumns, records,
    reconciliation: {parsedSourceRows: rows.length, previewedRows: records.length, candidateRows, heldRows, unexplainedRowDifference: rows.length - records.length},
    reversibility: {mode: "preview_only_no_target_writes", targetWrites: 0, rollback: "Discard this preview. No target records were created or changed."},
    limitations: [
      "A candidate is structurally valid only; it is not approved for migration.",
      "No source file is stored and no target database is written.",
      "Source ownership, permission, identity matching and business meaning require human verification.",
      "A checksum proves byte identity, not source authenticity or lawful permission."
    ]
  };
}

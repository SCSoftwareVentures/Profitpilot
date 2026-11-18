// Synthetic-only workflow presenter. Never authorises an invoice or a financial result.
// No external effects, network calls, storage or customer data.
import {validateInvoiceRows, matchInvoice} from "./engine.js";

function amountInCents(value) {
  const text = String(value);
  if (!/^(?:0|[1-9]\d*)(?:\.\d{1,2})?$/.test(text)) throw new Error("Invalid currency decimal");
  const [whole, fraction = ""] = text.split(".");
  const cents = BigInt(whole) * 100n + BigInt((fraction + "00").slice(0, 2));
  if (cents > 99999999999999n) throw new Error("Invoice amount exceeds supported maximum");
  return cents;
}


export function prepareInvoiceReview(rows, contract) {
  if (!Array.isArray(rows)) throw new TypeError("Invoice rows must be an array");
  if (!contract || !contract.id || !contract.site || !contract.periodStart || !contract.periodEnd) {
    throw new TypeError("Contract identity, site and period are required");
  }
  if (contract.currency !== undefined && contract.currency !== "AUD") throw new Error("Synthetic workflow supports AUD only");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(contract.periodStart) || !/^\d{4}-\d{2}-\d{2}$/.test(contract.periodEnd) || !Number.isFinite(Date.parse(contract.periodStart+"T00:00:00Z")) || !Number.isFinite(Date.parse(contract.periodEnd+"T00:00:00Z")) || new Date(contract.periodStart+"T00:00:00Z").toISOString().slice(0,10)!==contract.periodStart || new Date(contract.periodEnd+"T00:00:00Z").toISOString().slice(0,10)!==contract.periodEnd || contract.periodEnd < contract.periodStart) throw new Error("Invalid contract period");
  return validateInvoiceRows(rows).map(item => {
    const amount = item.record?.amount;
    if (typeof amount !== "string" && typeof amount !== "number") item.errors.push("Invalid amount type");
    else if (!/^(?:0|[1-9]\d*)(?:\.\d{1,2})?$/.test(String(amount)) || Number(amount) > 999999999999.99) item.errors.push("Amount must be a plain positive decimal with at most two places");
    if (item.errors.length) return {...item, candidate: null, status: "held"};
    const candidate = matchInvoice(item.record, contract);
    return {...item, candidate, status: candidate.confidence === "UNMATCHED" ? "held" : "pending_review"};
  });
}

export function syntheticPeriodReport({rows, decisions, contract}) {
  if (!Array.isArray(decisions)) throw new TypeError("Decisions must be an array");
  const reviewed = prepareInvoiceReview(rows, contract);
  const seen = new Set();
  const rowIds = reviewed.map(item => String(item.rowNumber));
  if (new Set(rowIds).size !== rowIds.length) throw new Error("Duplicate source row numbers");
  if (decisions.some(d => !rowIds.includes(String(d.rowNumber)))) throw new Error("Decision references unknown row");
  let confirmedInvoiceCents = 0n;
  const entries = reviewed.map(item => {
    const matches = decisions.filter(d => String(d.rowNumber) === String(item.rowNumber));
    if (matches.length > 1) throw new Error("Conflicting or duplicate decisions");
    const decision = matches[0];
    if (decision && !["confirmed", "rejected", "pending"].includes(decision.status)) throw new Error("Unknown decision");
    if (decision?.status === "confirmed") {
      if (item.status !== "pending_review" || !item.candidate.evidence.identity || !item.candidate.evidence.period || !item.candidate.evidence.amount) {
        throw new Error("Cannot confirm an unsupported invoice candidate");
      }
      if (!decision.reviewer || !decision.evidenceRef) throw new Error("Confirmation requires reviewer and evidence");
      const invoiceId = item.record.invoice_id;
      if (seen.has(invoiceId)) throw new Error("Duplicate confirmed invoice ID");
      seen.add(invoiceId);
      confirmedInvoiceCents += amountInCents(item.record.amount);
      if (confirmedInvoiceCents > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("Confirmed invoice total exceeds safe precision");
    }
    return {rowNumber:item.rowNumber, invoiceId:item.record.invoice_id ?? null,
      status:item.status === "held" ? "held" : (decision?.status ?? "pending"),
      errors:item.errors, evidence:item.candidate?.evidence ?? null};
  });
  // An invoice-only prototype is not an audited contribution or complete revenue measure.
  return {contractId:contract.id, periodStart:contract.periodStart, periodEnd:contract.periodEnd,
    confirmedInvoiceAmount:Number(confirmedInvoiceCents) / 100, currency:"AUD",
    eligibleRevenue:null, deliveryCosts:null, contribution:null,
    completeness:"incomplete", exclusions:["Other revenue sources not verified","Payroll and other delivery costs not reconciled"],
    entries};
}

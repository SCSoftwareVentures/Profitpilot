// Synthetic-only workflow presenter. Never authorises an invoice or a financial result.
// No external effects, network calls, storage or customer data.
import {validateInvoiceRows, matchInvoice, money} from "./engine.js";

export function prepareInvoiceReview(rows, contract) {
  if (!Array.isArray(rows)) throw new TypeError("Invoice rows must be an array");
  if (!contract || !contract.id || !contract.site || !contract.periodStart || !contract.periodEnd) {
    throw new TypeError("Contract identity, site and period are required");
  }
  return validateInvoiceRows(rows).map(item => {
    if (item.errors.length) return {...item, candidate: null, status: "held"};
    const candidate = matchInvoice(item.record, contract);
    return {...item, candidate, status: candidate.confidence === "UNMATCHED" ? "held" : "pending_review"};
  });
}

export function syntheticPeriodReport({rows, decisions, contract, labourCost = null}) {
  if (!Array.isArray(decisions)) throw new TypeError("Decisions must be an array");
  const reviewed = prepareInvoiceReview(rows, contract);
  const seen = new Set();
  let eligibleRevenue = 0;
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
      eligibleRevenue = money(eligibleRevenue + Number(item.record.amount));
    }
    return {rowNumber:item.rowNumber, invoiceId:item.record.invoice_id ?? null,
      status:item.status === "held" ? "held" : (decision?.status ?? "pending"),
      errors:item.errors, evidence:item.candidate?.evidence ?? null};
  });
  // An invoice-only prototype is not an audited contribution or complete revenue measure.
  return {contractId:contract.id, periodStart:contract.periodStart, periodEnd:contract.periodEnd,
    confirmedInvoiceAmount:money(eligibleRevenue), currency:"AUD",
    eligibleRevenue:null, deliveryCosts:null, contribution:null,
    completeness:"incomplete", exclusions:["Other revenue sources not verified","Payroll and other delivery costs not reconciled"],
    entries};
}

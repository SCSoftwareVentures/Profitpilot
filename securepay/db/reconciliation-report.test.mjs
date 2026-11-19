import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync,randomUUID} from "node:crypto";
import {summarizeReport,signReport,verifySignedReport,reportCSV,renderReconciliationDashboard} from "./reconciliation-report.mjs";
const tenantId=randomUUID(),milestoneId=randomUUID();
const report={schema:"securepay-report-v1",mode:"sandbox",moneyMoved:false,tenantId,reportId:randomUUID(),generatedAt:"2026-11-19T00:00:00Z",
 checkpoint:{tenantId,last_seq:"12",last_hash:"a".repeat(64)},
 milestones:[{milestoneId,status:"disputed",fundingStatus:"funded",caseId:randomUUID(),caseStatus:"authorized",settlementId:randomUUID(),
 fundedCents:"5000",payoutCents:"3000",refundCents:"0",remainingCents:"2000",journalVerified:true,unresolvedIssues:"1",legs:[{kind:"refund",status:"unknown",amountCents:"2000",attempts:1}]}]};
test("signed export detects payload alteration and wrong signing key",()=>{
 const {privateKey,publicKey}=generateKeyPairSync("ed25519"),other=generateKeyPairSync("ed25519");
 const envelope=signReport(report,privateKey);
 assert.equal(verifySignedReport(envelope,publicKey),true);
 assert.equal(verifySignedReport(envelope,other.publicKey),false);
 const changed=structuredClone(envelope);changed.report.milestones[0].remainingCents="1999";
 assert.equal(verifySignedReport(changed,publicKey),false);
 assert.equal(verifySignedReport({...envelope,signature:"invalid"},publicKey),false);
});
test("dashboard distinguishes sandbox and buyer summary; export uses exact integer cents and rejects injected values",()=>{
 const summary=summarizeReport(report);assert.equal(summary.remainingCents,"2000");assert.equal(summary.uncertainLegs,1);
 const html=renderReconciliationDashboard(report),buyer=renderReconciliationDashboard(report,{buyerSummary:true});
 assert.match(html,/SANDBOX ONLY/);assert.match(html,/\$20\.00/);assert.ok(html.includes(milestoneId));
 assert.ok(!buyer.includes(milestoneId)&&!buyer.includes(tenantId)&&!buyer.includes(report.checkpoint.last_hash));
 assert.match(reportCSV(report),/"sandbox","[a-f0-9-]+","disputed"/);
 const invalid=structuredClone(report);invalid.milestones[0].status="<script>alert(1)</script>";
 assert.throws(()=>renderReconciliationDashboard(invalid),/Invalid milestone report/);
 assert.throws(()=>reportCSV(invalid),/Invalid milestone report/);
 const negative=structuredClone(report);negative.milestones[0].remainingCents="-1";
 assert.ok(reportCSV(negative).includes('"\'-1"'));
});

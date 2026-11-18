// Convert PostgreSQL numeric(14,2) aggregates without floating-point parsing.
export function exactAggregateCents(value){
 if(typeof value!=="string"||!/^-?\d+\.\d{2}$/.test(value))throw new TypeError("Invalid fixed-scale financial aggregate");
 const negative=value.startsWith("-");
 const [whole,fraction]=(negative?value.slice(1):value).split(".");
 const cents=BigInt(whole)*100n+BigInt(fraction);
 const signed=negative?-cents:cents;
 if(signed>BigInt(Number.MAX_SAFE_INTEGER)||signed< -BigInt(Number.MAX_SAFE_INTEGER))throw new RangeError("Financial aggregate exceeds safe cent range");
 return Number(signed);
}
export function financialTotals(revenueAggregate,costAggregate){
 const revenueCents=exactAggregateCents(revenueAggregate);
 const costCents=exactAggregateCents(costAggregate);
 const contributionCents=revenueCents-costCents;
 if(!Number.isSafeInteger(contributionCents))throw new RangeError("Contribution exceeds safe cent range");
 return {revenue:revenueCents/100,deliveryCost:costCents/100,contribution:contributionCents/100,marginPercent:revenueCents?Math.round(contributionCents/revenueCents*10000)/100:null};
}

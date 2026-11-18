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
function roundedMarginBasisPoints(contributionCents,revenueCents){
 let numerator=BigInt(contributionCents)*10000n;
 let denominator=BigInt(revenueCents);
 if(denominator<0n){numerator=-numerator;denominator=-denominator;}
 // Match Math.round tie handling without floating-point division.
 const shifted=2n*numerator+denominator;
 const divisor=2n*denominator;
 const quotient=shifted/divisor;
 const remainder=shifted%divisor;
 const rounded=quotient-(shifted<0n&&remainder!==0n?1n:0n);
 if(rounded>BigInt(Number.MAX_SAFE_INTEGER)||rounded< -BigInt(Number.MAX_SAFE_INTEGER))throw new RangeError("Margin exceeds safe basis-point range");
 return Number(rounded);
}
export function financialTotals(revenueAggregate,costAggregate){
 const revenueCents=exactAggregateCents(revenueAggregate);
 const costCents=exactAggregateCents(costAggregate);
 const contributionCents=revenueCents-costCents;
 if(!Number.isSafeInteger(contributionCents))throw new RangeError("Contribution exceeds safe cent range");
 return {revenue:revenueCents/100,deliveryCost:costCents/100,contribution:contributionCents/100,marginPercent:revenueCents?roundedMarginBasisPoints(contributionCents,revenueCents)/100:null};
}

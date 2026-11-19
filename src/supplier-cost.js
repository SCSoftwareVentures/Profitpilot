const digest=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x)&&!/^0+$/.test(x);
export const classifications=Object.freeze(["direct_site","overhead_pending","payroll_overlap","excluded"]);
export function supplierCostFields(x){if(!x||typeof x!=="object"||Array.isArray(x)||Object.keys(x).length!==3||!digest(x.intakeScopeDigest)||!classifications.includes(x.classification)||!digest(x.evidenceDigest))return null;return [x.intakeScopeDigest,x.classification,x.evidenceDigest];}

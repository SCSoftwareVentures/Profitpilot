const digest=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x)&&!/^0+$/.test(x);
export function invoiceCreditFields(x){if(!x||typeof x!=="object"||Array.isArray(x)||Object.keys(x).length!==3||!digest(x.creditReferenceDigest)||!digest(x.evidenceDigest)||typeof x.amount!=="string"||!/^(0|[1-9][0-9]{0,11})\.[0-9]{2}$/.test(x.amount)||x.amount==="0.00")return null;return [x.creditReferenceDigest,x.amount,x.evidenceDigest];}

const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export function invoiceCreditReversalFields(x){if(!x||typeof x!=="object"||Array.isArray(x)||Object.keys(x).length!==4||typeof x.reversesOrderId!=="string"||!uuid.test(x.reversesOrderId))return null;const {reversesOrderId,...rest}=x,f=invoiceCreditFields(rest);return f?[reversesOrderId,...f]:null;}

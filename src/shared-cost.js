const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const digest=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x)&&!/^0+$/.test(x);
const money=x=>typeof x==="string"&&/^(0|[1-9][0-9]{0,11})\.[0-9]{2}$/.test(x)&&x!=="0.00";
export function sharedCostFields(kind,source,input){
 if(!["payroll","overhead"].includes(kind)||typeof source!=="string"||!uuid.test(source)||!input||typeof input!=="object"||Object.keys(input).length!==2||!digest(input.evidenceDigest)||!Array.isArray(input.shares)||input.shares.length<1||input.shares.length>100)return null;
 const shares=[];let prev="";
 for(const line of input.shares){
  if(!Array.isArray(line)||line.length!==3||!money(line[2])||!(line[0]===null&&line[1]===null||typeof line[0]==="string"&&uuid.test(line[0])&&typeof line[1]==="string"&&uuid.test(line[1])))return null;
  const key=line[0]??"~";if(key<=prev)return null;prev=key;shares.push([line[0],line[1],line[2]]);
 }
 return {shares,evidence:input.evidenceDigest,canonical:["shared-cost-v1",kind,source,input.evidenceDigest,...shares.map(x=>[x[0]??"~",x[1]??"~",x[2]].join(","))].join("\n")};
}

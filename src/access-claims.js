// Validate claims after cryptographic verification, before database/session access.
const safeText=(v,max)=>typeof v==="string"&&v.length>0&&v.length<=max&&v.trim()===v&&!/[\x00-\x1f\x7f]/.test(v);
export function validAccessClaims(p,now=Math.floor(Date.now()/1000)){
 return !!p&&Number.isSafeInteger(p.iat)&&Number.isSafeInteger(p.exp)&&p.iat>=0&&p.iat<=now+5&&now-p.iat<=900&&p.exp>now&&p.exp>p.iat&&p.exp-p.iat<=900&&
  typeof p.jti==="string"&&/^[A-Za-z0-9._~-]{16,128}$/.test(p.jti)&&safeText(p.sub,512);
}

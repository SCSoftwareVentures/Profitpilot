// Strict production startup contract. Error messages identify settings, never values.
function fail(setting){throw Error("Invalid production security configuration: "+setting);}
function strictHttps(value,setting,{origin=false}={}){
 if(typeof value!=="string"||!value||value.trim()!==value||/[\x00-\x20\x7f]/.test(value))fail(setting);
 let url;try{url=new URL(value);}catch{fail(setting);}
 if(url.protocol!=="https:"||url.username||url.password||url.hash||url.search||!url.hostname)fail(setting);
 if(["localhost","127.0.0.1","[::1]"].includes(url.hostname))fail(setting);
 if(origin&&url.origin!==value)fail(setting);
 return url;
}
const clean=(v,min,max)=>typeof v==="string"&&v.length>=min&&v.length<=max&&v.trim()===v&&!/[\x00-\x1f\x7f]/.test(v);
export function assertProductionConfig(env=process.env){
 if(env.NODE_ENV!=="production")return;
 if(env.DATABASE_SSL!=="true"||env.NODE_TLS_REJECT_UNAUTHORIZED==="0")fail("verified TLS required");
 let database;
 try{database=new URL(env.DATABASE_URL);}catch{fail("DATABASE_URL");}
 if(!["postgres:","postgresql:"].includes(database.protocol)||database.username!=="profitpilot_app"||!database.password||!database.hostname||database.search||database.hash)fail("restricted DATABASE_URL");
 strictHttps(env.AUTH_ISSUER,"AUTH_ISSUER");
 strictHttps(env.AUTH_JWKS_URL,"AUTH_JWKS_URL");
 if(!clean(env.AUTH_AUDIENCE,3,256))fail("AUTH_AUDIENCE");
 if(!clean(env.AUTH_STEP_UP_ACR,3,256))fail("AUTH_STEP_UP_ACR");
 const maxAge=Number(env.AUTH_STEP_UP_MAX_AGE_SECONDS??300);
 if(!Number.isInteger(maxAge)||maxAge<30||maxAge>900)fail("AUTH_STEP_UP_MAX_AGE_SECONDS");
 const origins=(env.CORS_ORIGIN||"").split(",").map(v=>v.trim());
 if(origins.length<1||origins.length>20||new Set(origins).size!==origins.length)fail("CORS_ORIGIN");
 for(const origin of origins)strictHttps(origin,"CORS_ORIGIN",{origin:true});
 const key=env.TENANT_CONTEXT_HMAC_SECRET||"";
 if(key.length%2!==0||!/^[a-f0-9]{64,256}$/i.test(key))fail("TENANT_CONTEXT_HMAC_SECRET");
 if(!/^[A-Za-z0-9._-]{1,128}$/.test(env.TENANT_CONTEXT_HMAC_KEY_ID||"primary"))fail("TENANT_CONTEXT_HMAC_KEY_ID");
 if(env.ENABLE_SYNTHETIC_PAYROLL_UI==="true"||env.ENABLE_ATTACHMENT_QUARANTINE==="true"||env.ENABLE_SYNTHETIC_ATTACHMENT_QUARANTINE==="true"||env.TEST_ADMIN_DATABASE_URL||env.TEST_APP_DATABASE_URL)fail("synthetic service settings");
 // Administrative and recovery credentials belong on independent operator systems.
 for(const name of ["POSTGRES_ADMIN_PASSWORD","PRIVACY_ADMIN_DATABASE_URL","PRIVACY_CHECKPOINT_KEY","PRIVACY_BACKUP_ENCRYPTION_KEY"]){
  if(env[name])fail("operator credential present in API environment ("+name+")");
 }
}
export function validRuntimeRole(row){
 return !!row&&row.role==="profitpilot_app"&&row.sessionRole==="profitpilot_app"&&row.canLogin===true
 &&["superuser","bypassRls","createRole","createDb","replication","inherit","otherMembership","databaseCreate","databaseTemp","publicCreate","privateCreate"].every(flag=>row[flag]===false);
}

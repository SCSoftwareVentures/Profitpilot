export function databaseSslConfig(env=process.env){
  if(env.NODE_ENV==="production"&&env.DATABASE_SSL!=="true"){
    throw new Error("Production database connections require DATABASE_SSL=true");
  }
  if(env.DATABASE_SSL==="true"){
    if(env.DATABASE_SSL_CA&&typeof env.DATABASE_SSL_CA!=="string")throw new Error("DATABASE_SSL_CA must be a PEM certificate string");
    return {rejectUnauthorized:true,...(env.DATABASE_SSL_CA?{ca:env.DATABASE_SSL_CA}:{})};
  }
  if(env.DATABASE_SSL_CA)throw new Error("DATABASE_SSL_CA cannot be set while database TLS is disabled");
  return false;
}

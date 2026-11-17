import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";

const {Pool}=pg;
const connectionString=process.env.DATABASE_SSL_TEST_URL;
const ca=process.env.DATABASE_SSL_CA;

test("production PostgreSQL TLS accepts the configured trusted CA",{
  skip:!connectionString||!ca
},async()=>{
  const pool=new Pool({connectionString,ssl:{rejectUnauthorized:true,ca}});
  try{
    const result=await pool.query("SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()");
    assert.equal(result.rows[0]?.ssl,true,"the database session must use TLS");
  }finally{await pool.end();}
});

test("production PostgreSQL TLS rejects an untrusted CA",{
  skip:!connectionString||!ca
},async()=>{
  const pool=new Pool({connectionString,ssl:{rejectUnauthorized:true,ca:"-----BEGIN CERTIFICATE-----\nnot-a-valid-trust-anchor\n-----END CERTIFICATE-----"}});
  try{
    await assert.rejects(async()=>pool.query("SELECT 1"));
  }finally{await pool.end();}
});

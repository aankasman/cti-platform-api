import pg from 'pg';
const { Pool } = pg;
const pool = new Pool({ connectionString: process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/rinjani' });

async function run() {
  const { rows } = await pool.query("SELECT id, name, stix_id, confidence, created_by_ref FROM threat_actors WHERE name ILIKE '%APT29%';");
  console.log(rows);
  pool.end();
}
run();

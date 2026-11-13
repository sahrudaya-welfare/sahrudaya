const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const { Pool } = require('pg');

const email = process.argv[2];
if (!email) {
  console.log('Usage: node verify-member.js <member_email>');
  console.log('Example: node verify-member.js vikramkkarthik10@gmail.com');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function run() {
  try {
    const res = await pool.query(
      'UPDATE members SET is_verified = true, verified_at = NOW(), verification_token = NULL WHERE LOWER(email) = LOWER($1) RETURNING id, name, email, is_verified',
      [email.trim()]
    );
    if (!res.rowCount) {
      console.log(`❌ No member found with email: ${email}`);
    } else {
      console.log(`✅ Member successfully verified:`, res.rows[0]);
    }
  } catch (err) {
    console.error('Error verifying member:', err.message);
  } finally {
    await pool.end();
  }
}

run();


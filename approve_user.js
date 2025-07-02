const { Pool } = require('pg');
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

console.log('Connected to Neon/Postgres database');

const email = process.argv[2];
if (!email) {
  console.error('Usage: node approve_user.js user@email.com');
  process.exit(1);
}

pool.query('UPDATE users SET verificationStatus = $1 WHERE email = $2', ['verified', email])
  .then(result => {
    if (result.rowCount === 0) {
      console.log('No user found with that email.');
    } else {
      console.log('User approved!');
    }
  })
  .catch(err => {
    console.error('Error approving user:', err.message);
  })
  .finally(() => {
    pool.end();
  }); 
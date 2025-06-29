const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('./users.db');

const email = process.argv[2];
if (!email) {
  console.error('Usage: node approve_user.js user@email.com');
  process.exit(1);
}

db.run('UPDATE users SET verificationStatus = ? WHERE email = ?', ['verified', email], function(err) {
  if (err) {
    console.error('Error approving user:', err.message);
  } else if (this.changes === 0) {
    console.log('No user found with that email.');
  } else {
    console.log('User approved!');
  }
  db.close();
}); 
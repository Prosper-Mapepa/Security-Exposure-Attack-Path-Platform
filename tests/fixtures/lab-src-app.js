const db = { query() {} };

function lookupUser(req, res) {
  const query = 'SELECT id, email FROM users WHERE id = ' + req.params.id;
  db.query(query);
  res.json({ id: req.params.id });
}

function readOrder(req, res) {
  res.json({ id: req.params.id, owner: 'unchecked' });
}

const password = 'lab-only-password';
const awsAccessKeyId = 'AKIAWZ3K7M4N6P2Q5R7S';

module.exports = { lookupUser, readOrder, password, awsAccessKeyId };

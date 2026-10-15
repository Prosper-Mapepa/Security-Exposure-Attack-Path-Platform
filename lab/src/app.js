const db = { query() {} };

function lookupUser(req, res) {
  db.query('SELECT id, email FROM users WHERE id = $1', [req.params.id]);
  res.json({ id: req.params.id });
}

function readOrder(req, res) {
  if (req.user?.id !== req.params.ownerId) {
    res.status(403).json({ error: 'forbidden' });
    return;
  }
  res.json({ id: req.params.id });
}

module.exports = { lookupUser, readOrder };

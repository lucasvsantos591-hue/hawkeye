// Sample safe app - dependencies have vulns but they're not used in exploitable way

const express = require('express');
const _ = require('lodash');

const app = express();
app.use(express.json());

// SAFE: Only using safe lodash functions
app.get('/api/users', (req, res) => {
  const users = [
    { id: 1, name: 'Alice' },
    { id: 2, name: 'Bob' },
  ];

  // Using only lodash.map (safe function)
  const result = _.map(users, 'name');
  res.json({ result });
});

// SAFE: Using express routing (safe)
app.post('/api/user', (req, res) => {
  const { name } = req.body;
  res.json({ created: name });
});

// SAFE: Using lodash.filter (safe function)
app.get('/api/filter', (req, res) => {
  const data = [1, 2, 3, 4, 5];
  const result = _.filter(data, (x) => x > 2);
  res.json({ result });
});

app.listen(3000, () => {
  console.log('Safe server running on port 3000');
});

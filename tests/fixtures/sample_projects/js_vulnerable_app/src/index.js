// Sample vulnerable app using express 4.16.0
// CVE-2018-3721: lodash.template vulnerability

const express = require('express');
const _ = require('lodash');

const app = express();
app.use(express.json());

// VULNERABLE: Using lodash.template with user input (CVE-2018-3721)
app.post('/render', (req, res) => {
  const { template, data } = req.body;

  try {
    // This is vulnerable - user input goes directly to template
    const compiled = _.template(template);
    const result = compiled(data);
    res.json({ result });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// SAFE: Using lodash.map (vulnerable function not called)
app.get('/map', (req, res) => {
  const data = [1, 2, 3, 4, 5];
  const result = _.map(data, (x) => x * 2);
  res.json({ result });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});

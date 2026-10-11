const express = require('express');
const axios = require('axios');
const got = require('got');
const superagent = require('superagent');

const app = express();

// A request-chosen URL that is parsed, converted or decoded first, given to an HTTP client's get()
// that is not awaited in place. Each client is used once: in this file no other call makes it
// request data.
app.get('/clients/wrapped', async (req, res) => {
  const parsed = axios.get(new URL(req.query.url));
  // ruleid: js.xss
  res.send((await parsed).data);
  const converted = got.get(String(req.query.url));
  // ruleid: js.xss
  res.send(await converted.text());
  const decoded = superagent.get(decodeURIComponent(req.query.url));
  // ruleid: js.xss
  res.send((await decoded).text);
});

module.exports = app;

import express from 'express';
import axios from 'axios';
import got from 'got';
import superagent from 'superagent';
import { execFile } from './tasks.mjs';
import * as tasks from './tasks.mjs';

const app = express();

// execFile() of an application module is no child_process call: what it hands to its callback
// is that module's data.
app.get('/tasks/run', (req, res) => {
  // ok: js.xss
  execFile('echo', [req.query.msg], (err, out) => res.send(out));
  // ok: js.xss
  tasks.execFile('echo', [req.query.msg], (err, out) => res.send(out));
  // ruleid: js.xss
  res.send('<p>' + req.query.msg + '</p>');
});

// The get() of an HTTP client (axios, got, superagent) given a URL on a fixed origin, not awaited
// in place: the page is that service's data, and the client does not become request data for the
// calls after it (no get() in this file has a request-chosen URL).
app.get('/clients/items/:id', async (req, res) => {
  const pendingItem = axios.get('https://api.example.com/items/' + req.params.id);
  const { data: item } = await pendingItem;
  // ok: js.xss
  res.send(item);
  const pending = axios.get('https://api.example.com/status');
  const { data: status } = await pending;
  // ok: js.xss
  res.send(status);
  const later = got.get(`https://api.example.com/items/${req.params.id}`);
  // ok: js.xss
  res.send(await later.text());
  const card = superagent.get('https://api.example.com/cards/' + req.params.id);
  // ok: js.xss
  res.send((await card).text);
});

export default app;

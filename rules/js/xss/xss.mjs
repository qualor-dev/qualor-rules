import express from 'express';
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

export default app;

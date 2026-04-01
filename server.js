'use strict';

const fs   = require('fs');
const path = require('path');
const envFile = path.join(__dirname, '.env');
if (fs.existsSync(envFile)) {
  for (const line of fs.readFileSync(envFile, 'utf8').split('\n')) {
    const m = line.match(/^([A-Z_][A-Z0-9_]*)=(.*)$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].trim();
  }
}

const net    = require('net');
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { exec, spawn } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

const app = express();
app.use(express.json());

// ─── Request Logger Middleware (registered early; log() is hoisted) ───────────
app.use((req, res, next) => {
  if (!req.path.startsWith('/api')) return next();
  const t0 = Date.now();
  const body = req.method !== 'GET' ? JSON.stringify(req.body || {}).slice(0, 200) : undefined;
  res.on('finish', () => {
    const ms = Date.now() - t0;
    const level = res.statusCode >= 500 ? 'ERROR' : res.statusCode >= 400 ? 'WARN' : 'INFO';
    const details = { status: res.statusCode, ms };
    if (body) details.body = body;
    log(level, 'API', `${req.method} ${req.path}`, details);
  });
  next();
});

// Serve index.html with MC_BASE injected so the frontend knows its sub-path
app.get('/', (req, res) => {
  let html = fs.readFileSync(path.join(__dirname, 'public/index.html'), 'utf8');
  html = html.replace(
    '</head>',
    `<script>window.MC_BASE=${JSON.stringify(BASE_PATH)};</script>\n</head>`
  );
  res.setHeader('Content-Type', 'text/html');
  res.send(html);
});

app.use(express.static(path.join(__dirname, 'public')));

// ─── Pi Fleet Config ──────────────────────────────────────────────────────────
const SSH_USER = process.env.SSH_USER     || 'jamil';
const SSH_KEY  = process.env.SSH_KEY_PATH || (process.env.HOME + '/.ssh/id_ed25519');
const OC_TOKEN = process.env.OC_TOKEN     || 'REDACTED_OC_TOKEN';
const PORT     = parseInt(process.env.PORT || '8095');

// On Windows (non-Docker direct run), use `wsl ssh`. In Docker (Linux), use node-ssh.
const USE_WSL_SSH = process.platform === 'win32' || process.env.USE_WSL_SSH === 'true';
const BASE_PATH   = (process.env.BASE_PATH || '').replace(/\/$/, ''); // e.g. "/mc" or ""

const PIES = [
  {
    id: 'pi1', label: 'RASPBERRYPI1',
    host: process.env.PI1_HOST || '192.0.2.101',
    user: SSH_USER,
    ocHome: `/home/${SSH_USER}/.openclaw`,
    gatewayPort: 18791,
  },
  {
    id: 'pi2', label: 'RASPBERRYPI2',
    host: process.env.PI2_HOST || '192.0.2.102',
    user: SSH_USER,
    ocHome: `/home/${SSH_USER}/.openclaw`,
    gatewayPort: 18791,
  },
  {
    id: 'pi3', label: 'RASPBERRYPI3',
    host: process.env.PI3_HOST || '192.0.2.103',
    user: SSH_USER,
    ocHome: `/home/${SSH_USER}/.openclaw`,
    gatewayPort: 18791,
  },
];

// Pi1 is the primary (for intel scans etc.)
const PRIMARY_PI = PIES[0];

// ─── Data Store ───────────────────────────────────────────────────────────────
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function readJson(file, def) {
  try {
    const p = path.join(DATA_DIR, file);
    return fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, 'utf8')) : def;
  } catch { return def; }
}
function writeJson(file, data) {
  fs.writeFileSync(path.join(DATA_DIR, file), JSON.stringify(data, null, 2));
}
function nextId(counterFile, prefix) {
  const counter = readJson(counterFile, { n: 0 });
  counter.n += 1;
  writeJson(counterFile, counter);
  return `${prefix}-${String(counter.n).padStart(3, '0')}`;
}

// ─── Logger ───────────────────────────────────────────────────────────────────
const LOG_FILE = path.join(DATA_DIR, 'logs.jsonl');
const LOG_MAX  = 10000;  // rotate when this many lines accumulate
const LOG_TRIM = 5000;   // keep this many after rotation
let _logWriteCount = 0;

function log(level, source, event, details) {
  const entry = { ts: new Date().toISOString(), level, source, event };
  if (details && Object.keys(details).length) entry.details = details;
  try { fs.appendFileSync(LOG_FILE, JSON.stringify(entry) + '\n'); } catch (e) { /* disk full etc */ }
  // Console echo (suppress DEBUG to avoid noise)
  if (level === 'ERROR') console.error(`[${level}] [${source}] ${event}`, details?.error || '');
  else if (level !== 'DEBUG') console.log(`[${level}] [${source}] ${event}`);
  // Periodic rotation
  if ((++_logWriteCount % 200) === 0) trimLogs();
}

function trimLogs() {
  try {
    if (!fs.existsSync(LOG_FILE)) return;
    const lines = fs.readFileSync(LOG_FILE, 'utf8').split('\n').filter(Boolean);
    if (lines.length > LOG_MAX) {
      fs.writeFileSync(LOG_FILE, lines.slice(-LOG_TRIM).join('\n') + '\n');
      log('INFO', 'SYSTEM', 'log:rotated', { kept: LOG_TRIM, dropped: lines.length - LOG_TRIM });
    }
  } catch {}
}

// ─── Network Probe ────────────────────────────────────────────────────────────
// Lightweight TCP reachability check — doesn't require SSH auth to succeed
function tcpProbe(host, port, timeoutMs = 3000) {
  return new Promise(resolve => {
    const sock = net.createConnection({ host, port });
    const timer = setTimeout(() => { sock.destroy(); resolve(false); }, timeoutMs);
    sock.on('connect', () => { clearTimeout(timer); sock.destroy(); resolve(true); });
    sock.on('error',   () => { clearTimeout(timer); resolve(false); });
    sock.on('close',   () => { clearTimeout(timer); resolve(false); });
  });
}

// ─── SSH ──────────────────────────────────────────────────────────────────────
async function sshExecPi(pi, cmd) {
  const cmdSummary = cmd.replace(/\s+/g, ' ').slice(0, 120);
  const t0 = Date.now();
  if (USE_WSL_SSH) {
    const escaped = cmd.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    try {
      const { stdout } = await execAsync(
        `wsl ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 ${pi.user}@${pi.host} "${escaped}"`,
        { timeout: 15000 }
      );
      log('DEBUG', 'SSH', 'exec:ok', { pi: pi.id, host: pi.host, ms: Date.now()-t0, cmd: cmdSummary });
      return stdout || '';
    } catch (e) {
      log('WARN', 'SSH', 'exec:fail', { pi: pi.id, host: pi.host, ms: Date.now()-t0, cmd: cmdSummary, error: e.message?.slice(0, 120) });
      console.error(`WSL SSH (${pi.id}):`, e.message?.slice(0, 120));
      return null;
    }
  }
  if (!fs.existsSync(SSH_KEY)) {
    log('ERROR', 'SSH', 'exec:no-key', { pi: pi.id, keyPath: SSH_KEY });
    return null;
  }
  const ssh = new (require('node-ssh').NodeSSH)();
  try {
    await ssh.connect({ host: pi.host, username: pi.user, privateKeyPath: SSH_KEY, readyTimeout: 5000 });
    const { stdout } = await ssh.execCommand(cmd);
    ssh.dispose();
    log('DEBUG', 'SSH', 'exec:ok', { pi: pi.id, host: pi.host, ms: Date.now()-t0, cmd: cmdSummary });
    return stdout || '';
  } catch (e) {
    log('WARN', 'SSH', 'exec:fail', { pi: pi.id, host: pi.host, ms: Date.now()-t0, cmd: cmdSummary, error: e.message?.slice(0, 120) });
    console.error(`SSH (${pi.id}):`, e.message?.slice(0, 120));
    return null;
  }
}

async function sshWritePi(pi, remotePath, content) {
  const t0 = Date.now();
  if (USE_WSL_SSH) {
    const b64 = Buffer.from(content).toString('base64');
    const ok = (await sshExecPi(pi, `echo ${b64} | base64 -d > ${remotePath}`)) !== null;
    log(ok ? 'DEBUG' : 'WARN', 'SSH', ok ? 'write:ok' : 'write:fail', { pi: pi.id, path: remotePath, bytes: content.length, ms: Date.now()-t0 });
    return ok;
  }
  if (!fs.existsSync(SSH_KEY)) {
    log('ERROR', 'SSH', 'write:no-key', { pi: pi.id, keyPath: SSH_KEY });
    return false;
  }
  const ssh = new (require('node-ssh').NodeSSH)();
  try {
    await ssh.connect({ host: pi.host, username: pi.user, privateKeyPath: SSH_KEY, readyTimeout: 5000 });
    await ssh.execCommand(`cat > ${remotePath}`, { stdin: content });
    ssh.dispose();
    log('DEBUG', 'SSH', 'write:ok', { pi: pi.id, path: remotePath, bytes: content.length, ms: Date.now()-t0 });
    return true;
  } catch (e) {
    log('WARN', 'SSH', 'write:fail', { pi: pi.id, path: remotePath, ms: Date.now()-t0, error: e.message?.slice(0, 120) });
    console.error(`SSH write (${pi.id}):`, e.message?.slice(0, 120));
    return false;
  }
}

async function fetchGatewayPi(pi) {
  const raw = await sshExecPi(
    pi,
    `curl -s --connect-timeout 3 -H "Authorization: Bearer ${OC_TOKEN}" http://localhost:${pi.gatewayPort}/ 2>/dev/null`
  );
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

// ─── Task Scoring ─────────────────────────────────────────────────────────────
function scoreTasks(allTasks, targets) {
  const recent = [...allTasks]
    .filter(t => t.status !== 'queue')
    .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt))
    .slice(0, 5);

  const recentKeywords = new Set(
    recent.flatMap(t => [
      ...(t.tags || []),
      ...t.title.toLowerCase().replace(/[^a-z0-9\s]/g, '').split(/\s+/).filter(w => w.length > 2),
    ])
  );

  return (targets || allTasks).map(t => {
    const taskWords = new Set([
      ...(t.tags || []),
      ...t.title.toLowerCase().replace(/[^a-z0-9\s]/g, '').split(/\s+/).filter(w => w.length > 2),
    ]);
    const intersection = [...taskWords].filter(w => recentKeywords.has(w)).length;
    const union = new Set([...taskWords, ...recentKeywords]).size;
    const momentum = union > 0
      ? Math.min(10, Math.round((intersection / Math.min(union, 8)) * 10 * 10) / 10 + 3)
      : 3;
    const descLen = (t.description || '').length;
    const baseF = 8 - Math.min(5, Math.floor(descLen / 300));
    const priorityAdj = t.priority === 'low' ? 1 : t.priority === 'high' ? -1 : 0;
    const feasibility = Math.max(1, Math.min(10, baseF + priorityAdj));
    return { ...t, momentumScore: Math.round(momentum * 10) / 10, feasibilityScore: feasibility };
  });
}

// ─── Dispatch System ──────────────────────────────────────────────────────────
const taskWriteDebounce = new Map();

async function getAvailablePi() {
  const tasks = readJson('tasks.json', []);
  for (const pi of PIES) {
    const reachRaw = await sshExecPi(pi, 'echo ok');
    if (reachRaw === null) continue;
    const hasInProgress = tasks.some(t => t.status === 'in-progress' && t.assignedPi === pi.id);
    if (!hasInProgress) return pi;
  }
  return null;
}

async function runComprehensionAgent(pi, task) {
  const prompt = `You are a task briefing agent for an autonomous software lab. Rewrite the following task as a clear, specific, step-by-step brief for a software agent that has no prior context. Explain what needs to be done, why it matters, what success looks like, and any important constraints. Be precise but not verbose. Use plain language. Do not use markdown headers — just numbered steps and clear prose.

TASK TITLE: ${task.title}
TASK DESCRIPTION: ${task.description || 'No description provided.'}
TAGS: ${(task.tags || []).join(', ') || 'none'}
TASK ID: ${task.id}`;

  try {
    await sshExecPi(pi, `mkdir -p ~/.openclaw/workspace/tasks/${task.id}`);
    await sshWritePi(pi, `~/.openclaw/workspace/tasks/${task.id}/COMPREHEND.md`, prompt);
    const raw = await sshExecPiTimeout(pi, `bash -lc "claude -p --output-format json --input-format text --permission-mode acceptEdits < ~/.openclaw/workspace/tasks/${task.id}/COMPREHEND.md 2>/dev/null"`, 30000);
    if (!raw) return task.description || 'No description provided.';
    const parsed = JSON.parse(raw);
    return parsed.result || task.description || 'No description provided.';
  } catch (e) {
    log('WARN', 'DISPATCH', 'comprehension:fail', { taskId: task.id, error: e.message?.slice(0, 120) });
    return task.description || 'No description provided.';
  }
}

async function sshExecPiTimeout(pi, cmd, timeoutMs) {
  const cmdSummary = cmd.replace(/\s+/g, ' ').slice(0, 120);
  const t0 = Date.now();
  if (USE_WSL_SSH) {
    const escaped = cmd.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    try {
      const { stdout } = await execAsync(
        `wsl ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 ${pi.user}@${pi.host} "${escaped}"`,
        { timeout: timeoutMs }
      );
      return stdout || '';
    } catch (e) {
      log('WARN', 'SSH', 'exec:timeout-or-fail', { pi: pi.id, ms: Date.now()-t0, cmd: cmdSummary, error: e.message?.slice(0, 120) });
      return null;
    }
  }
  if (!fs.existsSync(SSH_KEY)) return null;
  const ssh = new (require('node-ssh').NodeSSH)();
  try {
    await ssh.connect({ host: pi.host, username: pi.user, privateKeyPath: SSH_KEY, readyTimeout: 5000 });
    const { stdout } = await ssh.execCommand(cmd, { execOptions: { timeout: timeoutMs } });
    ssh.dispose();
    return stdout || '';
  } catch (e) {
    log('WARN', 'SSH', 'exec:timeout-or-fail', { pi: pi.id, ms: Date.now()-t0, cmd: cmdSummary, error: e.message?.slice(0, 120) });
    return null;
  }
}

async function dispatchTask(task, pi) {
  // Step 1: update task to in-progress
  {
    const tasks = readJson('tasks.json', []);
    const idx = tasks.findIndex(t => t.id === task.id);
    if (idx === -1) return;
    const now = new Date().toISOString();
    tasks[idx] = {
      ...tasks[idx],
      status: 'in-progress',
      assignedPi: pi.id,
      startedAt: now,
      updatedAt: now,
      activityLog: [...(tasks[idx].activityLog || []), { ts: now, action: 'Dispatched to ' + pi.label, by: 'system' }],
    };
    writeJson('tasks.json', tasks);
    log('INFO', 'DISPATCH', 'task:dispatched', { taskId: task.id, pi: pi.id });
  }

  // Step 2: run comprehension agent
  const brief = await runComprehensionAgent(pi, task);

  // Step 3: store brief
  {
    const tasks = readJson('tasks.json', []);
    const idx = tasks.findIndex(t => t.id === task.id);
    if (idx !== -1) {
      const now = new Date().toISOString();
      tasks[idx] = {
        ...tasks[idx],
        brief,
        updatedAt: now,
        activityLog: [...(tasks[idx].activityLog || []), { ts: now, action: 'Comprehension complete', by: 'system' }],
      };
      writeJson('tasks.json', tasks);
    }
  }

  // Step 4: write TASK.md to Pi
  await sshExecPi(pi, `mkdir -p ~/.openclaw/workspace/tasks/${task.id}`);
  await sshWritePi(pi, `~/.openclaw/workspace/tasks/${task.id}/TASK.md`, brief);

  // Step 5: spawn Claude Code via SSH (streaming)
  const claudeCmd = `bash -lc "cd ~/.openclaw/workspace/tasks/${task.id} && claude -p --output-format stream-json --verbose --permission-mode acceptEdits --allowedTools all < TASK.md 2>&1"`;
  let sshProc;
  if (USE_WSL_SSH) {
    sshProc = spawn('wsl', ['ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=10', `${pi.user}@${pi.host}`, claudeCmd]);
  } else {
    sshProc = spawn('ssh', ['-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=10', '-i', SSH_KEY, `${pi.user}@${pi.host}`, claudeCmd]);
  }

  log('INFO', 'DISPATCH', 'task:claude-started', { taskId: task.id, pi: pi.id });

  let stdoutBuf = '';
  sshProc.stdout.on('data', (chunk) => {
    stdoutBuf += chunk.toString();
    const lines = stdoutBuf.split('\n');
    stdoutBuf = lines.pop(); // keep incomplete line
    for (const line of lines) {
      if (!line.trim()) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { continue; }
      if (msg.type === 'assistant' && Array.isArray(msg.message?.content)) {
        const text = msg.message.content.filter(c => c.type === 'text').map(c => c.text).join('');
        if (text.length > 0) {
          const now = Date.now();
          const lastWrite = taskWriteDebounce.get(task.id) || 0;
          if (now - lastWrite > 2000) {
            taskWriteDebounce.set(task.id, now);
            const tasks = readJson('tasks.json', []);
            const idx = tasks.findIndex(t => t.id === task.id);
            if (idx !== -1) {
              tasks[idx].activityLog = [
                ...(tasks[idx].activityLog || []),
                { ts: new Date().toISOString(), action: 'output', text: text.slice(0, 600), by: 'agent' },
              ];
              tasks[idx].updatedAt = new Date().toISOString();
              writeJson('tasks.json', tasks);
            }
          }
        }
      }
    }
  });

  sshProc.on('close', (code) => {
    const tasks = readJson('tasks.json', []);
    const idx = tasks.findIndex(t => t.id === task.id);
    if (idx === -1) return;
    const now = new Date().toISOString();
    if (code === 0) {
      tasks[idx].status = 'completed';
      tasks[idx].completedAt = now;
      tasks[idx].updatedAt = now;
      tasks[idx].activityLog = [...(tasks[idx].activityLog || []), { ts: now, action: 'Task completed', by: 'system' }];
      log('INFO', 'DISPATCH', 'task:completed', { taskId: task.id, pi: pi.id });
    } else {
      tasks[idx].status = 'failed';
      tasks[idx].updatedAt = now;
      tasks[idx].activityLog = [...(tasks[idx].activityLog || []), { ts: now, action: `Task failed (exit ${code})`, by: 'system' }];
      log('WARN', 'DISPATCH', 'task:failed', { taskId: task.id, pi: pi.id, code });
    }
    writeJson('tasks.json', tasks);
    writeKnowledgeBase(pi, tasks[idx]);
    setTimeout(() => tryDispatchNext(), 1000);
  });

  sshProc.on('error', (err) => {
    log('ERROR', 'DISPATCH', 'task:spawn-error', { taskId: task.id, pi: pi.id, error: err.message });
    const tasks = readJson('tasks.json', []);
    const idx = tasks.findIndex(t => t.id === task.id);
    if (idx !== -1) {
      const now = new Date().toISOString();
      tasks[idx].status = 'failed';
      tasks[idx].updatedAt = now;
      tasks[idx].activityLog = [...(tasks[idx].activityLog || []), { ts: now, action: `Task failed: ${err.message}`, by: 'system' }];
      writeJson('tasks.json', tasks);
    }
    tryDispatchNext();
  });
}

async function tryDispatchNext() {
  const tasks = readJson('tasks.json', []);
  const priorityOrder = { high: 1, medium: 2, low: 3 };
  const queued = tasks
    .filter(t => t.status === 'queue')
    .sort((a, b) => {
      const pa = priorityOrder[a.priority] || 2;
      const pb = priorityOrder[b.priority] || 2;
      if (pa !== pb) return pa - pb;
      return new Date(a.createdAt) - new Date(b.createdAt);
    });
  if (!queued.length) return;
  const task = queued[0];

  // Try local dispatch first (if not already running)
  if (!localDispatchRunning) {
    localDispatchRunning = true;
    dispatchTaskLocal(task); // fire and forget
    return;
  }

  // Fall back to SSH Pi dispatch
  const pi = await getAvailablePi();
  if (!pi) return;
  dispatchTask(task, pi); // fire and forget
}

async function writeKnowledgeBase(pi, task) {
  try {
    const outputEntries = (task.activityLog || []).filter(e => e.action === 'output').slice(-10);
    let duration = 'unknown';
    if (task.startedAt && task.completedAt) {
      const ms = new Date(task.completedAt) - new Date(task.startedAt);
      const totalSec = Math.floor(ms / 1000);
      const hours = Math.floor(totalSec / 3600);
      const mins = Math.floor((totalSec % 3600) / 60);
      const secs = totalSec % 60;
      if (hours > 0) duration = `${hours}h ${mins}m`;
      else duration = `${mins}m ${secs}s`;
    }
    const md = `# ${task.id}: ${task.title}
Completed: ${task.completedAt || 'unknown'}
Pi: ${pi.label}
Duration: ${duration}

## Task Brief
${task.brief || task.description || 'No brief available.'}

## Output Log
${outputEntries.map(e => e.text).join('\n\n---\n\n')}
`;
    await sshExecPi(pi, 'mkdir -p ~/.openclaw/workspace/task-knowledge');
    await sshWritePi(pi, `~/.openclaw/workspace/task-knowledge/${task.id}-summary.md`, md);
    log('INFO', 'DISPATCH', 'task:kb-written', { taskId: task.id, pi: pi.id });
  } catch (e) {
    log('WARN', 'DISPATCH', 'task:kb-fail', { taskId: task.id, error: e.message?.slice(0, 120) });
  }
}

// ─── Local Dispatch (claude subprocess) ──────────────────────────────────────
let localDispatchRunning = false;

async function runComprehensionAgentLocal(task, taskDir) {
  const prompt = `You are a task briefing agent for an autonomous software lab. Rewrite the following task as a clear, specific, step-by-step brief for a software agent that has no prior context. Explain what needs to be done, why it matters, what success looks like, and any important constraints. Be precise but not verbose. Use plain language. Do not use markdown headers — just numbered steps and clear prose.

TASK TITLE: ${task.title}
TASK DESCRIPTION: ${task.description || 'No description provided.'}
TAGS: ${(task.tags || []).join(', ') || 'none'}
TASK ID: ${task.id}`;

  const comprehendPath = path.join(taskDir, 'COMPREHEND.md');
  fs.writeFileSync(comprehendPath, prompt);
  try {
    const { stdout } = await execAsync(
      `claude -p --permission-mode acceptEdits < COMPREHEND.md 2>/dev/null`,
      { timeout: 60000, cwd: taskDir }
    );
    return stdout.trim() || task.description || 'No description provided.';
  } catch (e) {
    log('WARN', 'DISPATCH', 'task:local-comprehension-fail', { taskId: task.id, error: e.message?.slice(0, 120) });
    return task.description || 'No description provided.';
  }
}

async function dispatchTaskLocal(task) {
  // Step 1: mark in-progress
  {
    const tasks = readJson('tasks.json', []);
    const idx = tasks.findIndex(t => t.id === task.id);
    if (idx === -1) { localDispatchRunning = false; return; }
    const now = new Date().toISOString();
    tasks[idx] = {
      ...tasks[idx],
      status: 'in-progress',
      assignedPi: 'local',
      startedAt: now,
      updatedAt: now,
      activityLog: [...(tasks[idx].activityLog || []),
        { ts: now, action: 'Dispatched to LOCAL AGENT', by: 'system' }],
    };
    writeJson('tasks.json', tasks);
    log('INFO', 'DISPATCH', 'task:local-start', { taskId: task.id });
  }

  const taskDir = path.join(DATA_DIR, 'tasks', task.id);
  fs.mkdirSync(taskDir, { recursive: true });

  // Step 2: comprehension brief
  const brief = await runComprehensionAgentLocal(task, taskDir);
  {
    const tasks = readJson('tasks.json', []);
    const idx = tasks.findIndex(t => t.id === task.id);
    if (idx !== -1) {
      const now = new Date().toISOString();
      tasks[idx].brief = brief;
      tasks[idx].updatedAt = now;
      tasks[idx].activityLog = [...(tasks[idx].activityLog || []),
        { ts: now, action: 'Comprehension complete', by: 'system' }];
      writeJson('tasks.json', tasks);
    }
  }

  // Step 3: write TASK.md
  fs.writeFileSync(path.join(taskDir, 'TASK.md'), brief);

  // Step 4: spawn claude locally — same stream-json pattern as Pi dispatch
  const claudeProc = spawn('sh', ['-c',
    'claude -p --output-format stream-json --verbose --permission-mode acceptEdits --allowedTools all < TASK.md 2>&1'
  ], { cwd: taskDir });

  log('INFO', 'DISPATCH', 'task:local-claude-started', { taskId: task.id });

  let stdoutBuf = '';
  claudeProc.stdout.on('data', (chunk) => {
    stdoutBuf += chunk.toString();
    const lines = stdoutBuf.split('\n');
    stdoutBuf = lines.pop();
    for (const line of lines) {
      if (!line.trim()) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { continue; }
      if (msg.type === 'assistant' && Array.isArray(msg.message?.content)) {
        const text = msg.message.content.filter(c => c.type === 'text').map(c => c.text).join('');
        if (text.length > 0) {
          const now = Date.now();
          const lastWrite = taskWriteDebounce.get(task.id) || 0;
          if (now - lastWrite > 2000) {
            taskWriteDebounce.set(task.id, now);
            const tasks = readJson('tasks.json', []);
            const idx = tasks.findIndex(t => t.id === task.id);
            if (idx !== -1) {
              tasks[idx].activityLog = [
                ...(tasks[idx].activityLog || []),
                { ts: new Date().toISOString(), action: 'output', text: text.slice(0, 600), by: 'agent' },
              ];
              tasks[idx].updatedAt = new Date().toISOString();
              writeJson('tasks.json', tasks);
            }
          }
        }
      }
    }
  });

  claudeProc.on('close', (code) => {
    const tasks = readJson('tasks.json', []);
    const idx = tasks.findIndex(t => t.id === task.id);
    if (idx === -1) { localDispatchRunning = false; return; }
    const now = new Date().toISOString();
    if (code === 0) {
      tasks[idx].status = 'completed';
      tasks[idx].completedAt = now;
      tasks[idx].updatedAt = now;
      tasks[idx].activityLog = [...(tasks[idx].activityLog || []),
        { ts: now, action: 'Task completed', by: 'system' }];
      log('INFO', 'DISPATCH', 'task:local-completed', { taskId: task.id });
    } else {
      tasks[idx].status = 'failed';
      tasks[idx].updatedAt = now;
      tasks[idx].activityLog = [...(tasks[idx].activityLog || []),
        { ts: now, action: `Task failed (exit ${code})`, by: 'system' }];
      log('WARN', 'DISPATCH', 'task:local-failed', { taskId: task.id, code });
    }
    writeJson('tasks.json', tasks);
    localDispatchRunning = false;
    setTimeout(() => tryDispatchNext(), 1000);
  });

  claudeProc.on('error', (err) => {
    log('ERROR', 'DISPATCH', 'task:local-spawn-error', { taskId: task.id, error: err.message });
    const tasks = readJson('tasks.json', []);
    const idx = tasks.findIndex(t => t.id === task.id);
    if (idx !== -1) {
      const now = new Date().toISOString();
      tasks[idx].status = 'failed';
      tasks[idx].updatedAt = now;
      tasks[idx].activityLog = [...(tasks[idx].activityLog || []),
        { ts: now, action: `Failed: ${err.message}`, by: 'system' }];
      writeJson('tasks.json', tasks);
    }
    localDispatchRunning = false;
    tryDispatchNext();
  });
}

// ─── Routes: Agents (all Pis) ─────────────────────────────────────────────────
app.get('/api/agents', async (req, res) => {
  const piResults = await Promise.all(PIES.map(async pi => {
    const [networkUp, gwData, ocRaw, workspaceRaw] = await Promise.all([
      tcpProbe(pi.host, 22, 3000),
      fetchGatewayPi(pi),
      sshExecPi(pi, `cat ${pi.ocHome}/openclaw.json 2>/dev/null`),
      sshExecPi(pi, `stat -c "%Y %n" ${pi.ocHome}/workspace*/MEMORY.md ${pi.ocHome}/workspace*/*.md 2>/dev/null | sort -rn | head -20`),
    ]);

    const piReachable = networkUp;  // network-level reachability (TCP probe)
    const sshReachable = ocRaw !== null;  // SSH + data available
    let agents = [{ id: 'main', name: 'MAIN', model: 'anthropic/claude-sonnet-4-6' }];

    if (ocRaw) {
      try {
        const oc = JSON.parse(ocRaw);
        agents = (oc.agents?.list || []).map(a => ({
          id: a.id,
          name: a.name || a.id.toUpperCase(),
          model: a.model?.primary || oc.agents?.defaults?.model?.primary || 'unknown',
          workspace: a.workspace || null,
        }));
      } catch {}
    }

    const activityMap = {};
    if (workspaceRaw) {
      for (const line of workspaceRaw.trim().split('\n')) {
        const [ts, ...rest] = line.split(' ');
        const filePath = rest.join(' ');
        const wsMatch = filePath.match(/workspace(?:-([^/]+))?/);
        if (wsMatch) {
          const agentId = wsMatch[1] || 'main';
          if (!activityMap[agentId] || parseInt(ts) > activityMap[agentId]) {
            activityMap[agentId] = parseInt(ts) * 1000;
          }
        }
      }
    }

    const now = Date.now();
    agents = agents.map(a => {
      const lastMs = activityMap[a.id] || null;
      const idleMs = lastMs ? now - lastMs : null;
      return {
        ...a,
        pi: pi.id,
        piLabel: pi.label,
        lastActiveAt: lastMs ? new Date(lastMs).toISOString() : null,
        idleMs,
        status: !piReachable ? 'offline'
          : !sshReachable ? 'dormant'
          : idleMs === null ? 'dormant'
          : idleMs < 5 * 60 * 1000 ? 'active'
          : idleMs < 60 * 60 * 1000 ? 'idle'
          : 'dormant',
      };
    });

    return {
      id: pi.id,
      label: pi.label,
      host: pi.host,
      reachable: piReachable,
      agents,
      gateway: gwData ? { ...gwData, reachable: true } : { reachable: false },
    };
  }));

  const allAgents = piResults.flatMap(p => p.agents);
  const primaryGateway = piResults[0]?.gateway || { reachable: false };

  res.json({
    agents: allAgents,
    gateway: primaryGateway,
    piReachable: piResults.some(p => p.reachable),
    pis: piResults,
  });
});

// ─── Routes: Tasks ────────────────────────────────────────────────────────────
app.get('/api/tasks', (req, res) => {
  res.json(scoreTasks(readJson('tasks.json', [])));
});

app.post('/api/tasks', (req, res) => {
  const tasks = readJson('tasks.json', []);
  const id = nextId('task-counter.json', 'MC');
  const task = {
    id, uid: uuidv4(),
    title: (req.body.title || 'Untitled Task').trim(),
    description: req.body.description || '',
    status: 'queue',
    agent: req.body.agent || 'main',
    pi: req.body.pi || 'pi1',
    priority: req.body.priority || 'medium',
    tags: req.body.tags || [],
    source: req.body.source || 'manual',
    sourceIntelId: req.body.sourceIntelId || null,
    assignedPi: null,
    brief: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    startedAt: null, completedAt: null,
    activityLog: [{ ts: new Date().toISOString(), action: 'Created', by: 'user' }],
  };
  tasks.push(task);
  writeJson('tasks.json', tasks);
  log('INFO', 'TASK', 'task:created', { id, title: task.title, priority: task.priority, agent: task.agent, pi: task.pi, source: task.source });
  const [scored] = scoreTasks(tasks, [task]);
  res.json(scored);
  setImmediate(() => tryDispatchNext());
});

app.put('/api/tasks/:id', (req, res) => {
  const tasks = readJson('tasks.json', []);
  const idx = tasks.findIndex(t => t.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });

  const old = tasks[idx];
  const updates = { ...req.body };
  const actLog = [...(old.activityLog || [])];

  if (updates.status && updates.status !== old.status) {
    log('INFO', 'TASK', 'task:status-change', { id: old.id, title: old.title, from: old.status, to: updates.status });
    actLog.push({ ts: new Date().toISOString(), action: `Status → ${updates.status}`, by: 'user' });
    if (updates.status === 'in-progress' && !old.startedAt) updates.startedAt = new Date().toISOString();
    if (updates.status === 'completed' && !old.completedAt) updates.completedAt = new Date().toISOString();
  }
  if (updates.title && updates.title !== old.title) {
    log('INFO', 'TASK', 'task:updated', { id: old.id, field: 'title' });
    actLog.push({ ts: new Date().toISOString(), action: 'Title updated', by: 'user' });
  }
  if (updates.description !== undefined && updates.description !== old.description) {
    log('INFO', 'TASK', 'task:updated', { id: old.id, field: 'description' });
    actLog.push({ ts: new Date().toISOString(), action: 'Description updated', by: 'user' });
  }

  delete updates.id; delete updates.uid; delete updates.createdAt;
  tasks[idx] = { ...old, ...updates, updatedAt: new Date().toISOString(), activityLog: actLog };
  writeJson('tasks.json', tasks);
  const [scored] = scoreTasks(tasks, [tasks[idx]]);
  res.json(scored);
  if (updates.status === 'queue' && old.status !== 'queue') {
    setImmediate(() => tryDispatchNext());
  }
});

app.delete('/api/tasks/:id', (req, res) => {
  let tasks = readJson('tasks.json', []);
  const target = tasks.find(t => t.id === req.params.id);
  tasks = tasks.filter(t => t.id !== req.params.id);
  writeJson('tasks.json', tasks);
  if (target) log('INFO', 'TASK', 'task:deleted', { id: target.id, title: target.title, status: target.status });
  res.json({ ok: true });
});

app.get('/api/tasks/:id', (req, res) => {
  const tasks = readJson('tasks.json', []);
  const task = tasks.find(t => t.id === req.params.id);
  if (!task) return res.status(404).json({ error: 'Not found' });
  const [scored] = scoreTasks(tasks, [task]);
  res.json(scored);
});

app.get('/api/tasks/:id/log', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  const taskId = req.params.id;
  const tasks = readJson('tasks.json', []);
  const task = tasks.find(t => t.id === taskId);
  if (!task) {
    res.write(`data: ${JSON.stringify({ error: 'Not found' })}\n\n`);
    res.end();
    return;
  }

  // Send initial log
  const initEntries = task.activityLog || [];
  res.write(`data: ${JSON.stringify(initEntries)}\n\n`);
  let sentCount = initEntries.length;

  // Poll for new entries
  const interval = setInterval(() => {
    const allTasks = readJson('tasks.json', []);
    const t = allTasks.find(t => t.id === taskId);
    if (!t) { clearInterval(interval); res.end(); return; }
    const log = t.activityLog || [];
    if (log.length > sentCount) {
      const newEntries = log.slice(sentCount);
      res.write(`data: ${JSON.stringify(newEntries)}\n\n`);
      sentCount = log.length;
    }
    if (t.status === 'completed' || t.status === 'failed') {
      res.write(`data: ${JSON.stringify({ done: true, status: t.status })}\n\n`);
      clearInterval(interval);
      res.end();
    }
  }, 1500);

  req.on('close', () => clearInterval(interval));
});

// ─── Routes: Cron (all Pis) ───────────────────────────────────────────────────
app.get('/api/cron', async (req, res) => {
  const results = await Promise.all(PIES.map(async pi => {
    const raw = await sshExecPi(pi, `cat ${pi.ocHome}/cron/jobs.json 2>/dev/null`);
    if (!raw) return { piId: pi.id, piLabel: pi.label, reachable: false, jobs: [] };
    try {
      const data = JSON.parse(raw);
      const jobs = (data.jobs || []).map(j => ({
        ...j,
        compositeId: `${pi.id}__${j.id}`,  // unique toggle ID across fleet
        pi: pi.id,
        piLabel: pi.label,
      }));
      return { piId: pi.id, piLabel: pi.label, reachable: true, jobs };
    } catch {
      return { piId: pi.id, piLabel: pi.label, reachable: false, jobs: [], error: 'Parse error' };
    }
  }));

  res.json({
    jobs: results.flatMap(r => r.jobs),
    pis: results,
    piReachable: results.some(r => r.reachable),
  });
});

// PUT /api/cron/pi1__jobId  — composite ID encodes which Pi to write to
app.put('/api/cron/:compositeId', async (req, res) => {
  const { enabled } = req.body;
  const sep = req.params.compositeId.indexOf('__');
  if (sep === -1) return res.status(400).json({ error: 'Invalid ID — expected piId__jobId' });

  const piId  = req.params.compositeId.slice(0, sep);
  const jobId = req.params.compositeId.slice(sep + 2);
  const pi = PIES.find(p => p.id === piId);
  if (!pi) return res.status(404).json({ error: `Unknown Pi: ${piId}` });

  const cronFile = `${pi.ocHome}/cron/jobs.json`;
  const raw = await sshExecPi(pi, `cat ${cronFile} 2>/dev/null`);
  if (!raw) return res.status(503).json({ error: `${pi.label} unreachable` });

  let data;
  try { data = JSON.parse(raw); } catch { return res.status(500).json({ error: 'Parse error' }); }

  const idx = data.jobs.findIndex(j => j.id === jobId);
  if (idx === -1) return res.status(404).json({ error: 'Job not found' });

  data.jobs[idx].enabled = !!enabled;
  data.jobs[idx].updatedAtMs = Date.now();

  const ok = await sshWritePi(pi, cronFile, JSON.stringify(data, null, 2));
  if (!ok) return res.status(500).json({ error: 'Write failed' });

  log('INFO', 'CRON', 'cron:toggled', { pi: piId, jobId, enabled: !!enabled, jobName: data.jobs[idx].name || jobId });
  res.json({ ...data.jobs[idx], compositeId: `${piId}__${jobId}`, pi: piId, piLabel: pi.label });
});

// ─── Routes: Activity Feed (all Pis via SSH) ──────────────────────────────────
const activityCache = {};  // per-Pi cache with 5-min TTL

async function fetchActivityFromPi(pi) {
  const cached = activityCache[pi.id];
  if (cached && Date.now() - cached.ts < 5 * 60 * 1000) return cached.events;

  // Read last 40 lines from the 3 most-recently-modified JSONL session files
  const raw = await sshExecPi(pi,
    `find ${pi.ocHome}/agents -name "*.jsonl" 2>/dev/null | ` +
    `xargs ls -t 2>/dev/null | head -3 | ` +
    `while read f; do printf 'FILE:%s\\n' "$f"; tail -40 "$f"; printf '\\nENDFILE\\n'; done`
  );
  if (!raw) return [];

  function extractText(content) {
    if (typeof content === 'string') return content;
    if (Array.isArray(content)) return content.filter(c => c?.type === 'text').map(c => c.text || '').join(' ').trim();
    return '';
  }

  const events = [];
  for (const chunk of raw.split('ENDFILE')) {
    const trimmed = chunk.trim();
    if (!trimmed) continue;
    const fileMatch = trimmed.match(/^FILE:(.+)\n/);
    if (!fileMatch) continue;
    const agentMatch = fileMatch[1].trim().match(/agents\/([^/]+)\//);
    const agentId = agentMatch ? agentMatch[1] : 'unknown';
    const assistantTexts = [];

    for (const line of trimmed.slice(fileMatch[0].length).split('\n').filter(Boolean)) {
      let msg;
      try { msg = JSON.parse(line); } catch { continue; }

      if (msg.type === 'session') {
        events.push({ ts: msg.timestamp, agent: agentId, pi: pi.id, piLabel: pi.label, kind: 'session', text: 'Session started' });
        continue;
      }
      if (msg.type !== 'message' || !msg.message) continue;
      const { role, content } = msg.message;
      const text = extractText(content);
      const ts = msg.timestamp;

      if (role === 'user') {
        const cronM = text.match(/^\[cron:[^\s]+\s+([^\]]+)\]/);
        if (cronM) {
          events.push({ ts, agent: agentId, pi: pi.id, piLabel: pi.label, kind: 'cron', text: `Cron: ${cronM[1]}` });
          continue;
        }
        if (/HEARTBEAT\.md|heartbeat/i.test(text)) {
          events.push({ ts, agent: agentId, pi: pi.id, piLabel: pi.label, kind: 'heartbeat', text: 'Heartbeat check' });
          continue;
        }
        if (/Reply with READY/i.test(text)) {
          events.push({ ts, agent: agentId, pi: pi.id, piLabel: pi.label, kind: 'startup', text: 'Startup ping' });
          continue;
        }
      }
      if (role === 'assistant' && text) {
        if (text === 'HEARTBEAT_OK') { events.push({ ts, agent: agentId, pi: pi.id, piLabel: pi.label, kind: 'heartbeat_ok', text: 'HEARTBEAT_OK' }); continue; }
        if (text === 'READY')        { events.push({ ts, agent: agentId, pi: pi.id, piLabel: pi.label, kind: 'ready', text: 'READY' }); continue; }
        if (text.length > 30) assistantTexts.push({ ts, text });
      }
    }
    if (assistantTexts.length > 0) {
      const last = assistantTexts[assistantTexts.length - 1];
      events.push({ ts: last.ts, agent: agentId, pi: pi.id, piLabel: pi.label, kind: 'summary', text: last.text.replace(/\*\*/g, '').slice(0, 140) });
    }
  }

  activityCache[pi.id] = { ts: Date.now(), events };
  return events;
}

app.get('/api/activity', async (req, res) => {
  const allEvents = (await Promise.all(PIES.map(pi => fetchActivityFromPi(pi).catch(() => [])))).flat();
  allEvents.sort((a, b) => new Date(b.ts) - new Date(a.ts));
  res.json(allEvents.slice(0, 50));
});

// ─── Routes: Stats ────────────────────────────────────────────────────────────
app.get('/api/stats', async (req, res) => {
  const local = readJson('api-stats.json', {
    totalRequests: 0, totalCost: 0,
    byAgent: {}, byDate: {}, byModel: {},
    lastUpdated: null,
  });
  const completionsRaw = await sshExecPi(PRIMARY_PI, `ls -t ${PRIMARY_PI.ocHome}/completions/ 2>/dev/null | head -5`);
  local.completionFiles = completionsRaw ? completionsRaw.trim().split('\n').filter(Boolean) : [];
  res.json(local);
});

app.post('/api/stats/track', (req, res) => {
  const stats = readJson('api-stats.json', {
    totalRequests: 0, totalCost: 0,
    byAgent: {}, byDate: {}, byModel: {},
  });
  const { agent = 'unknown', model = 'unknown', inputTokens = 0, outputTokens = 0 } = req.body;
  const today = new Date().toISOString().slice(0, 10);
  stats.totalRequests = (stats.totalRequests || 0) + 1;
  const costIn  = (inputTokens  / 1_000_000) * 3;
  const costOut = (outputTokens / 1_000_000) * 15;
  stats.totalCost = (stats.totalCost || 0) + costIn + costOut;
  const addEntry = (bucket, key) => {
    bucket[key] = bucket[key] || { requests: 0, inputTokens: 0, outputTokens: 0, cost: 0 };
    bucket[key].requests++;
    bucket[key].inputTokens  += inputTokens;
    bucket[key].outputTokens += outputTokens;
    bucket[key].cost += costIn + costOut;
  };
  addEntry(stats.byAgent, agent);
  addEntry(stats.byDate,  today);
  addEntry(stats.byModel, model);
  stats.lastUpdated = new Date().toISOString();
  writeJson('api-stats.json', stats);
  res.json({ ok: true });
});

// ─── Routes: Intelligence ─────────────────────────────────────────────────────
app.get('/api/intelligence', (req, res) => {
  res.json(readJson('intelligence.json', []));
});

app.post('/api/intelligence', (req, res) => {
  const items = readJson('intelligence.json', []);
  const id = nextId('intel-counter.json', 'INTEL');
  const item = {
    id, uid: uuidv4(),
    title: req.body.title || 'Untitled',
    summary: req.body.summary || '',
    analysis: req.body.analysis || '',
    softwareGap: req.body.softwareGap || '',
    roadmap: req.body.roadmap || [],
    tags: req.body.tags || [],
    momentumScore: req.body.momentumScore || 5,
    feasibilityScore: req.body.feasibilityScore || 5,
    queued: false, taskId: null,
    createdAt: new Date().toISOString(),
    source: req.body.source || 'manual',
    status: 'ready',
  };
  items.push(item);
  writeJson('intelligence.json', items);
  log('INFO', 'INTEL', 'intel:created', { id, title: item.title, source: item.source, momentum: item.momentumScore, feasibility: item.feasibilityScore });
  res.json(item);
});

app.put('/api/intelligence/:id', (req, res) => {
  const items = readJson('intelligence.json', []);
  const idx = items.findIndex(i => i.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const updates = { ...req.body };
  delete updates.id; delete updates.uid; delete updates.createdAt;
  items[idx] = { ...items[idx], ...updates, updatedAt: new Date().toISOString() };
  writeJson('intelligence.json', items);
  res.json(items[idx]);
});

app.put('/api/intelligence/:id/archive', (req, res) => {
  const items = readJson('intelligence.json', []);
  const idx = items.findIndex(i => i.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  items[idx] = { ...items[idx], status: 'archived', archivedAt: new Date().toISOString() };
  writeJson('intelligence.json', items);
  log('INFO', 'INTEL', 'intel:archived', { id: items[idx].id, title: items[idx].title });
  res.json(items[idx]);
});

app.put('/api/intelligence/:id/unarchive', (req, res) => {
  const items = readJson('intelligence.json', []);
  const idx = items.findIndex(i => i.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  items[idx] = { ...items[idx], status: 'ready', archivedAt: null };
  writeJson('intelligence.json', items);
  res.json(items[idx]);
});

app.post('/api/intelligence/:id/todo', (req, res) => {
  const items = readJson('intelligence.json', []);
  const idx = items.findIndex(i => i.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });

  const intel = items[idx];
  if (intel.saved) return res.status(409).json({ error: 'Already saved to To-Do', taskId: intel.taskId });

  const tasks = readJson('tasks.json', []);
  const taskId = nextId('task-counter.json', 'MC');
  const task = {
    id: taskId, uid: uuidv4(),
    title: intel.title,
    description: [intel.summary, intel.softwareGap].filter(Boolean).join('\n\n'),
    status: 'todo',
    agent: 'main',
    pi: 'pi1',
    priority: intel.momentumScore >= 7 ? 'high' : intel.momentumScore >= 4 ? 'medium' : 'low',
    tags: intel.tags || [],
    source: 'intelligence',
    sourceIntelId: intel.id,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    startedAt: null, completedAt: null,
    activityLog: [{ ts: new Date().toISOString(), action: `Saved to To-Do from ${intel.id}`, by: 'user' }],
  };
  tasks.push(task);
  writeJson('tasks.json', tasks);
  items[idx] = { ...intel, saved: true, taskId };
  writeJson('intelligence.json', items);
  log('INFO', 'INTEL', 'intel:todo', { intelId: intel.id, taskId, title: intel.title });
  res.json({ task, intel: items[idx] });
});

app.post('/api/intelligence/:id/queue', (req, res) => {
  const items = readJson('intelligence.json', []);
  const idx = items.findIndex(i => i.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });

  const intel = items[idx];
  if (intel.queued) return res.status(409).json({ error: 'Already queued', taskId: intel.taskId });

  const tasks = readJson('tasks.json', []);
  const taskId = nextId('task-counter.json', 'MC');
  const task = {
    id: taskId, uid: uuidv4(),
    title: intel.title,
    description: [intel.summary, intel.softwareGap].filter(Boolean).join('\n\n'),
    status: 'queue',
    agent: 'main',
    pi: 'pi1',
    priority: intel.momentumScore >= 7 ? 'high' : intel.momentumScore >= 4 ? 'medium' : 'low',
    tags: intel.tags || [],
    source: 'intelligence',
    sourceIntelId: intel.id,
    assignedPi: null,
    brief: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    startedAt: null, completedAt: null,
    activityLog: [{ ts: new Date().toISOString(), action: `Queued from ${intel.id}`, by: 'user' }],
  };
  tasks.push(task);
  writeJson('tasks.json', tasks);
  items[idx] = { ...intel, queued: true, taskId };
  writeJson('intelligence.json', items);
  log('INFO', 'INTEL', 'intel:queued', { intelId: intel.id, taskId, title: intel.title, priority: task.priority });
  res.json({ task, intel: items[idx] });
  setImmediate(() => tryDispatchNext());
});

app.post('/api/intelligence/scan', async (req, res) => {
  const pi = PRIMARY_PI;
  const scanPrompt = `# MISSION CONTROL — SOURCE INTELLIGENCE SCAN
Requested: ${new Date().toISOString()}

## Your Task
Search Twitter/X for recent developer discourse (last 24-48h) about:
1. New AI developer tools that just launched — what gaps exist in their ecosystem?
2. Developer pain points trending on Twitter ("I wish X could...", "why doesn't X...")
3. Workflows people are duct-taping together that should be one product
4. Features requested for Claude, Cursor, Copilot, etc. that don't exist yet

## Output Format
For each significant opportunity, write to: ~/.openclaw/workspace/intelligence/SCAN-{timestamp}.json

\`\`\`json
{
  "title": "Short opportunity title",
  "summary": "2-3 sentence exec summary of the Twitter signal",
  "analysis": "Full analysis — what people are saying, how often, sentiment, examples",
  "softwareGap": "Specific product/feature gap identified",
  "roadmap": [
    { "phase": "Phase 1", "duration": "Week 1-2", "steps": ["Step A", "Step B"] },
    { "phase": "Phase 2", "duration": "Week 3-4", "steps": ["Step C", "Step D"] }
  ],
  "tags": ["tag1", "tag2"],
  "momentumScore": 7,
  "feasibilityScore": 8
}
\`\`\`

Find 3-5 opportunities. After writing all files, reply: INTEL_SCAN_COMPLETE: N findings
`;

  const scanFile = `${pi.ocHome}/workspace/INTELLIGENCE_SCAN.md`;
  const [writeOk] = await Promise.all([
    sshWritePi(pi, scanFile, scanPrompt),
    sshExecPi(pi, `mkdir -p ${pi.ocHome}/workspace/intelligence`),
  ]);

  const items = readJson('intelligence.json', []);
  const id = nextId('intel-counter.json', 'INTEL');
  const placeholder = {
    id, uid: uuidv4(),
    title: 'Twitter Intelligence Scan — Pending',
    summary: `Agent scan triggered on ${pi.label}. The main agent will search Twitter for software gaps on next heartbeat cycle.`,
    analysis: '', softwareGap: '', roadmap: [],
    tags: ['scan', 'pending'],
    momentumScore: 5, feasibilityScore: 5,
    queued: false, taskId: null,
    createdAt: new Date().toISOString(),
    source: 'agent-scan',
    status: 'scanning',
  };
  items.push(placeholder);
  writeJson('intelligence.json', items);
  log('INFO', 'INTEL', 'intel:scan-triggered', { pi: pi.label, scanFile, writeOk });
  res.json({ triggered: writeOk, item: placeholder, scanFile });
});

app.post('/api/intelligence/poll', async (req, res) => {
  const pi = PRIMARY_PI;
  const raw = await sshExecPi(pi,
    `for f in ${pi.ocHome}/workspace/intelligence/SCAN-*.json; do [ -f "$f" ] && cat "$f" && echo "---FILE_END---"; done 2>/dev/null`
  );
  if (!raw) return res.json({ found: 0 });

  const items = readJson('intelligence.json', []);
  let added = 0;
  for (const chunk of raw.split('---FILE_END---')) {
    const trimmed = chunk.trim();
    if (!trimmed) continue;
    try {
      const data = JSON.parse(trimmed);
      if (!data.title || items.find(i => i.title === data.title)) continue;
      const id = nextId('intel-counter.json', 'INTEL');
      items.push({
        id, uid: uuidv4(), ...data,
        queued: false, taskId: null,
        createdAt: new Date().toISOString(),
        source: 'agent-scan', status: 'ready',
      });
      added++;
    } catch {}
  }

  if (added > 0) {
    writeJson('intelligence.json', items.map(i => i.status === 'scanning' ? { ...i, status: 'superseded' } : i));
    log('INFO', 'INTEL', 'intel:poll-imported', { added });
  } else {
    writeJson('intelligence.json', items);
    log('INFO', 'INTEL', 'intel:poll-empty', {});
  }
  res.json({ found: added });
});

// ─── Routes: Logs ─────────────────────────────────────────────────────────────
app.get('/api/logs', (req, res) => {
  const { level, source, limit = '300', offset = '0', search = '' } = req.query;
  if (!fs.existsSync(LOG_FILE)) return res.json({ entries: [], total: 0 });
  const lines = fs.readFileSync(LOG_FILE, 'utf8').split('\n').filter(Boolean);
  let entries = [];
  for (const line of lines) {
    try { entries.push(JSON.parse(line)); } catch {}
  }
  if (level && level !== 'ALL') entries = entries.filter(e => e.level === level);
  if (source && source !== 'ALL') entries = entries.filter(e => e.source === source);
  if (search) {
    const q = search.toLowerCase();
    entries = entries.filter(e =>
      e.event?.toLowerCase().includes(q) ||
      e.source?.toLowerCase().includes(q) ||
      JSON.stringify(e.details || {}).toLowerCase().includes(q)
    );
  }
  entries.reverse(); // newest first
  const total = entries.length;
  const page = entries.slice(Number(offset), Number(offset) + Number(limit));
  res.json({ entries: page, total, limit: Number(limit), offset: Number(offset) });
});

app.delete('/api/logs', (req, res) => {
  try {
    if (fs.existsSync(LOG_FILE)) fs.writeFileSync(LOG_FILE, '');
    log('INFO', 'SYSTEM', 'log:cleared', { by: 'user' });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`MISSION CONTROL  http://0.0.0.0:${PORT}`);
  console.log(`Mode             DOCKER/PC — SSH to Pi fleet`);
  console.log(`Pi fleet         ${PIES.map(p => `${p.label} (${p.host})`).join(', ')}`);
  console.log(`SSH transport    ${USE_WSL_SSH ? 'WSL SSH' : 'node-ssh'}`);
  log('INFO', 'SYSTEM', 'server:start', {
    port: PORT,
    basePath: BASE_PATH,
    sshMode: USE_WSL_SSH ? 'wsl' : 'node-ssh',
    pis: PIES.map(p => p.id),
    nodeVersion: process.version,
  });

  // On startup: re-queue any tasks that were in-progress locally (process died mid-run)
  const tasks = readJson('tasks.json', []);
  let recovered = 0;
  for (const t of tasks) {
    if (t.status === 'in-progress' && (!t.assignedPi || t.assignedPi === 'local')) {
      t.status = 'queue';
      t.assignedPi = undefined;
      t.startedAt = undefined;
      t.activityLog = [...(t.activityLog || []),
        { ts: new Date().toISOString(), action: 'Re-queued after server restart', by: 'system' }];
      recovered++;
    }
  }
  if (recovered > 0) {
    writeJson('tasks.json', tasks);
    log('INFO', 'SYSTEM', 'startup:recovery', { recovered });
    setTimeout(() => tryDispatchNext(), 2000);
  }
});

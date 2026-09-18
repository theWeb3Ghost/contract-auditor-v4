
const express = require('express');
const path = require('path');

const etherscanHandler = require('./api/etherscan');
const auditHandler = require('./api/audit');

const {
  router: batchRouter,
  resumePendingBatches
} = require('./api/batch');

const {
  router: contractSkipListRouter,
  ensureSkipListIndexes
} = require('./api/contract-skip-list');

const {
  router: reauditRouter,
  resumePendingReaudits
} = require('./api/reaudit');



const app = express();


// ============================================================
// LOG RUNTIME
// ============================================================

console.log('Node version:', process.version);


// ============================================================
// BODY PARSING
// ============================================================

app.use(
  express.json({
    limit: '10mb'
  })
);


// ============================================================
// CORS
// ============================================================

app.use((req, res, next) => {

  res.setHeader(
    'Access-Control-Allow-Origin',
    '*'
  );

  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET, POST, DELETE, OPTIONS'
  );

  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, x-etherscan-key, x-openai-key , x-openai-keys'
  );


  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }


  next();
});


// ============================================================
// API ROUTES
// ============================================================

app.get(
  '/api/etherscan',
  etherscanHandler
);


app.get(
  '/api/audit/:jobId',
  auditHandler
);


app.post(
  '/api/audit',
  auditHandler
);


// Batch routes.
app.use(
  '/api/batch',
  batchRouter
);

// Contract name skip list routes.
app.use(
  '/api/contract-skip-list',
  contractSkipListRouter
);

// Human-assisted one-shot Reaudit dashboard / queue.
app.use(
  '/api/reaudit',
  reauditRouter
);

// ============================================================
// HEALTH CHECK
// ============================================================

app.get(
  '/health',
  (req, res) => {
    res.json({
      ok: true,
      node: process.version,
      uptime: process.uptime()
    });
  }
);


// ============================================================
// STATIC FRONTEND
// ============================================================

app.use(
  express.static(
    path.join(__dirname)
  )
);


// ============================================================
// START SERVER
// ============================================================

const PORT =
  process.env.PORT || 3000;


const server =
  app.listen(
    PORT,
    '0.0.0.0',
    async () => {
  console.log(
    `Contract Auditor listening on port ${PORT}`
  );

  try {

    await ensureSkipListIndexes();

    console.log(
      '[CONTRACT SKIP LIST] Index ready'
    );

  } catch (error) {

    console.error(
      '[CONTRACT SKIP LIST] Index setup failed:',
      error
    );
  }


      // Reset any Reaudit whose LLM request was interrupted by a
      // Render restart. The user can run it again from the dashboard.
      await resumePendingReaudits();

      // Resume unfinished batches after restart.
      try {

        await resumePendingBatches();

      } catch (error) {

        console.error(
          '[SERVER] Batch auto-resume error:',
          error
        );

      }
    }
  );


// ============================================================
// LONG REQUEST SETTINGS
// ============================================================

server.requestTimeout = 0;

server.keepAliveTimeout = 65000;

server.headersTimeout = 66000;

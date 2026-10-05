
// api/audit.js
//
// POST /api/audit
// Starts an audit job and immediately returns a jobId.
//
// GET /api/audit/:jobId
// Returns the current status/result of an audit job.
//
// Jobs are persisted in MongoDB (collection: single_audit_jobs).
// A Render restart does not lose results for completed/failed jobs.

const crypto = require('crypto');
const { fetch, Agent } = require('undici');

const {
  getDb
} = require('./db');

// ============================================================
// CONFIGURATION
// ============================================================

// Maximum Solidity source characters sent to the LLM
// Kept in sync with llm.js MAX_CHARS and batch.js MAX_SOURCE_CHARS.
const MAX_CHARS = 3000000;

// LLM timeout: 10 minutes
const LLM_TIMEOUT = 10 * 60 * 1000;


// ============================================================
// UNDICI AGENT
// ============================================================
//
// This Agent is specifically for long-running LLM requests.
//
// headersTimeout:
// Maximum time waiting for response headers.
//
// bodyTimeout:
// Maximum time allowed while receiving the response body.
//
// connect.timeout:
// Maximum time allowed to establish a connection.
//

const llmDispatcher = new Agent({
  headersTimeout: LLM_TIMEOUT,
  bodyTimeout: LLM_TIMEOUT,

  connect: {
    timeout: 30000
  }
});


// ============================================================
// HELPERS
// ============================================================

async function updateJob(jobId, updates) {
  const db = await getDb();

  await db
    .collection('single_audit_jobs')
    .updateOne(
      { jobId },
      { $set: updates }
    );
}


// ============================================================
// RUN AUDIT
// ============================================================

async function runAudit(jobId, data) {
  const db = await getDb();

  let job = await db
    .collection('single_audit_jobs')
    .findOne({ jobId });

  if (!job) {
    console.error(
      `[AUDIT ${jobId}] Job not found`
    );
    return;
  }


  try {

    // --------------------------------------------------------
    // UPDATE JOB STATUS
    // --------------------------------------------------------

    await updateJob(jobId, {
      status: 'running',
      startedAt: Date.now()
    });

    job.status = 'running';
    job.startedAt = Date.now();


    const {
      source,
      systemPrompt,
      model,
      contractName,
      address,
      llmUrl,
      apiKey
    } = data;


    // --------------------------------------------------------
    // VALIDATE SOURCE
    // --------------------------------------------------------

    if (!source || typeof source !== 'string') {
      throw new Error(
        'Invalid or empty Solidity source code'
      );
    }


    // --------------------------------------------------------
    // TRUNCATE LARGE CONTRACTS
    // --------------------------------------------------------

    let src = source;
    let truncated = false;

    if (src.length > MAX_CHARS) {
      src = src.slice(0, MAX_CHARS);
      truncated = true;

      console.log(
        `[AUDIT ${jobId}] Source truncated from ${source.length} to ${MAX_CHARS} characters`
      );
    }


    // --------------------------------------------------------
    // BUILD USER MESSAGE
    // --------------------------------------------------------

    const userMessage = `
You are auditing the following Solidity smart contract.

Contract Name: ${contractName || 'Unknown'}

Contract Address: ${address || 'Not provided'}

SOURCE CODE:

\`\`\`solidity
${src}
\`\`\`

${truncated
  ? '[WARNING: Source code was truncated because it exceeded the maximum allowed size.]'
  : ''
}
`;


    // --------------------------------------------------------
    // DETERMINE ENDPOINT
    // --------------------------------------------------------

    if (!llmUrl || typeof llmUrl !== 'string' || !/^https?:\/\//.test(llmUrl.trim())) {
      throw new Error('LLM API URL is required and must be supplied by the frontend');
    }

    const endpoint = llmUrl.trim();

    if (!model || typeof model !== 'string' || !model.trim()) {
      throw new Error('LLM model is required and must be supplied by the frontend');
    }


    // --------------------------------------------------------
    // LOG REQUEST DETAILS
    // --------------------------------------------------------

    console.log(
      `[AUDIT ${jobId}] ========================================`
    );

    console.log(
      `[AUDIT ${jobId}] Starting LLM audit`
    );

    console.log(
      `[AUDIT ${jobId}] Endpoint: ${endpoint}`
    );

    console.log(
      `[AUDIT ${jobId}] Model: ${model || 'gpt-4o-mini'}`
    );

    console.log(
      `[AUDIT ${jobId}] Contract: ${contractName || 'Unknown'}`
    );

    console.log(
      `[AUDIT ${jobId}] Source length: ${src.length} characters`
    );

    console.log(
      `[AUDIT ${jobId}] Node version: ${process.version}`
    );

    console.log(
      `[AUDIT ${jobId}] ========================================`
    );


    // --------------------------------------------------------
    // CREATE ABORT CONTROLLER
    // --------------------------------------------------------
    //
    // This is an additional safety timeout.
    // Undici handles connection/body/header timeouts,
    // while AbortController provides an overall request limit.
    //

    const controller = new AbortController();

    const timeoutId = setTimeout(() => {

      console.error(
        `[AUDIT ${jobId}] Overall request timeout reached after ${LLM_TIMEOUT}ms`
      );

      controller.abort();

    }, LLM_TIMEOUT);


    // --------------------------------------------------------
    // SEND REQUEST TO LLM
    // --------------------------------------------------------

    let response;

    try {

      console.log(
        `[AUDIT ${jobId}] Sending request to LLM: ${endpoint}`
      );


      response = await fetch(endpoint, {

        method: 'POST',

        dispatcher: llmDispatcher,

        signal: controller.signal,

        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`,
          'Accept': 'application/json'
        },

        body: JSON.stringify({

          model: model || 'gpt-4o-mini',

          messages: [

            {
              role: 'system',
              content: systemPrompt
            },

            {
              role: 'user',
              content: userMessage
            }

          ]

        })

      });

    } finally {

      // Always clear timeout when fetch finishes
      clearTimeout(timeoutId);

    }


    // --------------------------------------------------------
    // LOG RESPONSE STATUS
    // --------------------------------------------------------

    console.log(
      `[AUDIT ${jobId}] LLM response received`
    );

    console.log(
      `[AUDIT ${jobId}] HTTP status: ${response.status}`
    );

    console.log(
      `[AUDIT ${jobId}] HTTP status text: ${response.statusText}`
    );


    // --------------------------------------------------------
    // READ RESPONSE AS TEXT FIRST
    // --------------------------------------------------------
    //
    // We read raw text before JSON parsing so we can debug
    // non-JSON responses from proxies/providers.
    //

    const rawText = await response.text();


    console.log(
      `[AUDIT ${jobId}] Response length: ${rawText.length} characters`
    );

    console.log(
      `[AUDIT ${jobId}] Response preview: ${rawText.slice(0, 500)}`
    );


    // --------------------------------------------------------
    // HANDLE HTTP ERRORS
    // --------------------------------------------------------

    if (!response.ok) {

      throw new Error(
        `LLM API returned HTTP ${response.status}: ${rawText.slice(0, 2000)}`
      );

    }


    // --------------------------------------------------------
    // PARSE JSON
    // --------------------------------------------------------

    let json;

    try {

      json = JSON.parse(rawText);

    } catch (parseError) {

      console.error(
        `[AUDIT ${jobId}] Invalid JSON received from LLM`
      );

      throw new Error(
        `LLM returned invalid JSON: ${rawText.slice(0, 2000)}`
      );

    }


    // --------------------------------------------------------
    // HANDLE API ERROR OBJECT
    // --------------------------------------------------------

    if (json.error) {

      console.error(
        `[AUDIT ${jobId}] LLM API error:`,
        json.error
      );

      throw new Error(
        json.error.message ||
        JSON.stringify(json.error)
      );

    }


    // --------------------------------------------------------
    // EXTRACT LLM RESPONSE
    // --------------------------------------------------------

    const result =
      json?.choices?.[0]?.message?.content ||
      json?.choices?.[0]?.text ||
      json?.output_text ||
      '';


    // --------------------------------------------------------
    // VALIDATE RESULT
    // --------------------------------------------------------

    if (!result || !String(result).trim()) {

      console.error(
        `[AUDIT ${jobId}] Empty LLM response`
      );

      console.error(
        `[AUDIT ${jobId}] Full response structure:`,
        JSON.stringify(json).slice(0, 5000)
      );

      throw new Error(
        'LLM returned an empty audit response'
      );

    }


    // --------------------------------------------------------
    // SAVE SUCCESSFUL RESULT
    // --------------------------------------------------------

    const finishedAt = Date.now();

    await updateJob(jobId, {
      status: 'completed',
      result: String(result).trim(),
      error: null,
      truncated,
      finishedAt
    });

    job.status = 'completed';
    job.result = String(result).trim();
    job.error = null;
    job.truncated = truncated;
    job.finishedAt = finishedAt;

    const duration =
      job.finishedAt - job.startedAt;


    console.log(
      `[AUDIT ${jobId}] ========================================`
    );

    console.log(
      `[AUDIT ${jobId}] AUDIT COMPLETED SUCCESSFULLY`
    );

    console.log(
      `[AUDIT ${jobId}] Result length: ${job.result.length} characters`
    );

    console.log(
      `[AUDIT ${jobId}] Duration: ${duration}ms (${(duration / 1000).toFixed(2)} seconds)`
    );

    console.log(
      `[AUDIT ${jobId}] ========================================`
    );


  } catch (err) {

    // --------------------------------------------------------
    // MARK JOB AS FAILED
    // --------------------------------------------------------

    const finishedAt = Date.now();

    let jobError;

    if (
      err?.name === 'AbortError' ||
      err?.name === 'TimeoutError'
    ) {

      jobError =
        `LLM request timed out after ${LLM_TIMEOUT / 60000} minutes.`;

    } else {

      jobError = String(
        err?.cause?.message ||
        err?.message ||
        err ||
        'Unknown audit error'
      );

    }

    await updateJob(jobId, {
      status: 'failed',
      error: jobError,
      finishedAt
    });

    job.status = 'failed';
    job.finishedAt = finishedAt;
    job.error = jobError;


    // --------------------------------------------------------
    // DETAILED ERROR LOGGING
    // --------------------------------------------------------

    console.error(
      `[AUDIT ${jobId}] ========================================`
    );

    console.error(
      `[AUDIT ${jobId}] AUDIT FAILED`
    );

    console.error(
      `[AUDIT ${jobId}] ERROR DETAILS:`,
      {
        name: err?.name,

        message: err?.message,

        code: err?.code,

        cause: err?.cause
          ? {
              name: err.cause.name,
              message: err.cause.message,
              code: err.cause.code,
              errno: err.cause.errno,
              syscall: err.cause.syscall,
              hostname: err.cause.hostname
            }
          : null,

        stack: err?.stack
      }
    );

    console.error(
      `[AUDIT ${jobId}] ========================================`
    );

  }

}


// ============================================================
// EXPRESS API HANDLER
// ============================================================

module.exports = async function auditHandler(req, res) {


  // ----------------------------------------------------------
  // CORS HEADERS
  // ----------------------------------------------------------

  res.setHeader(
    'Access-Control-Allow-Origin',
    '*'
  );

  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET, POST, OPTIONS'
  );

  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, x-openai-key'
  );


  // ----------------------------------------------------------
  // HANDLE OPTIONS
  // ----------------------------------------------------------

  if (req.method === 'OPTIONS') {

    return res.status(204).end();

  }


  // ==========================================================
  // POST /api/audit
  // START A NEW AUDIT
  // ==========================================================

  if (req.method === 'POST') {

    const {
      source,
      systemPrompt,
      model,
      contractName,
      address,
      llmUrl
    } = req.body || {};


    // --------------------------------------------------------
    // VALIDATE SOURCE
    // --------------------------------------------------------

    if (!source) {

      return res.status(400).json({
        error: 'source is required'
      });

    }


    if (typeof source !== 'string') {

      return res.status(400).json({
        error: 'source must be a string'
      });

    }


    // --------------------------------------------------------
    // VALIDATE SYSTEM PROMPT
    // --------------------------------------------------------

    if (!systemPrompt) {

      return res.status(400).json({
        error: 'systemPrompt is required'
      });

    }


    // --------------------------------------------------------
    // GET API KEY
    // --------------------------------------------------------

    const apiKey = req.headers['x-openai-key'];


    if (!apiKey) {

      return res.status(500).json({
        error:
          'No API key provided. Set x-openai-key or OPENAI_API_KEY.'
      });

    }


    // --------------------------------------------------------
    // CREATE JOB
    // --------------------------------------------------------

    const jobId = crypto.randomUUID();

    const createdAt = Date.now();

    const db = await getDb();

    await db
      .collection('single_audit_jobs')
      .insertOne({

        jobId,

        status: 'queued',

        result: null,

        error: null,

        truncated: false,

      createdAt,

      startedAt: null,

      startedAt: null,

      finishedAt: null

    });


    console.log(
      `[AUDIT ${jobId}] New audit job created`
    );


    // --------------------------------------------------------
    // RETURN IMMEDIATELY
    // --------------------------------------------------------
    //
    // Important:
    // The frontend receives the jobId immediately.
    // The long LLM audit continues in the background.
    //

    res.status(202).json({

      jobId,

      status: 'queued'

    });


    // --------------------------------------------------------
    // RUN AUDIT IN BACKGROUND
    // --------------------------------------------------------

    runAudit(jobId, {

      source,

      systemPrompt,

      model,

      contractName,

      address,

      llmUrl,

      apiKey

    }).catch((err) => {

      console.error(
        `[AUDIT ${jobId}] Unexpected background error:`,
        err
      );

    });


    return;

  }


  // ==========================================================
  // GET /api/audit/:jobId
  // CHECK AUDIT STATUS
  // ==========================================================

  if (req.method === 'GET') {

    const jobId = req.params.jobId;


    if (!jobId) {

      return res.status(400).json({
        error: 'jobId is required'
      });

    }


    const db = await getDb();

    const job = await db
      .collection('single_audit_jobs')
      .findOne(
        { jobId },
        {
          projection: {
            _id: 0,
            jobId: 1,
            status: 1,
            result: 1,
            error: 1,
            truncated: 1,
            createdAt: 1,
            startedAt: 1,
            finishedAt: 1
          }
        }
      );


    if (!job) {

      return res.status(404).json({
        error: 'Audit job not found'
      });

    }


    return res.status(200).json({

      jobId,

      status: job.status,

      result:
        job.status === 'completed'
          ? job.result
          : null,

      error:
        job.status === 'failed'
          ? job.error
          : null,

      truncated: job.truncated,

      createdAt: job.createdAt,

      startedAt: job.startedAt,

      finishedAt: job.finishedAt

    });

  }


  // ==========================================================
  // METHOD NOT ALLOWED
  // ==========================================================

  return res.status(405).json({
    error: 'Method not allowed. Use GET or POST.'
  });

};

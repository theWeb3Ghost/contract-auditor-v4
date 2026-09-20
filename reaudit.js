// api/reaudit.js
// Human-assisted, one-shot Reaudit queue for unresolved black-box audits.
//
// Reaudit is deliberately asynchronous:
//   1. Original batch item becomes UNRATED.
//   2. A Reaudit record is created.
//   3. The main batch continues with normal items.
//   4. The user adds external contract addresses manually.
//   5. Verified source is fetched here.
//   6. RUN REAUDIT performs one additional Normal or COM review.
//   7. The completed result is marked READY.
//   8. The batch worker atomically claims READY and applies it at the
//      next worker boundary before the next untouched normal item.
//
// A Reaudit is one-shot. RUN or SKIP permanently consumes the opportunity.

const express = require('express');
const { getDb } = require('./db');
const { runLLMAudit } = require('./llm');
const { runComReaudit } = require('./com');
const { fetchSource } = require('./etherscan');

const router = express.Router();

const ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;
const UNRATED_RE = /UNRATED\s*[—-]\s*Verdict withheld:\s*unresolved black-box dependency gates a fund-release decision/i;
const MAX_EVIDENCE_CHARS = 2500000;

function now() {
  return new Date();
}

function cleanAddress(address) {
  const value = String(address || '').trim();
  return ADDRESS_RE.test(value) ? value : null;
}

function errorText(error) {
  return String(error?.message || error || 'Unknown error');
}

function isUnratedResult(value) {
  return UNRATED_RE.test(String(value || ''));
}

function extractBlackBoxEscalation(value) {
  const text = String(value || '');
  const match = text.match(/Black-box escalation triggered[\s\S]{0,4000}/i);
  if (match) return match[0].trim();

  const tagged = text.match(/\[BLACK_BOX_MANIPULABLE\][\s\S]{0,4000}/i);
  return tagged ? tagged[0].trim() : '';
}

function getComResult(item, side) {
  return item?.com?.[side]?.final?.result || item?.com?.[side]?.initial?.result || '';
}

function getOriginalResults(item) {
  if (item?.com) {
    return {
      llmA: getComResult(item, 'llmA'),
      llmB: getComResult(item, 'llmB')
    };
  }
  return { normal: String(item?.audit || '') };
}

function resultTriggered(item) {
  if (item?.com) {
    return isUnratedResult(getComResult(item, 'llmA')) || isUnratedResult(getComResult(item, 'llmB'));
  }
  return isUnratedResult(item?.audit);
}

async function ensureReauditRecord({ batch, item }) {
  const db = await getDb();
  const reaudits = db.collection('reaudits');

  if (item.reauditUsed) return null;
  if (!resultTriggered(item)) return null;

  const existing = await reaudits.findOne({ auditId: String(item._id) });
  if (existing) {
    await db.collection('batch_items').updateOne(
      { _id: item._id, reauditUsed: { $ne: true } },
      { $set: { status: 'reaudit_pending', auditStage: 'reaudit_pending', reauditId: String(item._id), updatedAt: now() } }
    );
    return existing;
  }

  const original = getOriginalResults(item);
  const combined = item.com
    ? `${original.llmA}\n\n${original.llmB}`
    : original.normal;

  const document = {
    auditId: String(item._id),
    batchId: batch.batchId,
    originalIndex: item.index,
    mainAddress: item.address,
    auditedAddress: item.auditedAddress || item.address,
    chainId: String(batch.chainId || '1'),
    mode: batch.mode === 'com' && batch.com?.enabled ? 'com' : 'normal',
    contractName: item.contractName || 'Unknown',
    compilerVersion: item.compilerVersion || null,
    mainSource: String(item.source || ''),
    status: 'pending',
    skipped: false,
    completed: false,
    originalResult: item.com ? null : original.normal,
    originalCom: item.com || null,
    originalBlackBoxEscalation: extractBlackBoxEscalation(combined),
    externalContracts: [],
    result: null,
    com: null,
    error: null,
    createdAt: now(),
    updatedAt: now(),
    finishedAt: null,
    prioritySeq: Number(item.index) || 0
  };

  try {
    await reaudits.insertOne(document);
  } catch (error) {
    if (error?.code === 11000) {
      return reaudits.findOne({ auditId: String(item._id) });
    }
    throw error;
  }

  await db.collection('batch_items').updateOne(
    { _id: item._id, reauditUsed: { $ne: true } },
    {
      $set: {
        status: 'reaudit_pending',
        reauditUsed: false,
        auditStage: 'reaudit_pending',
        reauditId: String(item._id),
        updatedAt: now()
      }
    }
  );

  console.log(`[REAUDIT] Created for ${item.address} batch=${batch.batchId} index=${item.index}`);
  return document;
}

async function fetchExternalContract({ address, chainId, etherscanKey }) {
  const base = await fetchSource(address, chainId, etherscanKey);

  if (!base || !base.SourceCode) {
    return {
      address,
      sourceStatus: 'unverified',
      source: null,
      isProxy: false,
      implementation: null,
      note: 'Contract source is not verified on the selected explorer.'
    };
  }

  const isProxy = base.Proxy === '1' && ADDRESS_RE.test(String(base.Implementation || ''));
  const implementation = isProxy ? String(base.Implementation).trim() : null;

  if (!isProxy) {
    return {
      address,
      sourceStatus: 'verified',
      source: flattenSource(base.SourceCode),
      contractName: base.ContractName || 'Unknown',
      compilerVersion: base.CompilerVersion || null,
      isProxy: false,
      implementation: null
    };
  }

  const impl = await fetchSource(implementation, chainId, etherscanKey);

  if (!impl || !impl.SourceCode) {
    return {
      address,
      sourceStatus: 'unverified',
      source: null,
      contractName: base.ContractName || 'Unknown',
      compilerVersion: base.CompilerVersion || null,
      isProxy: true,
      implementation,
      note: 'Proxy implementation was detected but its source is not verified.'
    };
  }

  return {
    address,
    sourceStatus: 'verified',
    source: flattenSource(impl.SourceCode),
    contractName: impl.ContractName || base.ContractName || 'Unknown',
    compilerVersion: impl.CompilerVersion || base.CompilerVersion || null,
    isProxy: true,
    implementation,
    note: 'Proxy resolved to verified implementation source.'
  };
}

function flattenSource(raw) {
  let s = String(raw || '').trim();
  try {
    if (s.startsWith('{{') && s.endsWith('}}')) s = s.slice(1, -1);
    if (s.startsWith('{')) {
      const parsed = JSON.parse(s);
      const sources = parsed.sources || parsed;
      let out = '';
      for (const [file, content] of Object.entries(sources)) {
        const code = (content && (content.content || content)) || '';
        out += `// ==== FILE: ${file} ====\n${code}\n\n`;
      }
      return out.trim() || String(raw || '');
    }
  } catch (_) {}
  return String(raw || '');
}

function verifiedEvidence(re) {
  const blocks = [];
  for (const entry of re.externalContracts || []) {
    if (entry.sourceStatus !== 'verified' || !entry.source) continue;
    blocks.push(`EXTERNAL CONTRACT: ${entry.address}\n` +
      `Contract Name: ${entry.contractName || 'Unknown'}\n` +
      `Proxy: ${entry.isProxy ? 'yes' : 'no'}\n` +
      `Implementation: ${entry.implementation || 'N/A'}\n` +
      `VERIFIED SOURCE:\n\`\`\`solidity\n${entry.source}\n\`\`\``);
  }
  let result = blocks.join('\n\n==============================\n\n');
  if (result.length > MAX_EVIDENCE_CHARS) result = result.slice(0, MAX_EVIDENCE_CHARS) + '\n[EXTERNAL EVIDENCE TRUNCATED]';
  return result;
}

async function getReauditById(id) {
  const db = await getDb();
  return db.collection('reaudits').findOne({ _id: require('mongodb').ObjectId.isValid(id) ? new (require('mongodb').ObjectId)(id) : null });
}

async function listReaudits(req, res) {
  try {
    const db = await getDb();
    // Unstick any 'ready' Reaudit whose batch has no worker.
    await drainReadyReaudits().catch(e => console.error('[REAUDIT] drain failed:', e));
    const query = {};
    if (req.query.batchId) query.batchId = String(req.query.batchId);
    if (req.query.status) query.status = String(req.query.status);

    // Never let old 'applied' records push actionable ones out of the list:
    // return every non-applied record, plus the most recent applied ones.
    const reaudits = db.collection('reaudits');
    let records;
    if (query.status) {
      records = await reaudits.find(query).sort({ createdAt: 1 }).limit(500).toArray();
    } else {
      const active = await reaudits
        .find({ ...query, status: { $ne: 'applied' } })
        .sort({ createdAt: 1 })
        .limit(500)
        .toArray();
      const done = await reaudits
        .find({ ...query, status: 'applied' })
        .sort({ updatedAt: -1 })
        .limit(500)
        .toArray();
      records = [...active, ...done];
    }

    // Finished records don't need their (large) source code on every poll.
    // Keep a short marker so the UI still shows "verified".
    for (const r of records) {
      if (r.status !== 'applied') continue;
      if (r.mainSource) r.mainSource = '[stored]';
      if (Array.isArray(r.externalContracts)) {
        r.externalContracts = r.externalContracts.map(c => ({
          ...c,
          source: c.source ? '[stored]' : c.source
        }));
      }
    }

    return res.json({ ok: true, reaudits: records });
  } catch (error) {
    return res.status(500).json({ ok: false, error: errorText(error) });
  }
}

async function getReaudit(req, res) {
  try {
    const record = await getReauditById(req.params.id);
    if (!record) return res.status(404).json({ ok: false, error: 'Reaudit not found' });
    return res.json({ ok: true, reaudit: record });
  } catch (error) {
    return res.status(500).json({ ok: false, error: errorText(error) });
  }
}

async function addExternalContract(req, res) {
  try {
    const db = await getDb();
    const reaudits = db.collection('reaudits');
    const record = await getReauditById(req.params.id);

    if (!record) return res.status(404).json({ ok: false, error: 'Reaudit not found' });
    if (record.status !== 'pending') return res.status(409).json({ ok: false, error: `Reaudit is ${record.status}; contracts can only be added while pending.` });

    const address = cleanAddress(req.body?.address);
    if (!address) return res.status(400).json({ ok: false, error: 'A valid Ethereum contract address is required.' });
    if (address.toLowerCase() === String(record.mainAddress).toLowerCase()) {
      return res.status(400).json({ ok: false, error: 'The Reaudit external contract must be different from the main contract.' });
    }

    const duplicate = (record.externalContracts || []).some(x => String(x.address).toLowerCase() === address.toLowerCase());
    if (duplicate) return res.status(409).json({ ok: false, error: 'That external contract is already attached.' });

    const batch = await db.collection('batches').findOne({ batchId: record.batchId });
    if (!batch) return res.status(404).json({ ok: false, error: 'Parent batch not found' });
    if (!batch.etherscanKey) return res.status(400).json({ ok: false, error: 'This batch has no saved Etherscan key.' });

    const external = await fetchExternalContract({
      address,
      chainId: record.chainId,
      etherscanKey: batch.etherscanKey
    });

    external.addedAt = now();

    external.includedInLLM =
    external.sourceStatus === 'verified' && Boolean(external.source);

const hasVerifiedSource =
  (record.externalContracts || []).some(
    x => x.sourceStatus === 'verified' && x.source
  ) || external.includedInLLM;

await reaudits.updateOne(
  { _id: record._id, status: 'pending' },
  {
    $push: { externalContracts: external },
    $set: {
      updatedAt: now(),
      auditStage: hasVerifiedSource
        ? 'reaudit_ready_to_run'
        : 'reaudit_pending'
    }
  }
);

    const updated = await reaudits.findOne({ _id: record._id });
    return res.json({ ok: true, contract: external, reaudit: updated });
  } catch (error) {
    return res.status(500).json({ ok: false, error: errorText(error) });
  }
}

function buildNormalReauditContext(record, evidence) {
  return `
ONE-TIME REAUDIT — BLACK-BOX ESCALATION RESOLUTION

This is the FINAL allowed Reaudit for this contract. Do NOT create or request another Reaudit.

ORIGINAL BLACK-BOX ESCALATION:
${record.originalBlackBoxEscalation || 'See the original audit result below.'}

FIRST LLM RESULT:
${record.originalResult || 'Unavailable'}

NEW VERIFIED EXTERNAL CONTRACT EVIDENCE:
${evidence || 'No verified external contract source was supplied.'}

Re-evaluate the ORIGINAL audit using the newly supplied verified external source(s).
Preserve findings that remain supported by code. Retract findings disproven by the new evidence.
Resolve the original black-box dependency where the supplied source permits it.
If another external dependency remains unresolved, clearly document that limitation in the final
report, but do not create another Reaudit item.
`;
}

async function runNormalReaudit(record, batch, evidence) {
  const keys = Array.isArray(batch.llmApiKeys)
    ? [...new Set(batch.llmApiKeys.map(k => String(k || '').trim()).filter(Boolean))]
    : [];

  if (!batch.llmUrl || !batch.model || !keys.length) {
    const error = new Error('Original Normal LLM configuration is incomplete for Reaudit');
    error.code = 'REAUDIT_CONFIG_INVALID';
    throw error;
  }

  let lastError = null;
  for (const apiKey of keys) {
    try {
      return await runLLMAudit({
        source: batchItemSource(record),
        systemPrompt: batch.systemPrompt,
        model: batch.model,
        contractName: record.contractName || 'Unknown',
        address: record.auditedAddress || record.mainAddress,
        llmUrl: batch.llmUrl,
        apiKey,
        additionalContext: buildNormalReauditContext(record, evidence)
      });
    } catch (error) {
      lastError = error;
      const code = String(error?.code || '').toUpperCase();
      if (!['RATE_LIMIT', 'QUOTA', 'INVALID_KEY', 'PROVIDER_ERROR', 'EMPTY_RESPONSE'].includes(code)) throw error;
    }
  }
  throw lastError || new Error('All Normal Reaudit LLM keys failed');
}

function batchItemSource(record) {
  return String(record.mainSource || '');
}

// Returns the main contract's source. Older COM reaudits were created before
// batch_items.source was persisted, so fall back to the item, then re-fetch
// from the explorer, and save the healed value so this only happens once.
async function resolveMainSource({ db, record, item, batch }) {
  const existing = String(record.mainSource || item?.source || '').trim();
  if (existing) return existing;

  const address = record.auditedAddress || record.mainAddress;
  if (!batch?.etherscanKey) {
    throw new Error('Main contract source is missing and this batch has no saved Etherscan key to re-fetch it.');
  }

  const fetched = await fetchExternalContract({
    address,
    chainId: record.chainId || String(batch.chainId || '1'),
    etherscanKey: batch.etherscanKey
  });

  if (fetched.sourceStatus !== 'verified' || !fetched.source) {
    throw new Error(`Main contract source is missing and could not be re-fetched for ${address}.`);
  }

  await db.collection('reaudits').updateOne(
    { _id: record._id },
    { $set: { mainSource: fetched.source, updatedAt: now() } }
  );
  await db.collection('batch_items').updateOne(
    { _id: item._id },
    { $set: { source: fetched.source } }
  );
  return fetched.source;
}

async function runReaudit(req, res) {
  try {
    const db = await getDb();
    const reaudits = db.collection('reaudits');
    const record = await getReauditById(req.params.id);

    if (!record) return res.status(404).json({ ok: false, error: 'Reaudit not found' });
    if (record.status !== 'pending') return res.status(409).json({ ok: false, error: `Reaudit is ${record.status}; only pending Reaudits can be run.` });
    if (!(record.externalContracts || []).some(x => x.sourceStatus === 'verified' && x.source)) {
      return res.status(400).json({ ok: false, error: 'Add at least one verified external contract source before running Reaudit.' });
    }

    // Atomic claim prevents two browser clicks from launching two Reaudits.
    const claim = await reaudits.findOneAndUpdate(
      { _id: record._id, status: 'pending' },
      { $set: { status: 'running', startedAt: now(), updatedAt: now(), error: null } },
      { returnDocument: 'after' }
    );

    if (!claim) return res.status(409).json({ ok: false, error: 'Reaudit was already claimed.' });

    const batch = await db.collection('batches').findOne({ batchId: record.batchId });
    const item = await db.collection('batch_items').findOne({
  _id: new (require('mongodb').ObjectId)(record.auditId)
});
    if (!batch || !item) throw new Error('Parent batch item no longer exists');

    const mainSource = await resolveMainSource({ db, record, item, batch });
    record.mainSource = mainSource;

    const evidence = verifiedEvidence(record);
    const externalSummary = (record.externalContracts || []).map(x => ({
      address: x.address,
      sourceStatus: x.sourceStatus,
      isProxy: x.isProxy,
      implementation: x.implementation,
      contractName: x.contractName,
      note: x.note,
      includedInLLM: x.includedInLLM
    }));

    await reaudits.updateOne({ _id: record._id }, { $set: { externalSummary, updatedAt: now() } });

    if (record.mode === 'com') {
      const checkpoint = async com => {
        await reaudits.updateOne(
          { _id: record._id },
          { $set: { com, updatedAt: now() } }
        );
      };

      // runComReaudit supplies the main source through runAudit below.
      const runAudit = async (side, additionalContext) => {
        const cfg = batch.com?.[side];
        const keys = Array.isArray(cfg?.apiKeys)
          ? [...new Set(cfg.apiKeys.map(k => String(k || '').trim()).filter(Boolean))]
          : [];
        if (!cfg?.url || !cfg?.model || !keys.length) {
          const error = new Error(`COM ${side} is not fully configured for Reaudit`);
          error.code = 'COM_CONFIG_INVALID';
          throw error;
        }

        let lastError = null;
        for (const apiKey of keys) {
          try {
            const audit = await runLLMAudit({
              source: mainSource,
              systemPrompt: batch.systemPrompt,
              model: cfg.model,
              contractName: item.contractName || 'Unknown',
              address: item.auditedAddress || item.address,
              llmUrl: cfg.url,
              apiKey,
              additionalContext
            });
            return audit.result;
          } catch (error) {
            lastError = error;
            const code = String(error?.code || '').toUpperCase();
            if (!['RATE_LIMIT', 'QUOTA', 'INVALID_KEY', 'PROVIDER_ERROR', 'EMPTY_RESPONSE'].includes(code)) throw error;
          }
        }
        throw lastError || new Error(`COM ${side} Reaudit failed`);
      };

      const outcome = await runComReaudit({
        item: {
          ...item,
          source: mainSource,
          reauditOriginalBlackBox: record.originalBlackBoxEscalation
        },
        runAudit,
        checkpoint,
        evidenceContext: evidence
      });

      await reaudits.updateOne(
        { _id: record._id },
        {
          $set: {
            status: 'ready',
            completed: true,
            skipped: false,
            com: outcome.com,
            result: null,
            error: null,
            finishedAt: now(),
            updatedAt: now()
          }
        }
      );
    } else {
      const audit = await runNormalReaudit(record, {
        ...batch,
        systemPrompt: batch.systemPrompt
      }, evidence);

      await reaudits.updateOne(
        { _id: record._id },
        {
          $set: {
            status: 'ready',
            completed: true,
            skipped: false,
            result: audit.result,
            truncated: audit.truncated || false,
            error: null,
            finishedAt: now(),
            updatedAt: now()
          }
        }
      );
    }

    await drainReadyReaudits(record.batchId).catch(e => console.error('[REAUDIT] drain failed:', e));
    return res.json({ ok: true, status: 'ready', message: 'Reaudit completed and queued for priority application by the batch worker.' });
  } catch (error) {
    try {
      const db = await getDb();
await db.collection('reaudits').updateOne(
  { _id: new (require('mongodb').ObjectId)(req.params.id) },
  {
    $set: {
      status: 'pending',
      updatedAt: now(),
      error: errorText(error)
    }
  }
);
    } catch (_) {}
    return res.status(500).json({ ok: false, error: errorText(error) });
  }
}

async function skipReaudit(req, res) {
  try {
    const db = await getDb();
    const reaudits = db.collection('reaudits');
    const record = await getReauditById(req.params.id);
    if (!record) return res.status(404).json({ ok: false, error: 'Reaudit not found' });

    const claimed = await reaudits.findOneAndUpdate(
      { _id: record._id, status: 'pending' },
      {
        $set: {
          status: 'ready',
          completed: true,
          skipped: true,
          result: null,
          com: null,
          error: null,
          finishedAt: now(),
          updatedAt: now()
        }
      },
      { returnDocument: 'after' }
    );

    if (!claimed) return res.status(409).json({ ok: false, error: `Reaudit is already ${record.status}.` });

    await drainReadyReaudits(record.batchId).catch(e => console.error('[REAUDIT] drain failed:', e));
    return res.json({ ok: true, status: 'ready', skipped: true, message: 'Reaudit skipped and queued for priority application.' });
  } catch (error) {
    return res.status(500).json({ ok: false, error: errorText(error) });
  }
}

async function resumePendingReaudits() {
  try {
    const db = await getDb();
    const result = await db.collection('reaudits').updateMany(
      { status: 'running' },
      { $set: { status: 'pending', updatedAt: now(), error: 'Server restarted before Reaudit completed; returned to pending.' } }
    );
    if (result.modifiedCount) console.log(`[REAUDIT] Reset ${result.modifiedCount} interrupted Reaudit(s) to pending`);
  } catch (error) {
    console.error('[REAUDIT] Startup recovery failed:', error);
  }
}

// Worker helpers ------------------------------------------------
async function claimReadyReaudit(batchId) {
  const db = await getDb();
  return db.collection('reaudits').findOneAndUpdate(
    {
      batchId,
      status: 'ready',
      appliedAt: { $exists: false }
    },
    {
      $set: {
        status: 'applying',
        claimedAt: now(),
        updatedAt: now()
      }
    },
    {
      sort: { prioritySeq: 1, createdAt: 1 },
      returnDocument: 'after'
    }
  );
}

async function applyClaimedReaudit(record) {
  const db = await getDb();
  const items = db.collection('batch_items');
  const reaudits = db.collection('reaudits');

  const item = await items.findOne({
  _id: new (require('mongodb').ObjectId)(record.auditId),
  batchId: record.batchId
});
  if (!item) {
    await reaudits.updateOne({ _id: record._id }, { $set: { status: 'applied', appliedAt: now(), updatedAt: now(), error: 'Original batch item no longer exists' } });
    return { applied: false, missing: true };
  }

  const set = {
    status: 'completed',
    auditStage: record.skipped ? 'reaudit_skipped' : 'reaudit_completed',
    reauditUsed: true,
    reauditAppliedAt: now(),
    reauditId: record.auditId,
    updatedAt: now(),
    finishedAt: record.finishedAt || now(),
    error: record.skipped ? null : null
  };

  if (!record.skipped) {
    if (record.mode === 'com' && record.com) {
      set.com = record.com;
      set.audit = null;
    } else {
      set.audit = record.result;
      set.truncated = record.truncated || false;
    }
  }

  await items.updateOne(
    { _id: item._id, reauditUsed: { $ne: true } },
    { $set: set }
  );

  await reaudits.updateOne(
    { _id: record._id, status: 'applying' },
    {
      $set: {
        status: 'applied',
        appliedAt: now(),
        updatedAt: now()
      }
    }
  );

  console.log(`[REAUDIT] Applied ${record.mainAddress} batch=${record.batchId} index=${record.originalIndex} skipped=${record.skipped}`);
  return { applied: true, skipped: Boolean(record.skipped) };
}

// Applying a finished Reaudit is only a DB write, so it must not depend on a
// batch worker being alive. If the batch is paused / completed / cancelled (no
// worker), nothing would ever claim the 'ready' record. This applies them
// directly. When a worker IS active we leave it to the worker's priority slot.
// claimReadyReaudit is atomic, so a worker and this function can never both
// apply the same record.
function workerIsActive(batchId) {
  try {
    return require('./batch').isWorkerActive(batchId);
  } catch (_) {
    return false;
  }
}

async function drainReadyReaudits(onlyBatchId = null) {
  const db = await getDb();
  const query = { status: 'ready', appliedAt: { $exists: false } };
  if (onlyBatchId) query.batchId = onlyBatchId;

  const batchIds = await db.collection('reaudits').distinct('batchId', query);
  let applied = 0;

  for (const batchId of batchIds) {
    if (workerIsActive(batchId)) continue;

    let record;
    while ((record = await claimReadyReaudit(batchId))) {
      const result = await applyClaimedReaudit(record);
      if (result.applied) {
        await db.collection('batches').updateOne(
          { batchId },
          { $inc: { completed: 1 }, $set: { updatedAt: now() } }
        );
        applied++;
      }
    }
  }

  if (applied) console.log(`[REAUDIT] Drained ${applied} ready Reaudit(s) with no active worker`);
  return applied;
}

// Clear finished (applied) Reaudit records from the queue.
// Body: { ids?: string[], batchId?: string }. With no filter it clears every
// applied record. Only 'applied' records are ever deleted: the batch item has
// already stored its final result, so nothing depends on them. A pending /
// running / ready record must be closed with SKIP instead, otherwise its batch
// item would be stranded on reaudit_pending.
async function clearReaudits(req, res) {
  try {
    const { ObjectId } = require('mongodb');
    const db = await getDb();
    const query = { status: 'applied' };

    if (Array.isArray(req.body?.ids)) {
      const ids = req.body.ids.filter(id => ObjectId.isValid(id)).map(id => new ObjectId(id));
      if (!ids.length) return res.json({ ok: true, deleted: 0 });
      query._id = { $in: ids };
    }
    if (req.body?.batchId) query.batchId = String(req.body.batchId);

    const result = await db.collection('reaudits').deleteMany(query);
    return res.json({ ok: true, deleted: result.deletedCount || 0 });
  } catch (error) {
    return res.status(500).json({ ok: false, error: errorText(error) });
  }
}

router.get('/', listReaudits);
router.post('/clear', clearReaudits);
router.get('/:id', getReaudit);
router.post('/:id/contracts', addExternalContract);
router.post('/:id/run', runReaudit);
router.post('/:id/skip', skipReaudit);

module.exports = {
  router,
  ensureReauditRecord,
  claimReadyReaudit,
  applyClaimedReaudit,
  resumePendingReaudits,
  isUnratedResult
};

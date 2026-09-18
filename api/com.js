// api/com.js
// Checkpoint-safe concurrent two-auditor COM orchestrator.

const COM_REVIEW_PROMPT = `
COM CROSS-REVIEW PROTOCOL
You are performing a second-stage adversarial review of a Solidity security audit.
Do not assume either first-pass audit is correct.
Validate findings against source code, reject false positives, re-check your own reasoning,
search for vulnerabilities missed by both auditors, resolve disagreements with concrete code evidence,
and then produce a complete final security assessment in the same structured style as the original audit.
`;

function isDone(v) {
  return v && v.status === 'complete' && typeof v.result === 'string' && v.result.trim();
}

async function runComBatchItem({ item, contract, runAudit, checkpoint }) {
  const state = item.com || { status: 'phase1', llmA: {}, llmB: {} };
  state.llmA ||= {};
  state.llmB ||= {};

  const runPhase = async (side, phase, context) => {
    const bucket = state[side];
    if (isDone(bucket[phase])) return bucket[phase].result;
    bucket[phase] = { ...(bucket[phase] || {}), status: 'running', startedAt: new Date() };
    await checkpoint(state);
    try {
      const result = await runAudit(side, context);
      bucket[phase] = { status: 'complete', result, finishedAt: new Date() };
      await checkpoint(state);
      return result;
    } catch (error) {
      bucket[phase] = { status: 'pending', error: String(error?.message || error), updatedAt: new Date() };
      await checkpoint(state);
      throw error;
    }
  };

  // Phase 1: genuinely concurrent. Each branch checkpoints independently.
  if (!isDone(state.llmA.initial) || !isDone(state.llmB.initial)) {
    state.status = 'phase1';
    await checkpoint(state);
    const tasks = [];
    if (!isDone(state.llmA.initial)) tasks.push(runPhase('llmA', 'initial', ''));
    if (!isDone(state.llmB.initial)) tasks.push(runPhase('llmB', 'initial', ''));
    await Promise.all(tasks);
  }

  const a1 = state.llmA.initial.result;
  const b1 = state.llmB.initial.result;

  // Phase 2: genuinely concurrent cross-review.
  if (!isDone(state.llmA.final) || !isDone(state.llmB.final)) {
    state.status = 'phase2';
    await checkpoint(state);
    const tasks = [];
    if (!isDone(state.llmA.final)) {
      tasks.push(runPhase(
        'llmA',
        'final',
        `${COM_REVIEW_PROMPT}\n\nYOUR FIRST-PASS AUDIT (A1):\n${a1}\n\nINDEPENDENT AUDITOR FIRST-PASS AUDIT (B1):\n${b1}`
      ));
    }
    if (!isDone(state.llmB.final)) {
      tasks.push(runPhase(
        'llmB',
        'final',
        `${COM_REVIEW_PROMPT}\n\nYOUR FIRST-PASS AUDIT (B1):\n${b1}\n\nINDEPENDENT AUDITOR FIRST-PASS AUDIT (A1):\n${a1}`
      ));
    }
    await Promise.all(tasks);
  }

  state.status = 'complete';
  state.completedAt = new Date();
  await checkpoint(state);
  return { status: 'completed', com: state };
}

// ------------------------------------------------------------
// COM REAUDIT
// ------------------------------------------------------------
//
// A Reaudit is NOT a new phase-1 audit. The original COM A/B
// results are the first-pass evidence. New verified external
// source(s) are added, and both auditors independently perform a
// fresh cross-review. Each auditor receives:
//   - main contract source (runAudit supplies it)
//   - original A/B results
//   - original black-box escalation
//   - all verified external evidence
//   - the other auditor's original result
//
// The two final Reaudit results are saved as the new COM result.
// No recursive Reaudit is created from this function.
// ------------------------------------------------------------
async function runComReaudit({
  item,
  runAudit,
  checkpoint,
  evidenceContext
}) {
  const original = item.com || {};
  const a1 = original?.llmA?.final?.result || original?.llmA?.initial?.result || '';
  const b1 = original?.llmB?.final?.result || original?.llmB?.initial?.result || '';

  if (!a1 && !b1) {
    const error = new Error('Original COM results are missing; cannot run COM Reaudit');
    error.code = 'COM_REAUDIT_MISSING_ORIGINAL_RESULTS';
    throw error;
  }

  const state = {
    status: 'reaudit_phase2',
    llmA: {
      initial: original?.llmA?.initial || null,
      final: null
    },
    llmB: {
      initial: original?.llmB?.initial || null,
      final: null
    },
    reaudit: true,
    startedAt: new Date()
  };

  const runFinal = async (side, own, other) => {
    const context = `${COM_REVIEW_PROMPT}

THIS IS A ONE-TIME REAUDIT. DO NOT CREATE OR REQUEST ANOTHER REAUDIT.

NEW VERIFIED EXTERNAL EVIDENCE:
${evidenceContext || 'No verified external evidence was supplied.'}

ORIGINAL BLACK-BOX ESCALATION:
${item.reauditOriginalBlackBox || 'Not separately extracted; inspect the original audit result.'}

ORIGINAL AUDITOR A RESULT:
${a1 || '[missing]'}

ORIGINAL AUDITOR B RESULT:
${b1 || '[missing]'}

YOUR ORIGINAL RESULT:
${own || '[missing]'}

OTHER AUDITOR RESULT:
${other || '[missing]'}

Re-evaluate the main contract against the newly supplied verified source(s).
Preserve findings that remain supported, retract findings disproven by the new evidence,
and explicitly identify any remaining unresolved external dependency or limitation.
Even if another black-box dependency remains unresolved, this is the FINAL pass and must not
create another Reaudit item.`;

    return runAudit(side, context);
  };

  state.status = 'reaudit_phase2';
  await checkpoint(state);

  const [a2, b2] = await Promise.all([
    runFinal('llmA', a1, b1),
    runFinal('llmB', b1, a1)
  ]);

  state.llmA.final = { status: 'complete', result: a2, finishedAt: new Date() };
  state.llmB.final = { status: 'complete', result: b2, finishedAt: new Date() };
  state.status = 'complete';
  state.completedAt = new Date();

  await checkpoint(state);

  return {
    status: 'completed',
    com: state
  };
}

module.exports = {
  runComBatchItem,
  runComReaudit,
  COM_REVIEW_PROMPT
};

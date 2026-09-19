
// api/batch.js

const crypto =
  require('crypto');

const express =
  require('express');

const {
  getDb
} = require('./db');

const {
  runLLMAudit
} = require('./llm');

const {
  shouldSkipContractName
} = require('./contract-skip-list');

const {
  updateBatchConfig
} = require('./batch-config');

const {
  runComBatchItem
} = require('./com');

const {
  ensureReauditRecord,
  claimReadyReaudit,
  applyClaimedReaudit
} = require('./reaudit');


// ============================================================
// CONFIGURATION
// ============================================================

// Maximum source sent to the LLM.
const MAX_SOURCE_CHARS =
  1500000;

// ============================================================
// ADAPTIVE LLM RATE LEARNING
// ============================================================
//
// The system learns the safest request interval for each:
//
// Provider + Model + API Key
//
// It starts conservatively, slowly probes faster after sustained
// success, and slows down aggressively when a provider rate limit
// is detected.
//
// The learned state is persisted in MongoDB, so restarting the
// server does NOT reset the learned rate.
// ============================================================

const RATE_LEARNING = {

  // Starting point for a completely unknown provider/profile.
  //
  // 600ms ~= 1.67 requests/sec.
  DEFAULT_INTERVAL_MS:
    600,

  // Never go faster than this.
  //
  // This protects against the learner becoming too aggressive.
  MIN_INTERVAL_MS:
    300,

  // Never become slower than this.
  //
  // Prevents pathological rate-limit loops from making the
  // pipeline effectively unusable.
  MAX_INTERVAL_MS:
    30000,

  // Number of successful LLM requests before we cautiously
  // attempt to increase speed.
  SUCCESS_THRESHOLD:
    50,

  // After SUCCESS_THRESHOLD consecutive successes:
  //
  // 1000ms -> 970ms
  //
  // Small changes make learning stable.
  SUCCESS_SPEEDUP_FACTOR:
    0.97,

  // On rate limit:
  //
  // 600ms -> 900ms
  //
  // This is intentionally much more aggressive than speeding up.
  RATE_LIMIT_SLOWDOWN_FACTOR:
    1.5,

  // Keep request timestamps for this rolling window.
  WINDOW_MS:
    30 * 60 * 1000,

  // Hard cap on timestamps stored in memory/database.
  MAX_HISTORY:
    3000,

  // Persist normal learning progress every N successful requests.
  SAVE_EVERY_SUCCESSES:
    10
};

// ============================================================
// API KEY POOL
// ============================================================
//
// Multiple keys can be configured.
//
// Example:
//
// LLM_API_KEYS=key1,key2,key3
//
// Each key gets:
//   - Independent rate learning
//   - Independent cooldown
//   - Independent quota state
//   - Independent health tracking
//
// Raw keys are NEVER returned through the API.
// ============================================================

const KEY_POOL = {

  // Temporary 429 cooldown.
  RATE_LIMIT_COOLDOWN_MS:
    2 * 60 * 1000,

  // Quota failures usually last longer.
  QUOTA_COOLDOWN_MS:
    60 * 60 * 1000,

  // Provider/server failures.
  PROVIDER_ERROR_COOLDOWN_MS:
    30 * 1000,

  // Invalid credentials.
  INVALID_KEY_COOLDOWN_MS:
    24 * 60 * 60 * 1000,

  // ----------------------------------------------------------
  // EMPTY RESPONSE HANDLING
  // ----------------------------------------------------------
  //
  // A HTTP 200 empty completion does NOT mean the key is bad.
  //
  // We allow retries and only temporarily cool down a key when
  // empty responses become consecutive/repeated.
  // ----------------------------------------------------------

  EMPTY_RESPONSE_THRESHOLD:
    3,

  EMPTY_RESPONSE_COOLDOWN_MS:
    60 * 1000
};

function getConfiguredLLMKeys(batch) {

  if (
    !Array.isArray(
      batch?.llmApiKeys
    )
  ) {
    return [];
  }

  return [

    ...new Set(

      batch.llmApiKeys

        .map(
          key =>
            String(
              key || ''
            ).trim()
        )

        .filter(Boolean)

    )

  ];
}


function getConfiguredKeysFrom(config) {
  if (!Array.isArray(config?.apiKeys)) return [];
  return [...new Set(config.apiKeys.map(k => String(k || '').trim()).filter(Boolean))];
}


// ============================================================
// GET ALL CURRENTLY CONFIGURED WEB KEYS
// ============================================================
//
// Keys live inside batches because your web interface submits
// them with batch configuration.
//
// We collect unique fingerprints across batches.
//
// Raw API keys are never returned.
// ============================================================

async function getCurrentConfiguredKeyFingerprints(db) {
  const batches = await db
    .collection('batches')
    .find(
      {},
      {
        projection: {
          llmApiKeys: 1,
          mode: 1,
          com: 1
        }
      }
    )
    .toArray();

  const fingerprints = new Set();

  for (const batch of batches) {
    // Normal mode keys
    const normalKeys = getConfiguredLLMKeys(batch);

    for (const key of normalKeys) {
      fingerprints.add(getKeyFingerprint(key));
    }

    // COM mode: include BOTH auditor key pools
    if (batch.mode === 'com' && batch.com) {
      const llmAKeys = getConfiguredKeysFrom(
        batch.com.llmA
      );

      const llmBKeys = getConfiguredKeysFrom(
        batch.com.llmB
      );

      for (const key of llmAKeys) {
        fingerprints.add(getKeyFingerprint(key));
      }

      for (const key of llmBKeys) {
        fingerprints.add(getKeyFingerprint(key));
      }
    }
  }

  return fingerprints;
}

function getKeyFingerprint(apiKey) {

  return crypto
    .createHash('sha256')
    .update(String(apiKey || ''))
    .digest('hex')
    .slice(-12);
}

// How long to wait between completed contracts.
const ITEM_DELAY =
  200;

// Maximum number of attempts when the LLM returns an empty response.
// 3 total attempts = initial attempt + 2 retries.
const MAX_EMPTY_AUDIT_ATTEMPTS =
  3;

// ============================================================
// WORKER STATE
// ============================================================

const activeWorkers =
  new Set();


// ============================================================
// ADDRESS VALIDATION
// ============================================================

const ADDRESS_RE =
  /^0x[a-fA-F0-9]{40}$/;


function cleanAddress(
  address
) {

  if (
    typeof address !==
    'string'
  ) {
    return null;
  }


  const value =
    address.trim();


  if (
    !ADDRESS_RE.test(
      value
    )
  ) {
    return null;
  }


  return value;
}


// ============================================================
// PARSE ADDRESSES
// ============================================================
//
// Supports:
//
// [
//   {"address":"0x..."},
//   {"address":"0x..."}
// ]
//
// JSONL:
//
// {"address":"0x..."}
// {"address":"0x..."}
//
// Plain:
//
// 0x...
// 0x...
//
// Also:
//
// [
//   "0x...",
//   "0x..."
// ]
//
// Duplicates are removed.
// ============================================================

function parseAddresses(
  input
) {

  const addresses =
    [];

  const seen =
    new Set();


  function add(
    value
  ) {

    const address =
      cleanAddress(
        value
      );


    if (!address) {
      return;
    }


    const normalized =
      address.toLowerCase();


    if (
      seen.has(
        normalized
      )
    ) {
      return;
    }


    seen.add(
      normalized
    );


    addresses.push(
      address
    );
  }


  function parseValue(
    value
  ) {

    if (
      typeof value ===
      'string'
    ) {

      // A string may contain one or more addresses.
      const matches =
        value.match(
          /0x[a-fA-F0-9]{40}/g
        );


      if (matches) {

        for (
          const address
          of matches
        ) {
          add(address);
        }

      } else {

        add(value);
      }


      return;
    }


    if (
      Array.isArray(
        value
      )
    ) {

      for (
        const item
        of value
      ) {

        parseValue(
          item
        );
      }


      return;
    }


    if (
      value &&
      typeof value ===
      'object'
    ) {

      if (
        value.address
      ) {

        add(
          value.address
        );
      }


      if (
        value.contractAddress
      ) {

        add(
          value.contractAddress
        );
      }


      if (
        Array.isArray(
          value.addresses
        )
      ) {

        parseValue(
          value.addresses
        );
      }
    }
  }


  // Already parsed object/array.
  if (
    input &&
    typeof input ===
    'object'
  ) {

    parseValue(
      input
    );

    return addresses;
  }


  if (
    typeof input !==
    'string'
  ) {

    return addresses;
  }


  const text =
    input.trim();


  if (!text) {
    return addresses;
  }


  // ==========================================================
  // FIRST: TRY THE ENTIRE STRING AS JSON
  //
  // This is the important fix for pretty-printed JSON.
  // ==========================================================

  try {

    const parsed =
      JSON.parse(
        text
      );


    parseValue(
      parsed
    );


    if (
      addresses.length
    ) {

      return addresses;
    }

  } catch {
    // Continue to JSONL/plain-text parsing.
  }


  // ==========================================================
  // JSONL / PLAIN TEXT
  // ==========================================================

  const lines =
    text.split(
      /\r?\n/
    );


  for (
    const line
    of lines
  ) {

    const trimmed =
      line.trim();


    if (!trimmed) {
      continue;
    }


    // Try one complete JSONL line.
    try {

      const parsed =
        JSON.parse(
          trimmed
        );


      parseValue(
        parsed
      );


      continue;

    } catch {
      // Fall through.
    }


    // Find Ethereum addresses anywhere in the line.
    const matches =
      trimmed.match(
        /0x[a-fA-F0-9]{40}/g
      );


    if (matches) {

      for (
        const address
        of matches
      ) {

        add(
          address
        );
      }
    }
  }


  return addresses;
}


// ============================================================
// ERROR HELPERS
// ============================================================

function errorText(
  error
) {

  return String(
    error?.message ||
    error ||
    'Unknown error'
  ) }

function isEmptyAuditResponseError(
  error
) {

  const code =
    String(
      error?.code ||
      ''
    ).toUpperCase();

  if (
    code === 'EMPTY_RESPONSE'
  ) {
    return true;
  }

  const message =
    errorText(
      error
    ).toLowerCase();

  return (
    message.includes(
      'llm returned an empty audit response'
    )
  );
}


function isPipelineStopError(
  error
) {

  if (!error) {
    return false;
  }

  const code =
    String(
      error.code ||
      ''
    ).toUpperCase();

  // Only explicit machine-generated error codes should stop
  // the entire pipeline.
  //
  // Do not inspect arbitrary natural-language messages.

  return (
    code === 'RATE_LIMIT' ||
    code === 'QUOTA' ||
    code === 'ALL_KEYS_UNAVAILABLE'
  );
}


function pipelineStopType(
  error
) {

  const code =
    String(
      error?.code ||
      ''
    ).toUpperCase();


  if (
    code ===
    'QUOTA'
  ) {

    return 'paused_quota';
  }


  return 'paused_rate_limit';
}


// ============================================================
// TIME HELPERS
// ============================================================

function now() {
  return new Date();
}


function sleep(
  milliseconds
) {

  return new Promise(
    resolve =>
      setTimeout(
        resolve,
        milliseconds
      )
  );
}


// ============================================================
// ADAPTIVE GLOBAL LLM RATE CONTROLLER
// ============================================================
//
// One Node process may process multiple batches, but all LLM
// requests pass through this single controller.
//
// The controller:
//   1. Serializes LLM requests.
//   2. Learns safe request intervals.
//   3. Persists learning in MongoDB.
//   4. Survives server restarts.
//   5. Tracks recent request timestamps.
// ============================================================


const rateProfiles =
  new Map();


let llmThrottle =
  Promise.resolve();


// ============================================================
// PROFILE KEY
// ============================================================
//
// We never store the raw API key in the rate profile.
//
// Instead:
//
// SHA256(llmUrl + model + apiKey)
//
// This creates a stable identity for one provider/model/key
// combination without exposing the key.
// ============================================================

function getRateProfileId({
  llmUrl,
  model, 
  apiKey
}) {

  return crypto
    .createHash(
      'sha256'
    )
    .update(
      [
        String(
          llmUrl ||
          ''
        ),

        String(
          model ||
          ''
        ),

        String(
          apiKey ||
          ''
        )
      ].join(
        '|'
      )
    )
    .digest(
      'hex'
    );
}


// ============================================================
// CREATE DEFAULT PROFILE
// ============================================================

function createDefaultRateProfile({
  profileId,
  llmUrl,
  model, 
  apiKey
}) {

  return {

    _id:
      profileId,

    llmUrl:
      llmUrl ||
      null,

    model:
      model ||
      null,


    // --------------------------------------------------------
    // CURRENT LEARNED STATE
    // --------------------------------------------------------

    currentIntervalMs:
      RATE_LEARNING.DEFAULT_INTERVAL_MS,

    fastestKnownSafeMs:
      RATE_LEARNING.DEFAULT_INTERVAL_MS,

    lastFailedIntervalMs:
      null,


    // --------------------------------------------------------
    // SUCCESS / FAILURE STATS
    // --------------------------------------------------------

    consecutiveSuccesses:
      0,

    totalSuccesses:
      0,

    rateLimitHits:
      0,


    // --------------------------------------------------------
    // REQUEST HISTORY
    // --------------------------------------------------------

    recentRequests:
      [],

    lastRequestAt:
      0,

    lastRateLimitAt:
      null,

    // --------------------------------------------------------
// KEY POOL STATE
// --------------------------------------------------------

keyFingerprint:
  getKeyFingerprint(apiKey),

keyStatus:
  'available',

cooldownUntil:
  null,

lastErrorCode:
  null,

lastErrorAt:
  null,

quotaHits:
  0,

invalidKeyHits:
  0,

providerErrorHits:
  0,

// --------------------------------------------------------
// EMPTY RESPONSE HEALTH
// --------------------------------------------------------
//
// These are separate from rate limits and invalid keys.
// A HTTP 200 empty response should never permanently
// disable a key.
// --------------------------------------------------------

emptyResponseStreak:
  0,

totalEmptyResponses:
  0,

lastEmptyResponseAt:
  null,

lastUsedAt:
  null,
    // --------------------------------------------------------
    // INTERNAL STATE
    // --------------------------------------------------------

    unsavedSuccesses:
      0,

    createdAt:
      now(),

    updatedAt:
      now()
  };
}


// ============================================================
// NORMALIZE PROFILE
// ============================================================
//
// Allows us to safely load older/incomplete MongoDB documents.
// ============================================================

function normalizeRateProfile(
  profile,
  defaults
) {

  const fallback =
    createDefaultRateProfile(
      defaults
    );


  return {

    ...fallback,

    ...profile,


    currentIntervalMs:
      clampInterval(
        profile?.currentIntervalMs ??
        fallback.currentIntervalMs
      ),

    fastestKnownSafeMs:
      clampInterval(
        profile?.fastestKnownSafeMs ??
        fallback.fastestKnownSafeMs
      ),

    recentRequests:
      Array.isArray(
        profile?.recentRequests
      )
        ? profile.recentRequests
        : [],

    unsavedSuccesses:
      0
  };
}


// ============================================================
// CLAMP INTERVAL
// ============================================================

function clampInterval(
  value
) {

  const numeric =
    Number(
      value
    );

  if (
    !Number.isFinite(
      numeric
    )
  ) {
    return RATE_LEARNING.DEFAULT_INTERVAL_MS;
  }


  return Math.round(
    Math.max(
      RATE_LEARNING.MIN_INTERVAL_MS,

      Math.min(
        RATE_LEARNING.MAX_INTERVAL_MS,
        numeric
      )
    )
  );
}


// ============================================================
// PRUNE REQUEST HISTORY
// ============================================================
//
// We only care about recent behavior.
//
// Old timestamps are removed so MongoDB does not grow forever.
// ============================================================

function pruneRateHistory(
  profile
) {

  const cutoff =
    Date.now() -
    RATE_LEARNING.WINDOW_MS;


  profile.recentRequests =
    profile.recentRequests
      .map(
        timestamp =>
          new Date(
            timestamp
          ).getTime()
      )
      .filter(
        timestamp =>
          Number.isFinite(
            timestamp
          ) &&
          timestamp >= cutoff
      )
      .slice(
        -RATE_LEARNING.MAX_HISTORY
      );
}


// ============================================================
// LOAD RATE PROFILE
// ============================================================
//
// MongoDB is checked only when a profile is first needed.
//
// Afterwards the profile stays cached in memory.
// ============================================================

async function getRateProfile({
  llmUrl,
  model,
  apiKey
}) {
  const profileId =
    getRateProfileId({
      llmUrl,
      model,
      apiKey
    });

  if (
    rateProfiles.has(
      profileId
    )
  ) {
    return rateProfiles.get(
      profileId
    );
  }

  const db =
    await getDb();

  const collection =
    db.collection(
      'llm_rate_profiles'
    );

  const existing =
    await collection.findOne({
      _id: profileId
    });

  if (existing) {
    const profile =
      normalizeRateProfile(
        existing,
        {
          profileId,
          llmUrl,
          model,
          apiKey
        }
      );

    pruneRateHistory(
      profile
    );

    rateProfiles.set(
      profileId,
      profile
    );

    console.log(
      `[RATE LEARNER] Loaded profile for ${model}: ` +
      `${profile.currentIntervalMs}ms interval, ` +
      `${profile.totalSuccesses} successes, ` +
      `${profile.rateLimitHits} rate limits`
    );

    return profile;
  }

  const profile =
    createDefaultRateProfile({
      profileId,
      llmUrl,
      model,
      apiKey
    });

  pruneRateHistory(
    profile
  );

  try {
    await collection.insertOne({
      ...profile,
      updatedAt: now()
    });
  } catch (error) {
    // Another concurrent request may have created
    // this exact profile between findOne() and insertOne().
    if (
      error?.code !== 11000
    ) {
      throw error;
    }

    const concurrentProfile =
      await collection.findOne({
        _id: profileId
      });

    if (!concurrentProfile) {
      throw error;
    }

    const loadedProfile =
      normalizeRateProfile(
        concurrentProfile,
        {
          profileId,
          llmUrl,
          model,
          apiKey
        }
      );

    pruneRateHistory(
      loadedProfile
    );

    rateProfiles.set(
      profileId,
      loadedProfile
    );

    return loadedProfile;
  }

  rateProfiles.set(
    profileId,
    profile
  );

  console.log(
    `[RATE LEARNER] Created profile for ${model}`
  );

  return profile;
}


// ============================================================
// SAVE RATE PROFILE
// ============================================================

async function saveRateProfile(
  profile
) {

  pruneRateHistory(
    profile
  );


  const db =
    await getDb();


  await db
    .collection(
      'llm_rate_profiles'
    )
    .updateOne(
      {
        _id:
          profile._id
      },
      {
        $set: {
          keyFingerprint:
  profile.keyFingerprint,

keyStatus:
  profile.keyStatus,

cooldownUntil:
  profile.cooldownUntil,

lastErrorCode:
  profile.lastErrorCode,

lastErrorAt:
  profile.lastErrorAt,

quotaHits:
  profile.quotaHits,

invalidKeyHits:
  profile.invalidKeyHits,

providerErrorHits:
  profile.providerErrorHits,

emptyResponseStreak:
  profile.emptyResponseStreak,

totalEmptyResponses:
  profile.totalEmptyResponses,

lastEmptyResponseAt:
  profile.lastEmptyResponseAt,

lastUsedAt:
  profile.lastUsedAt,

          llmUrl:
            profile.llmUrl,

          model:
            profile.model,

          currentIntervalMs:
            profile.currentIntervalMs,

          fastestKnownSafeMs:
            profile.fastestKnownSafeMs,

          lastFailedIntervalMs:
            profile.lastFailedIntervalMs,

          consecutiveSuccesses:
            profile.consecutiveSuccesses,

          totalSuccesses:
            profile.totalSuccesses,

          rateLimitHits:
            profile.rateLimitHits,

          recentRequests:
            profile.recentRequests,

          lastRequestAt:
            profile.lastRequestAt,

          lastRateLimitAt:
            profile.lastRateLimitAt,

          updatedAt:
            now()
        }
      },
      {
        upsert:
          true
      }
    );


  profile.unsavedSuccesses =
    0;
}
// ============================================================
// RECORD EMPTY RESPONSE
// ============================================================
//
// EMPTY_RESPONSE is NOT an invalid API key.
//
// The provider successfully answered HTTP-wise but returned no
// usable completion.
//
// Strategy:
//
// 1st / 2nd consecutive empty response:
//   - track it
//   - allow retry/failover
//
// 3rd consecutive empty response:
//   - short cooldown
//
// Any successful audit:
//   - resets the streak
// ============================================================

async function recordEmptyResponse(
  db,
  profile
) {

  if (!profile) {
    return;
  }

  const collection =
    db.collection(
      'llm_rate_profiles'
    );

  const nowDate =
    now();

  profile.emptyResponseStreak =
    Number(
      profile.emptyResponseStreak || 0
    ) + 1;

  profile.totalEmptyResponses =
    Number(
      profile.totalEmptyResponses || 0
    ) + 1;

  profile.lastEmptyResponseAt =
    nowDate;

  profile.lastErrorCode =
    'EMPTY_RESPONSE';

  profile.lastErrorAt =
    nowDate;

  // Do NOT touch:
  //
  // invalidKeyHits
  // rateLimitHits
  // quotaHits
  //
  // Empty responses are their own failure type.

  if (
    profile.emptyResponseStreak >=
    KEY_POOL.EMPTY_RESPONSE_THRESHOLD
  ) {

    profile.keyStatus =
      'cooldown';

    profile.cooldownUntil =
      new Date(
        Date.now() +
        KEY_POOL.EMPTY_RESPONSE_COOLDOWN_MS
      );

    console.warn(
      `[KEY POOL] key=${profile.keyFingerprint} ` +
      `entered empty-response cooldown after ` +
      `${profile.emptyResponseStreak} consecutive empty responses`
    );

  } else {

    console.warn(
      `[KEY POOL] Empty response | ` +
      `key=${profile.keyFingerprint} | ` +
      `streak=${profile.emptyResponseStreak}/` +
      `${KEY_POOL.EMPTY_RESPONSE_THRESHOLD}`
    );
  }

  await collection.updateOne(
    {
      _id:
        profile._id
    },
    {
      $set: {
        emptyResponseStreak:
          profile.emptyResponseStreak,

        totalEmptyResponses:
          profile.totalEmptyResponses,

        lastEmptyResponseAt:
          profile.lastEmptyResponseAt,

        keyStatus:
          profile.keyStatus,

        cooldownUntil:
          profile.cooldownUntil,

        lastErrorCode:
          profile.lastErrorCode,

        lastErrorAt:
          profile.lastErrorAt,

        updatedAt:
          nowDate
      }
    }
  );
}
// ============================================================
// KEY POOL STATUS
// ============================================================

function isKeyAvailable(profile) {

  if (!profile) {
    return false;
  }

  if (
    profile.keyStatus === 'disabled'
  ) {
    return false;
  }

  const cooldownUntil =
    profile.cooldownUntil
      ? new Date(
          profile.cooldownUntil
        ).getTime()
      : 0;

  if (
    cooldownUntil &&
    cooldownUntil > Date.now()
  ) {
    return false;
  }

  // Automatically recover expired cooldowns.
  if (
    cooldownUntil &&
    cooldownUntil <= Date.now() &&
    profile.keyStatus === 'cooldown'
  ) {

    profile.keyStatus =
      'available';

    profile.cooldownUntil =
      null;
  }

  return true;
}


function getKeyCooldownRemaining(profile) {

  if (
    !profile?.cooldownUntil
  ) {
    return 0;
  }

  return Math.max(
    0,
    new Date(
      profile.cooldownUntil
    ).getTime() -
    Date.now()
  );
}
function getKeyScore(profile) {

  if (
    !isKeyAvailable(profile)
  ) {
    return -Infinity;
  }

  let score =
    100000;

  // Faster learned interval = better.
  score -=
    Number(
      profile.currentIntervalMs || 0
    ) * 10;

  // Rate limits reduce preference.
  score -=
    Number(
      profile.rateLimitHits || 0
    ) * 500;

  // Repeated empty responses reduce confidence,
  // but much less aggressively than a real rate limit.
  score -=
    Number(
      profile.emptyResponseStreak || 0
    ) * 250;

  // Total historical empty responses have a tiny effect.
  score -=
    Math.min(
      Number(
        profile.totalEmptyResponses || 0
      ),
      20
    ) * 10;

  // Consecutive successes increase confidence.
  score +=
    Math.min(
      Number(
        profile.consecutiveSuccesses || 0
      ),
      RATE_LEARNING.SUCCESS_THRESHOLD
    ) * 20;

  // Recently successful keys get a small preference.
  if (
    profile.lastUsedAt &&
    Date.now() -
      new Date(
        profile.lastUsedAt
      ).getTime()
      <
      5 * 60 * 1000
  ) {
    score +=
      100;
  }

  return score;
}

//====================================================
// SELECT BEST API KEY
// ============================================================

async function selectBestLLMKey({
  batch
}) {

  const keys =
    getConfiguredLLMKeys(batch);

  if (!keys.length) {

    const error =
      new Error(
        'No LLM API keys configured'
      );

    error.code =
      'NO_API_KEYS';

    throw error;
  }

  const candidates =
    [];

  for (
    const apiKey of keys
  ) {

    const profile =
      await getRateProfile({
        llmUrl:
          batch.llmUrl,

        model:
          batch.model,

        apiKey
      });

    profile.keyFingerprint =
      getKeyFingerprint(apiKey);

    candidates.push({
      apiKey,
      profile
    });
  }

  const available =
    candidates.filter(
      candidate =>
        isKeyAvailable(
          candidate.profile
        )
    );

  if (!available.length) {

    const earliestRecovery =
      candidates
        .map(
          candidate =>
            getKeyCooldownRemaining(
              candidate.profile
            )
        )
        .filter(Boolean)
        .sort(
          (a, b) => a - b
        )[0] || null;

    const error =
      new Error(
        'All configured LLM API keys are unavailable'
      );

    error.code =
      'ALL_KEYS_UNAVAILABLE';

    error.retryAfterMs =
      earliestRecovery;

    throw error;
  }

  available.sort(
    (a, b) =>
      getKeyScore(
        b.profile
      ) -
      getKeyScore(
        a.profile
      )
  );

  const selected =
    available[0];

  selected.profile.keyStatus =
    'active';

  selected.profile.lastUsedAt =
    now();

  return selected;
}

// ============================================================
// WAIT FOR LLM SLOT
// ============================================================
//
// This replaces the old fixed 600ms limiter.
//
// Every request:
//   1. Loads learned profile.
//   2. Waits according to current learned interval.
//   3. Records exact request timestamp.
//   4. Returns the profile for later success/failure learning.
// ============================================================

function waitForLLMSlot({
  batch
}) {

  const next =
    llmThrottle.then(
      async () => {

        const selected =
          await selectBestLLMKey({
            batch
          });

        const {
          apiKey,
          profile
        } =
          selected;

        const lastRequestTime =
          Number(
            profile.lastRequestAt || 0
          );

        const elapsed =
          Date.now() -
          lastRequestTime;

        const wait =
          Math.max(
            0,
            profile.currentIntervalMs -
            elapsed
          );

        if (wait > 0) {

          console.log(
            `[RATE LEARNER] Key ${profile.keyFingerprint} ` +
            `waiting ${wait}ms ` +
            `(interval ${profile.currentIntervalMs}ms)`
          );

          await sleep(wait);
        }

        const sentAt =
          Date.now();

        profile.lastRequestAt =
          sentAt;

        profile.lastUsedAt =
          now();

        profile.recentRequests.push(
          sentAt
        );

        pruneRateHistory(
          profile
        );

        console.log(
          `[RATE LEARNER] key=${profile.keyFingerprint} | ` +
          `interval=${profile.currentIntervalMs}ms | ` +
          `1m=${getRequestsInWindow(profile, 60 * 1000)} | ` +
          `30m=${profile.recentRequests.length}`
        );

        return {
          apiKey,
          profile
        };
      }
    );

  llmThrottle =
    next.catch(
      () => {}
    );

  return next;
}

// ============================================================
// COUNT REQUESTS IN WINDOW
// ============================================================

function getRequestsInWindow(
  profile,
  windowMs
) {

  const cutoff =
    Date.now() -
    windowMs;


  return profile.recentRequests.filter(
    timestamp =>
      Number(
        timestamp
      ) >= cutoff
  ).length;
}


// ============================================================
// RECORD SUCCESS
// ============================================================
//
// Learning strategy:
//
// Every success:
//   consecutiveSuccesses++
//
// Every 50 consecutive successes:
//   speed up by 3%
//
// Example:
//
// 1000ms -> 970ms -> 941ms -> 913ms
// ============================================================

async function recordLLMSuccess(
  profile
) {

  if (!profile) {
    return;
  }


  profile.consecutiveSuccesses +=
    1;

  profile.totalSuccesses +=
    1;

  profile.unsavedSuccesses +=
    1;

  // A successful LLM response breaks the consecutive
// empty-response streak.

profile.emptyResponseStreak =
  0;

  // ----------------------------------------------------------
  // DISCOVER FASTER SAFE ZONE
  // ----------------------------------------------------------

  if (
    profile.currentIntervalMs <
    profile.fastestKnownSafeMs
  ) {

    profile.fastestKnownSafeMs =
      profile.currentIntervalMs;
  }


  // ----------------------------------------------------------
  // CAUTIOUS SPEED INCREASE
  // ----------------------------------------------------------

  if (
    profile.consecutiveSuccesses >=
    RATE_LEARNING.SUCCESS_THRESHOLD
  ) {

    const previousInterval =
      profile.currentIntervalMs;


    const fasterInterval =
      clampInterval(
        previousInterval *
        RATE_LEARNING.SUCCESS_SPEEDUP_FACTOR
      );


    // Only change if it actually produces a new integer value.
    if (
      fasterInterval <
      previousInterval
    ) {

      profile.currentIntervalMs =
        fasterInterval;


      console.log(
        `[RATE LEARNER] ${RATE_LEARNING.SUCCESS_THRESHOLD} successes. ` +
        `Speeding up: ${previousInterval}ms -> ` +
        `${fasterInterval}ms`
      );
    }


    profile.consecutiveSuccesses =
      0;


    // Save immediately when the learned speed changes.
    await saveRateProfile(
      profile
    );

    return;
  }


  // ----------------------------------------------------------
  // PERIODIC PERSISTENCE
  // ----------------------------------------------------------

  if (
    profile.unsavedSuccesses >=
    RATE_LEARNING.SAVE_EVERY_SUCCESSES
  ) {

    await saveRateProfile(
      profile
    );
  }
}


// ============================================================
// RECORD RATE LIMIT
// ============================================================
//
// Learning strategy:
//
// Rate limit:
//   1. Record the interval that failed.
//   2. Reset consecutive successes.
//   3. Slow down aggressively.
//   4. Persist immediately.
//
// Example:
//
// 600ms -> rate limit
//
// New interval:
//
// 600 * 1.5 = 900ms
// ============================================================

async function recordLLMRateLimit(
  profile,
  error
) {

  if (!profile) {
    return;
  }


  const failedInterval =
    profile.currentIntervalMs;


  const newInterval =
    clampInterval(
      failedInterval *
      RATE_LEARNING.RATE_LIMIT_SLOWDOWN_FACTOR
    );


  profile.lastFailedIntervalMs =
    failedInterval;

  profile.currentIntervalMs =
    newInterval;

  profile.consecutiveSuccesses =
    0;

  profile.rateLimitHits +=
    1;

  profile.lastRateLimitAt =
    now();


  pruneRateHistory(
    profile
  );


  console.error(
    `[RATE LEARNER] RATE LIMIT DETECTED | ` +
    `failed=${failedInterval}ms | ` +
    `new=${newInterval}ms | ` +
    `1m=${getRequestsInWindow(profile, 60 * 1000)} | ` +
    `10m=${profile.recentRequests.length} | ` +
    `error=${errorText(error)}`
  );


  // Rate limits are critical learning events.
  // Persist immediately.
  await saveRateProfile(
    profile
  );
            }


// ============================================================
// RECORD KEY FAILURE
// ============================================================

async function recordKeyFailure(
  profile,
  error
) {

  if (!profile) {
    return;
  }

  const code =
    String(
      error?.code || ''
    ).toUpperCase();

  profile.lastErrorCode =
    code || 'UNKNOWN';

  profile.lastErrorAt =
    now();

  if (
    code === 'RATE_LIMIT'
  ) {

    await recordLLMRateLimit(
      profile,
      error
    );

    profile.keyStatus =
      'cooldown';

    profile.cooldownUntil =
      new Date(
        Date.now() +
        KEY_POOL.RATE_LIMIT_COOLDOWN_MS
      );

  } else if (
    code === 'QUOTA'
  ) {

    profile.quotaHits =
      (profile.quotaHits || 0) + 1;

    profile.keyStatus =
      'cooldown';

    profile.cooldownUntil =
      new Date(
        Date.now() +
        KEY_POOL.QUOTA_COOLDOWN_MS
      );

  } else if (
    code === 'INVALID_KEY'
  ) {

    profile.invalidKeyHits =
      (profile.invalidKeyHits || 0) + 1;

    profile.keyStatus =
      'disabled';

    profile.cooldownUntil =
      new Date(
        Date.now() +
        KEY_POOL.INVALID_KEY_COOLDOWN_MS
      );

  } else if (
    code === 'PROVIDER_ERROR'
  ) {

    profile.providerErrorHits =
      (profile.providerErrorHits || 0) + 1;

    profile.keyStatus =
      'cooldown';

    profile.cooldownUntil =
      new Date(
        Date.now() +
        KEY_POOL.PROVIDER_ERROR_COOLDOWN_MS
      );
  }

  await saveRateProfile(
    profile
  );

  console.warn(
    `[KEY POOL] ${profile.keyFingerprint} ` +
    `status=${profile.keyStatus} ` +
    `reason=${code} ` +
    `cooldown=${profile.cooldownUntil || 'none'}`
  );
}


// ============================================================
// FETCH CONTRACT SOURCE
// ============================================================


async function fetchContractSource({
  address,
  chainId,
  etherscanKey
}) {

  const apiKey = etherscanKey;

  if (!apiKey) {
    throw new Error(
      'No Etherscan API key configured'
    );
  }


  // ============================================================
  // HELPER: FETCH ONE ADDRESS FROM ETHERSCAN
  // ============================================================

  async function fetchOne(contractAddress) {

    const chain =
      encodeURIComponent(chainId || '1');

    const url =
      `https://api.etherscan.io/v2/api` +
      `?chainid=${chain}` +
      `&module=contract` +
      `&action=getsourcecode` +
      `&address=${encodeURIComponent(contractAddress)}` +
      `&apikey=${encodeURIComponent(apiKey)}`;

    const response = await fetch(url);

    const raw = await response.text();


    // ----------------------------------------------------------
    // RATE LIMIT
    // ----------------------------------------------------------

    if (response.status === 429) {

      const error = new Error(
        'Explorer API rate limit reached'
      );

      error.code = 'RATE_LIMIT';
      error.httpStatus = 429;

      throw error;
    }


    // ----------------------------------------------------------
    // HTTP ERROR
    // ----------------------------------------------------------

    if (!response.ok) {

      throw new Error(
        `Explorer returned HTTP ${response.status}: ` +
        raw.slice(0, 500)
      );
    }


    // ----------------------------------------------------------
    // PARSE RESPONSE
    // ----------------------------------------------------------

    let data;

    try {

      data = JSON.parse(raw);

    } catch {

      throw new Error(
        'Explorer returned invalid JSON'
      );
    }


    const result =
      Array.isArray(data.result)
        ? data.result[0]
        : null;


    // ----------------------------------------------------------
    // NOT VERIFIED
    // ----------------------------------------------------------

    if (
      !result ||
      !result.SourceCode ||
      !String(result.SourceCode).trim()
    ) {

      return {
        verified: false,

        reason:
          data.message ||
          'Contract source not verified'
      };
    }


    return {
      verified: true,

      address: contractAddress,

      source:
        result.SourceCode,

      contractName:
        result.ContractName ||
        'Unknown',

      compilerVersion:
        result.CompilerVersion ||
        null,

      isProxy:
        result.Proxy === '1',

      implementation:
        result.Implementation ||
        null
    };
  }


  // ============================================================
  // STEP 1: FETCH ORIGINAL ADDRESS
  // ============================================================

  const base =
    await fetchOne(address);


  // Normal unverified contract → skip
  if (!base.verified) {

    return base;
  }


  // ============================================================
  // STEP 2: CHECK IF IT IS A PROXY
  // ============================================================

  const implementationAddress =
    base.implementation;


  const isValidImplementation =
    base.isProxy &&
    implementationAddress &&
    /^0x[a-fA-F0-9]{40}$/.test(
      implementationAddress
    );


  // ------------------------------------------------------------
  // NORMAL CONTRACT
  // ------------------------------------------------------------

  if (!isValidImplementation) {

    return {
      verified: true,

      address,

      auditedAddress: address,

      source:
        base.source,

      contractName:
        base.contractName,

      compilerVersion:
        base.compilerVersion,

      isProxy: false,

      implementation: null
    };
  }


  // ============================================================
  // STEP 3: FETCH IMPLEMENTATION
  // ============================================================

  console.log(
    `[PROXY DETECTED] ${address}`
  );

  console.log(
    `[IMPLEMENTATION] ${implementationAddress}`
  );


  const implementation =
    await fetchOne(
      implementationAddress
    );


  // ============================================================
  // STEP 4: IMPLEMENTATION NOT VERIFIED → SKIP
  // ============================================================

  if (!implementation.verified) {

    console.log(
      `[PROXY SKIPPED] Implementation not verified: ` +
      `${implementationAddress}`
    );

    return {
      verified: false,

      isProxy: true,

      proxyAddress: address,

      implementation:
        implementationAddress,

      reason:
        'Proxy implementation source is not verified'
    };
  }


  // ============================================================
  // STEP 5: IMPLEMENTATION VERIFIED
  // SEND IMPLEMENTATION SOURCE TO LLM
  // ============================================================

  console.log(
    `[PROXY RESOLVED] ${address}`
  );

  console.log(
    `[AUDITING IMPLEMENTATION] ${implementationAddress}`
  );


  return {
    verified: true,

    // Original address submitted by user
    address,

    // Actual address whose code is audited
    auditedAddress:
      implementationAddress,

    // IMPORTANT:
    // THIS IS IMPLEMENTATION SOURCE
    source:
      implementation.source,

    contractName:
      implementation.contractName,

    compilerVersion:
      implementation.compilerVersion,

    isProxy: true,

    proxyAddress:
      address,

    implementation:
      implementationAddress
  };
  }

// ============================================================
// PROCESS ONE ITEM
// ============================================================

async function processBatchItem(
  batch,
  item
) {

  const db =
    await getDb();


  const items =
    db.collection(
      'batch_items'
    );


  const address =
    item.address;


  console.log(
    `[BATCH ${batch.batchId}] Processing #${item.index + 1}: ${address}`
  );


  // Mark running.
  await items.updateOne(
    {
      _id:
        item._id
    },
    {
      $set: {
        status:
          'running',

        startedAt:
          now(),

        error:
          null
      }
    }
  );


  // ==========================================================
  // FETCH SOURCE
  // ==========================================================

  let contract;


  try {

    contract =
      await fetchContractSource({
        address,

        chainId:
          batch.chainId,

        etherscanKey:
          batch.etherscanKey
      });

  } catch (error) {

    if (
      isPipelineStopError(
        error
      )
    ) {

      throw error;
    }


    await items.updateOne(
      {
        _id:
          item._id
      },
      {
        $set: {

          status:
            'failed',

          error:
            errorText(
              error
            ),

          finishedAt:
            now()
        }
      }
    );


    return {
      status:
        'failed'
    };
  }


  // ==========================================================
  // UNVERIFIED CONTRACT
  // ==========================================================

  if (
    !contract.verified
  ) {

    await items.updateOne(
      {
        _id:
          item._id
      },
      {
        $set: {

          status:
            'skipped',

          error:
            contract.reason ||
            'Contract source not verified',

          finishedAt:
            now()
        }
      }
    );


    return {
      status:
        'skipped'
    };
  }



  // ==========================================================
// MANUAL CONTRACT NAME SKIP LIST
// ==========================================================
//
// Contract source has already been fetched, so we now know
// the actual contract name.
//
// Check the persistent user-managed skip list BEFORE any
// LLM request.
//
// If a name matches:
//
// - No LLM slot is consumed
// - No API key is used
// - No retry occurs
// - No LLM compute is wasted
//
// Removing the name from the dashboard will allow future
// contracts with that name to be audited again.
// ==========================================================

const skipCheck =
  await shouldSkipContractName(
    contract.contractName
  );

if (
  skipCheck.skip
) {

  console.log(
    `[BATCH ${batch.batchId}] ` +
    `Skipping contract "${contract.contractName}" ` +
    `because it matches the manual skip list`
  );

  await items.updateOne(
    {
      _id:
        item._id
    },
    {
      $set: {

        status:
          'skipped',

        contractName:
          contract.contractName,

        compilerVersion:
          contract.compilerVersion,

        implementation:
          contract.implementation ||
          null,

        isProxy:
          contract.isProxy ||
          false,

        auditedAddress:
          contract.auditedAddress ||
          address,

        error:
          `Manual skip list match: ${contract.contractName}`,

        skipReason:
          'manual_contract_name_skip',

        skippedRule:
          skipCheck.rule?.contractName ||
          contract.contractName,

        finishedAt:
          now()
      }
    }
  );

  return {
    status:
      'skipped',

    reason:
      'manual_contract_name_skip'
  };
}


// ==========================================================
// COM DUAL-AUDITOR MODE
// ==========================================================
if (batch.mode === 'com' && batch.com?.enabled) {
  const runComAudit = async (side, additionalContext) => {
    const cfg = batch.com?.[side];
    const keys = getConfiguredKeysFrom(cfg);
    if (!cfg?.url || !cfg?.model || !keys.length) {
      const error = new Error(`COM ${side} is not fully configured`);
      error.code = 'COM_CONFIG_INVALID';
      throw error;
    }

    // COM requests intentionally run concurrently across auditors.
    // Key choice is independent, while normal rate learning remains untouched.
    let lastError;
    for (const apiKey of keys) {
            try {
        const audit = await runLLMAudit({
          source: contract.source,
          systemPrompt: batch.systemPrompt,
          model: cfg.model,
          contractName: contract.contractName,
          address,
          llmUrl: cfg.url,
          apiKey,
          additionalContext
        });
        return audit.result;
      } catch (error) {
        lastError = error;
        const code = String(error?.code || '').toUpperCase();
        if (!['RATE_LIMIT','QUOTA','INVALID_KEY','PROVIDER_ERROR','EMPTY_RESPONSE'].includes(code)) throw error;
      }
    }
    throw lastError || new Error(`COM ${side} failed`);
  };

  const outcome = await runComBatchItem({
    item,
    contract,
    runAudit: runComAudit,
    checkpoint: async com => {
      await items.updateOne({ _id: item._id }, { $set: {
        com,
        status: com.status === 'complete' ? 'completed' : 'running',
        contractName: contract.contractName,
        compilerVersion: contract.compilerVersion,
        implementation: contract.implementation || null,
        isProxy: contract.isProxy || false,
        auditedAddress: contract.auditedAddress || address,
        // Persist the audited source so Reaudit can reuse it later.
        source: contract.source,
        updatedAt: now(),
        ...(com.status === 'complete' ? { finishedAt: now() } : {})
      }});
    }
  });

  const updatedItem = await items.findOne({ _id: item._id });
  const reaudit = await ensureReauditRecord({
    batch,
    item: updatedItem || item
  });

  if (reaudit) {
    return {
      status: 'reaudit_pending',
      terminal: true
    };
  }

  return outcome;
}


// ==========================================================
// LLM AUDIT
// ==========================================================



// The adaptive rate profile used for this request.
//
// It is returned by waitForLLMSlot() and then used to teach
// the learner whether this request succeeded or hit a limit.


let audit;
let lastAuditError = null;
let attemptedKeys = new Set();

const maxKeyAttempts =
  Math.max(
    1,
    getConfiguredLLMKeys(batch).length
  );

for (
  let attempt = 1;
  attempt <= maxKeyAttempts;
  attempt++
) {

  let rateProfile = null;
  let selectedApiKey = null;

  try {

    const slot =
      await waitForLLMSlot({
        batch
      });

    rateProfile =
      slot.profile;

    selectedApiKey =
      slot.apiKey;

    // Prevent repeatedly selecting a key that
    // already failed during this same contract audit.
    if (
      attemptedKeys.has(
        rateProfile.keyFingerprint
      )
    ) {

      rateProfile.keyStatus =
        'cooldown';

      rateProfile.cooldownUntil =
        new Date(
          Date.now() + 1000
        );

      continue;
    }

    attemptedKeys.add(
      rateProfile.keyFingerprint
    );

    console.log(
      `[BATCH ${batch.batchId}] ` +
      `LLM key=${rateProfile.keyFingerprint} ` +
      `attempt ${attempt}/${maxKeyAttempts} ` +
      `interval=${rateProfile.currentIntervalMs}ms`
    );

    audit =
      await runLLMAudit({

        source:
          contract.source,

        systemPrompt:
          batch.systemPrompt,

        model:
          batch.model,

        contractName:
          contract.contractName,

        address,

        llmUrl:
          batch.llmUrl,

        apiKey:
          selectedApiKey
      });

    await recordLLMSuccess(
      rateProfile
    );

    rateProfile.keyStatus =
      'available';

    await saveRateProfile(
      rateProfile
    );

    break;

  } catch (error) {

    lastAuditError =
      error;

    const code =
      String(
        error?.code || ''
      ).toUpperCase();

    console.warn(
      `[KEY POOL] Request failed | ` +
      `code=${code} | ` +
      `key=${rateProfile?.keyFingerprint || 'unknown'}`
    );

    // ==========================================================
// EMPTY RESPONSE
// ==========================================================
//
// HTTP 200 but no usable completion.
//
// This must NEVER be treated as INVALID_KEY.
// ==========================================================

if (
  isEmptyAuditResponseError(
    error
  )
) {

  await recordEmptyResponse(
  db,
  rateProfile
);

console.warn(
    `[KEY POOL] EMPTY_RESPONSE | ` +
    `key=${rateProfile?.keyFingerprint || 'unknown'} | ` +
    `attempt=${attempt}/${maxKeyAttempts}`
  );

  // Try another API key if one is available.
  if (
    attempt < maxKeyAttempts
  ) {
    continue;
  }
  // Allow the existing item retry mechanism to retry.
  throw error;
}

    if (
      code === 'PROMPT_TOO_LARGE'
    ) {

      // This is a PERMANENT rejection tied to the prompt itself,
      // not the key. Rotating keys will produce the identical
      // failure every time — stop immediately instead of burning
      // through the whole key pool and pausing the batch over it.
      break;
    }

    if (
      [
        'RATE_LIMIT',
        'QUOTA',
        'INVALID_KEY',
        'PROVIDER_ERROR'
      ].includes(code)
    ) {

      await recordKeyFailure(
        rateProfile,
        error
      );

      // Try another key.
      continue;
    }

    if (
      isEmptyAuditResponseError(error) &&
      attempt < maxKeyAttempts
    ) {

      continue;
    }

    break;
  }
}


// ==========================================================
// ALL KEYS FAILED
// ==========================================================

if (!audit) {

  if (
    lastAuditError?.code ===
    'ALL_KEYS_UNAVAILABLE'
  ) {

    throw lastAuditError;
  }

  // A permanent, non-retryable rejection (e.g. the contract's
  // source is too large for this model/tier's prompt cap) should
  // fail only this item, not the whole batch. Let it fall through
  // to the normal "mark item failed, move on" handling below
  // instead of being relabeled as a key-pool exhaustion error.
  if (
    lastAuditError?.code !==
    'PROMPT_TOO_LARGE'
  ) {

    const allKeys =
      getConfiguredLLMKeys(batch);

    if (
      attemptedKeys.size >=
      allKeys.length
    ) {

      const error =
        new Error(
          'All LLM API keys failed or entered cooldown'
        );

      error.code =
        'ALL_KEYS_UNAVAILABLE';

      throw error;
    }
  }
}

    

// ==========================================================
// HANDLE FINAL AUDIT FAILURE
// ==========================================================

if (
  !audit
) {

  await items.updateOne(
    {
      _id:
        item._id
    },
    {
      $set: {

        status:
          'failed',

        error:
          errorText(
            lastAuditError ||
            'LLM audit failed'
          ),

        contractName:
          contract.contractName,

        compilerVersion:
          contract.compilerVersion,

        implementation:
          contract.implementation,

        finishedAt:
          now()
      }
    }
  );

  return {
    status:
      'failed'
  };
}
  // ==========================================================
  // SAVE SUCCESS
  // ==========================================================

  await items.updateOne(
    {
      _id:
        item._id
    },
    {
     $set: {
  status: 'completed',

  // Address user originally submitted
  address: address,

  // Actual contract address audited
  auditedAddress:
    contract.auditedAddress || address,

  contractName:
    contract.contractName,

  compilerVersion:
    contract.compilerVersion,

  // Proxy metadata
  isProxy:
    contract.isProxy || false,

  implementation:
    contract.implementation || null,

  // IMPORTANT:
  // This is implementation source for proxies
  source:
    contract.source,

  audit:
    audit.result,

  truncated:
    audit.truncated,

  finishedAt:
    now()
     }
    }
  );


  const updatedItem = await items.findOne({ _id: item._id });
  const reaudit = await ensureReauditRecord({
    batch,
    item: updatedItem || item
  });

  if (reaudit) {
    return {
      status: 'reaudit_pending',
      terminal: true
    };
  }

  return {
    status:
      'completed'
  };
}


// ============================================================
// BATCH WORKER
// ============================================================

async function startBatchWorker(
  batchId
) {

  if (
    activeWorkers.has(
      batchId
    )
  ) {

    console.log(
      `[BATCH ${batchId}] Worker already active`
    );

    return;
  }


  activeWorkers.add(
    batchId
  );


  console.log(
    `[BATCH ${batchId}] Worker started`
  );


  try {

    const db =
      await getDb();


    const batches =
      db.collection(
        'batches'
      );


    const items =
      db.collection(
        'batch_items'
      );


    // Do not overwrite a manually paused batch.
    const initialBatch =
      await batches.findOne({
        batchId
      });


    if (
      !initialBatch
    ) {

      return;
    }


    if (
      [
        'paused',
        'paused_rate_limit',
        'paused_quota',
        'cancelled',
        'completed'
      ].includes(
        initialBatch.status
      )
    ) {

      return;
    }


    await batches.updateOne(
      {
        batchId
      },
      {
        $set: {

          status:
            'running',

          updatedAt:
            now(),

          lastError:
            null
        }
      }
    );


    while (true) {

      // Always reload state.
      const batch =
        await batches.findOne({
          batchId
        });


      if (
        !batch
      ) {

        break;
      }


      // --------------------------------------------------------
      // STOP STATES
      // --------------------------------------------------------

      if (
        [
          'paused',
          'paused_rate_limit',
          'paused_quota',
          'cancelled'
        ].includes(
          batch.status
        )
      ) {

        console.log(
          `[BATCH ${batchId}] Worker stopped: ${batch.status}`
        );

        break;
      }


      // --------------------------------------------------------
      // REAUDIT PRIORITY SLOT
      // --------------------------------------------------------
      //
      // A completed Reaudit never interrupts an item already in
      // progress. It is atomically claimed here, at the worker
      // boundary, before the next untouched normal item.
      // --------------------------------------------------------

      const readyReaudit = await claimReadyReaudit(batchId);

      if (readyReaudit) {
        const applied = await applyClaimedReaudit(readyReaudit);

        if (applied.applied) {
          await batches.updateOne(
            { batchId },
            {
              $inc: { completed: 1 },
              $set: { updatedAt: now() }
            }
          );
        }

        await sleep(50);
        continue;
      }

      // --------------------------------------------------------
      // NEXT NORMAL ITEM
      // --------------------------------------------------------

      const item = await items.findOne(
        {
          batchId,
          status: {
            $in: ['pending', 'running']
          }
        },
        {
          sort: { index: 1 }
        }
      );

      if (!item) {
        // Do not finish a batch while a human Reaudit is still
        // waiting for input or an LLM result. The dashboard can
        // then be used while the batch remains alive.
        const waitingReaudit = await db.collection('reaudits').findOne({
          batchId,
          // 'ready' MUST be included: a Reaudit can flip running -> ready
          // between the claim check above and this check. Without it the
          // batch is marked completed and the worker exits, leaving the
          // item stuck on reaudit_pending.
          status: { $in: ['pending', 'running', 'ready', 'applying'] }
        });

        if (waitingReaudit) {
          await sleep(1000);
          continue;
        }

        await batches.updateOne(
          { batchId },
          {
            $set: {
              status: 'completed',
              completedAt: now(),
              updatedAt: now(),
              currentIndex: batch.total
            }
          }
        );

        console.log(
          `[BATCH ${batchId}] Batch completed`
        );

        break;
      }


      // --------------------------------------------------------
      // PROCESS
      // --------------------------------------------------------

      try {

        const outcome =
          await processBatchItem(
            batch,
            item
          );


        // A non-terminal COM outcome must never advance progress.
        if (outcome && outcome.terminal === false) {
          await sleep(250);
          continue;
        }

        const updates = {

          currentIndex:
            item.index + 1,

          updatedAt:
            now()
        };


        if (
          outcome.status ===
          'completed'
        ) {

          updates.completed =
            (batch.completed || 0) +
            1;
        }

        // reaudit_pending is intentionally not counted as done.
        // The priority application later increments completed.

        if (
          outcome.status ===
            'failed' ||
          outcome.status ===
            'skipped'
        ) {

          updates.failed =
            (batch.failed || 0) +
            1;
        }


        await batches.updateOne(
          {
            batchId
          },
          {
            $set:
              updates
          }
        );


      } catch (error) {

        // ------------------------------------------------------
        // RATE LIMIT / QUOTA
        // ------------------------------------------------------

        if (
          isPipelineStopError(
            error
          )
        ) {

          const pauseStatus =
            pipelineStopType(
              error
            );


          await items.updateOne(
            {
              _id:
                item._id
            },
            {
              $set: {

                status:
                  'pending',

                error:
                  errorText(
                    error
                  ),

                startedAt:
                  null
              }
            }
          );


          await batches.updateOne(
            {
              batchId
            },
            {
              $set: {

                status:
                  pauseStatus,

                lastError:
                  errorText(
                    error
                  ),

                pausedAt:
                  now(),

                updatedAt:
                  now()
              }
            }
          );


          console.error(
            `[BATCH ${batchId}] ${pauseStatus.toUpperCase()} - PIPELINE PAUSED`
          );


          break;
        }


        // ------------------------------------------------------
        // UNEXPECTED ERROR
        // ------------------------------------------------------

        await items.updateOne(
          {
            _id:
              item._id
          },
          {
            $set: {

              status:
                'failed',

              error:
                errorText(
                  error
                ),

              finishedAt:
                now()
            }
          }
        );


        await batches.updateOne(
          {
            batchId
          },
          {
            $inc: {
              failed:
                1
            },

            $set: {

              currentIndex:
                item.index + 1,

              updatedAt:
                now()
            }
          }
        );
      }


      // Small delay after each item.
      await sleep(
        ITEM_DELAY
      );
    }


  } catch (error) {

    console.error(
      `[BATCH ${batchId}] Worker crashed:`,
      error
    );


    try {

      const db =
        await getDb();


      await db
        .collection(
          'batches'
        )
        .updateOne(
          {
            batchId
          },
          {
            $set: {

              status:
                'interrupted',

              lastError:
                errorText(
                  error
                ),

              updatedAt:
                now()
            }
          }
        );

    } catch (
      dbError
    ) {

      console.error(
        `[BATCH ${batchId}] Could not save crash state:`,
        dbError
      );
    }


  } finally {

    activeWorkers.delete(
      batchId
    );


    console.log(
      `[BATCH ${batchId}] Worker released`
    );
  }
}


// ============================================================
// CREATE BATCH
// ============================================================

async function createBatch(
  req,
  res
) {

  try { 
    const {
      addresses,
      rawInput,
      chainId,
      systemPrompt,
      model,
      llmUrl,
      mode,
      com
    } = req.body || {};

    const cleanMode = mode === 'com' ? 'com' : 'normal';
    const cleanCom = com && typeof com === 'object' ? {
      enabled: cleanMode === 'com',
      llmA: {
        url: String(com.llmA?.url || '').trim(),
        model: String(com.llmA?.model || '').trim(),
        apiKeys: Array.isArray(com.llmA?.apiKeys)
          ? [...new Set(com.llmA.apiKeys.map(k => String(k || '').trim()).filter(Boolean))]
          : []
      },
      llmB: {
        url: String(com.llmB?.url || '').trim(),
        model: String(com.llmB?.model || '').trim(),
        apiKeys: Array.isArray(com.llmB?.apiKeys)
          ? [...new Set(com.llmB.apiKeys.map(k => String(k || '').trim()).filter(Boolean))]
          : []
      }
    } : null;

    // LLM credentials MUST come from the frontend settings for the
    // selected audit engine. There is intentionally no server-key fallback.
    const rawLLMKeys =
      req.headers['x-openai-keys'] ||
      req.headers['x-openai-key'] ||
      '';

    const llmKeys = String(rawLLMKeys)
      .split(',')
      .map(key => key.trim())
      .filter(Boolean);

    if (cleanMode === 'normal' && (!String(llmUrl || '').trim() || !String(model || '').trim() || !llmKeys.length)) {
      return res.status(400).json({
        error: 'Normal mode requires URL, model and at least one API key from Normal settings'
      });
    }

    if (cleanMode === 'com' && (
      !cleanCom ||
      !cleanCom.llmA.url || !cleanCom.llmA.model || !cleanCom.llmA.apiKeys.length ||
      !cleanCom.llmB.url || !cleanCom.llmB.model || !cleanCom.llmB.apiKeys.length
    )) {
      return res.status(400).json({
        error: 'COM mode requires URL, model and at least one API key for both LLM A and LLM B from COM settings'
      });
    }

    const etherscanKey = req.headers['x-etherscan-key'] || '';

    if (!etherscanKey) {
      return res.status(400).json({
        error: 'Etherscan API key is required from the frontend settings'
      });
    }

    if (!systemPrompt) {

      return res
        .status(400)
        .json({
          error:
            'systemPrompt is required'
        });
    }


    const parsedAddresses =
      parseAddresses(
        addresses ||
        rawInput
      );


    if (
      !parsedAddresses.length
    ) {

      return res
        .status(400)
        .json({
          error:
            'No valid contract addresses found'
        });
    }


    const batchId =
      crypto.randomUUID();


    const db =
      await getDb();


    const batches =
      db.collection(
        'batches'
      );


    const items =
      db.collection(
        'batch_items'
      );


    await batches.insertOne({

      batchId,

      status:
        'queued',

      chainId:
        String(
          chainId ||
          '1'
        ),

      total:
        parsedAddresses.length,

      currentIndex:
        0,

      completed:
        0,

      failed:
        0,

      mode:
        cleanMode,

      com:
        cleanCom || {
          enabled: false,
          llmA: { url: '', model: '', apiKeys: [] },
          llmB: { url: '', model: '', apiKeys: [] }
        },

      model:
        cleanMode === 'normal' ? String(model || '').trim() : '',

      systemPrompt,

      llmUrl:
        cleanMode === 'normal' ? String(llmUrl || '').trim() : '',

      // Retained for the current personal-tool architecture.
      // Do not use this storage approach for a public multi-user
      // production application.
     llmApiKeys:

       cleanMode === 'normal' ? llmKeys : [],

      etherscanKey:
        etherscanKey,

      createdAt:
        now(),

      updatedAt:
        now()
    });


    await items.insertMany(
      parsedAddresses.map(
        (
          address,
          index
        ) => ({

          batchId,

          index,

          address,

          status:
            'pending',

          contractName:
            null,

          compilerVersion:
            null,

          implementation:
            null,

          source:
            null,

          audit:
            null,

          truncated:
            false,

          auditStage:
            'pending',

          reauditUsed:
            false,

          reauditId:
            null,

          error:
            null,

          createdAt:
            now(),

          startedAt:
            null,

          finishedAt:
            null
        })
      )
    );


    console.log(
      `[BATCH ${batchId}] Created with ${parsedAddresses.length} addresses`
    );


    startBatchWorker(
      batchId
    ).catch(
      error => {
        console.error(
          `[BATCH ${batchId}] Background start error:`,
          error
        );
      }
    );


    return res
      .status(202)
      .json({

        batchId,

        status:
          'queued',

        total:
          parsedAddresses.length
      });


  } catch (error) {

    console.error(
      '[BATCH] Create error:',
      error
    );


    return res
      .status(500)
      .json({
        error:
          errorText(
            error
          )
      });
  }
}


// ============================================================
// GET BATCH
// ============================================================

async function getBatch(
  req,
  res
) {

  try {

    const db =
      await getDb();


    const batch =
      await db
        .collection(
          'batches'
        )
        .findOne(
          {
            batchId:
              req.params.batchId
          },
          {
            projection: {

              openaiKey:
                0,

              etherscanKey:
                0,

              systemPrompt:
                0
            }
          }
        );


    if (
      !batch
    ) {

      return res
        .status(404)
        .json({
          error:
            'Batch not found'
        });
    }


    const page =
      Math.max(
        0,
        Number(req.query.page) || 0
      );

    const pageSize = 500;

    const [items, totalItems] =
      await Promise.all([

        db
          .collection('batch_items')
          .find(
            {
              batchId:
                batch.batchId
            },
            {
              projection: {

                source:
                  0,

                audit:
                  0
              }
            }
          )
          .sort({
            index:
              1
          })
          .skip(page * pageSize)
          .limit(pageSize)
          .toArray(),

        db
          .collection('batch_items')
          .countDocuments({
            batchId:
              batch.batchId
          })

      ]);


    return res.json({

      ...batch,

      items,

      totalItems,

      page,

      pageSize,

      totalPages:
        Math.ceil(totalItems / pageSize) || 1
    });


  } catch (error) {

    return res
      .status(500)
      .json({
        error:
          errorText(
            error
          )
      });
  }
}


// ============================================================
// GET BATCH ITEMS
// ============================================================

async function getBatchItems(
  req,
  res
) {

  try {

    const db =
      await getDb();


    const limit =
      Math.min(
        Number(
          req.query.limit
        ) || 100,

        500
      );


    const skip =
      Math.max(
        Number(
          req.query.skip
        ) || 0,

        0
      );


    const items =
      await db
        .collection(
          'batch_items'
        )
        .find(
          {
            batchId:
              req.params.batchId
          },
          {
            projection: {

              source:
                0,

              audit:
                0
            }
          }
        )
        .sort({
          index:
            1
        })
        .skip(
          skip
        )
        .limit(
          limit
        )
        .toArray();


    return res.json({

      items,

      skip,

      limit
    });


  } catch (error) {

    return res
      .status(500)
      .json({
        error:
          errorText(
            error
          )
      });
  }
}


// ============================================================
// PAUSE
// ============================================================

async function pauseBatch(
  req,
  res
) {

  try {

    const db =
      await getDb();


    const result =
      await db
        .collection(
          'batches'
        )
        .updateOne(
          {
            batchId:
              req.params.batchId,

            status: {
              $in: [
                'queued',
                'running'
              ]
            }
          },
          {
            $set: {

              status:
                'paused',

              pausedAt:
                now(),

              updatedAt:
                now()
            }
          }
        );


    if (
      !result.matchedCount
    ) {

      return res
        .status(404)
        .json({
          error:
            'Batch is not currently running'
        });
    }


    return res.json({

      ok:
        true,

      status:
        'paused'
    });


  } catch (error) {

    return res
      .status(500)
      .json({
        error:
          errorText(
            error
          )
      });
  }
}


// ============================================================
// RESUME
// ============================================================

async function resumeBatch(
  req,
  res
) {

  try {

    const db =
      await getDb();


    const batches =
      db.collection(
        'batches'
      );


    const batch =
      await batches.findOne({
        batchId:
          req.params.batchId
      });


    if (
      !batch
    ) {

      return res
        .status(404)
        .json({
          error:
            'Batch not found'
        });
    }


    if (
      batch.status ===
      'completed'
    ) {

      return res
        .status(400)
        .json({
          error:
            'Batch is already completed'
        });
    }


    await batches.updateOne(
      {
        batchId:
          batch.batchId
      },
      {
        $set: {

          status:
            'queued',

          resumedAt:
            now(),

          updatedAt:
            now(),

          lastError:
            null
        }
      }
    );


    startBatchWorker(
      batch.batchId
    ).catch(
      console.error
    );


    return res.json({

      ok:
        true,

      status:
        'queued'
    });


  } catch (error) {

    return res
      .status(500)
      .json({
        error:
          errorText(
            error
          )
      });
  }
}


// ============================================================
// RESTART FROM BEGINNING
// ============================================================
//
// Keeps the same batch and same addresses.
// Deletes all previous results and resets every address.
// ============================================================

async function restartBatch(
  req,
  res
) {

  try {

    const db =
      await getDb();


    const batches =
      db.collection(
        'batches'
      );


    const items =
      db.collection(
        'batch_items'
      );


    const batch =
      await batches.findOne({
        batchId:
          req.params.batchId
      });


    if (
      !batch
    ) {

      return res
        .status(404)
        .json({
          error:
            'Batch not found'
        });
    }


    // Ask the current worker to stop at its next state check.
    await batches.updateOne(
      {
        batchId:
          batch.batchId
      },
      {
        $set: {

          status:
            'paused',

          updatedAt:
            now(),

          lastError:
            null
        }
      }
    );


    // Restart means a brand-new audit run, so the one-shot Reaudit
    // opportunity is reset as well.
    await db.collection('reaudits').deleteMany({ batchId: batch.batchId });

    // Reset every item.
    await items.updateMany(
      {
        batchId:
          batch.batchId
      },
      {
        $set: {

          status:
            'pending',

          contractName:
            null,

          compilerVersion:
            null,

          implementation:
            null,

          source:
            null,

          audit:
            null,

          truncated:
            false,

          auditStage:
            'pending',

          reauditUsed:
            false,

          reauditId:
            null,

          error:
            null,

          startedAt:
            null,

          finishedAt:
            null
        }
      }
    );


    await batches.updateOne(
      {
        batchId:
          batch.batchId
      },
      {
        $set: {

          status:
            'queued',

          currentIndex:
            0,

          completed:
            0,

          failed:
            0,

          restartedAt:
            now(),

          updatedAt:
            now(),

          lastError:
            null
        }
      }
    );


    startBatchWorker(
      batch.batchId
    ).catch(
      console.error
    );


    return res.json({

      ok:
        true,

      status:
        'queued',

      currentIndex:
        0
    });


  } catch (error) {

    return res
      .status(500)
      .json({
        error:
          errorText(
            error
          )
      });
  }
}


// ============================================================
// CLEAR BATCH
// ============================================================
//
// Permanently deletes the batch and all its items.
// ============================================================

async function clearBatch(
  req,
  res
) {

  try {

    const db =
      await getDb();


    const batches =
      db.collection(
        'batches'
      );


    const items =
      db.collection(
        'batch_items'
      );


    const batch =
      await batches.findOne({
        batchId:
          req.params.batchId
      });


    if (
      !batch
    ) {

      return res
        .status(404)
        .json({
          error:
            'Batch not found'
        });
    }


    // Change state first so a running worker notices it.
    await batches.updateOne(
      {
        batchId:
          batch.batchId
      },
      {
        $set: {

          status:
            'cancelled',

          updatedAt:
            now()
        }
      }
    );


    await items.deleteMany({
      batchId:
        batch.batchId
    });


    await db.collection('reaudits').deleteMany({ batchId: batch.batchId });

    await batches.deleteOne({
      batchId:
        batch.batchId
    });


    console.log(
      `[BATCH ${batch.batchId}] Batch cleared`
    );


    return res.json({

      ok:
        true,

      cleared:
        true
    });


  } catch (error) {

    return res
      .status(500)
      .json({
        error:
          errorText(
            error
          )
      });
  }
}


// ============================================================
// DOWNLOAD REPORT
// ============================================================

async function downloadReport(
  req,
  res
) {

  try {

    const db =
      await getDb();


    const item =
      await db
        .collection(
          'batch_items'
        )
        .findOne({
          batchId:
            req.params.batchId,

          address:
            req.params.address
        });


    if (
      !item
    ) {

      return res
        .status(404)
        .json({
          error:
            'Report not found'
        });
    }


    if (
      item.status !==
      'completed'
    ) {

      return res
        .status(400)
        .json({
          error:
            'Audit is not completed'
        });
    }

        let findingsSection;

    if (item.com) {

      const unwrapResult = raw => {
        if (typeof raw === 'string') return raw.trim() || null;
        if (raw && typeof raw === 'object' && typeof raw.result === 'string') {
          return raw.result.trim() || null;
        }
        return null;
      };

      const aResult = unwrapResult(item.com?.llmA?.final?.result);
      const bResult = unwrapResult(item.com?.llmB?.final?.result);

      if (!aResult && !bResult) {
        findingsSection =
          '# AUDIT FINDINGS\n\nNo completed COM audit results were found for this item.';
      } else {
        findingsSection =
`# AUDIT FINDINGS — AUDITOR A (final, cross-reviewed)

${aResult || '_Auditor A result unavailable._'}

---

# AUDIT FINDINGS — AUDITOR B (final, cross-reviewed)

${bResult || '_Auditor B result unavailable._'}`;
      }

    } else {
      findingsSection =
`# AUDIT FINDINGS

${item.audit || 'No audit content available.'}`;
    }

    const report = `# SMART CONTRACT SECURITY AUDIT REPORT

Generated: ${item.finishedAt || new Date().toISOString()}

## Contract Information

Address: ${item.address}

Contract Name: ${item.contractName || 'Unknown'}

Compiler: ${item.compilerVersion || 'Unknown'}

Implementation: ${item.implementation || 'N/A'}

---

${findingsSection}

---
    
---

## Disclaimer

This automated report is generated using AI-assisted analysis.
It should not be considered a replacement for a professional
manual smart contract security audit.
`;


    const safeAddress =
      item.address.replace(
        /[^a-zA-Z0-9]/g,
        '_'
      );


    res.setHeader(
      'Content-Type',
      'text/markdown; charset=utf-8'
    );


    res.setHeader(
      'Content-Disposition',
      `attachment; filename="audit-${safeAddress}.md"`
    );


    return res.send(
      report
    );


  } catch (error) {

    return res
      .status(500)
      .json({
        error:
          errorText(
            error
          )
      });
  }
}


// ============================================================
// AUTO RESUME AFTER RENDER RESTART
// ============================================================
//
// IMPORTANT:
//
// We intentionally do NOT auto-resume paused / rate-limited /
// quota-paused batches.
//
// If Render restarts while the batch was actively running,
// it resumes.
//
// If YOU paused it, it remains paused.
//
// If the provider rate-limited you, it remains paused until
// you explicitly press Resume.
// ============================================================

async function resumePendingBatches() {

  try {

    const db =
      await getDb();


    const batches =
      await db
        .collection(
          'batches'
        )
        .find({
          status: {
            $in: [
              'running',
              'queued',
              'interrupted'
            ]
          }
        })
        .toArray();


    console.log(
      `[BATCH] Found ${batches.length} resumable batch(es)`
    );


    for (
      const batch
      of batches
    ) {

      console.log(
        `[BATCH ${batch.batchId}] Resuming after server startup`
      );


      startBatchWorker(
        batch.batchId
      ).catch(
        console.error
      );
    }


  } catch (error) {

    console.error(
      '[BATCH] Auto-resume failed:',
      error
    );
  }
}


// ============================================================
// LLM RATE INTELLIGENCE RESET
// ============================================================
//
// Reset modes:
//
// soft:
//   Unlock keys and clear temporary failure state.
//
// learning:
//   Keep profiles but reset all learned rate intelligence.
//
// hard:
//   Delete all rate intelligence profiles.
//
// IMPORTANT:
//
// None of these delete API keys from batches.
// Your web/batch configuration remains untouched.
// ============================================================

async function resetLLMRateIntelligence(
  req,
  res
) {

  try {

    const mode =
      String(
        req.body?.mode ||
        'soft'
      )
        .trim()
        .toLowerCase();

    const db =
      await getDb();

    const collection =
      db.collection(
        'llm_rate_profiles'
      );


    // ========================================================
    // HARD RESET
    // ========================================================

    if (
      mode === 'hard'
    ) {

      const result =
        await collection.deleteMany(
          {}
        );

      console.log(
        `[LLM RESET] Hard reset deleted ` +
        `${result.deletedCount} rate profiles`
      );

      return res.json({
        ok: true,

        mode:
          'hard',

        deletedProfiles:
          result.deletedCount,

        message:
          'All LLM rate intelligence was deleted. API keys stored in batches were not deleted.'
      });
    }


    // ========================================================
    // LEARNING RESET
    // ========================================================

    if (
      mode === 'learning'
    ) {

      const timestamp =
        now();

      const result =
        await collection.updateMany(
          {},
          {
            $set: {

              // Rate learning.
              currentIntervalMs:
                RATE_LEARNING.DEFAULT_INTERVAL_MS,

              fastestKnownSafeMs:
                RATE_LEARNING.DEFAULT_INTERVAL_MS,

              lastFailedIntervalMs:
                null,

              consecutiveSuccesses:
                0,

              totalSuccesses:
                0,

              rateLimitHits:
                0,

              recentRequests:
                [],

              lastRequestAt:
                0,

              lastRateLimitAt:
                null,

              // Empty response learning.
              emptyResponseStreak:
                0,

              totalEmptyResponses:
                0,

              lastEmptyResponseAt:
                null,

              // Key health.
              keyStatus:
                'available',

              cooldownUntil:
                null,

              lastErrorCode:
                null,

              lastErrorAt:
                null,

              quotaHits:
                0,

              invalidKeyHits:
                0,

              providerErrorHits:
                0,

              updatedAt:
                timestamp
            }
          }
        );

      console.log(
        `[LLM RESET] Learning reset modified ` +
        `${result.modifiedCount} profile(s)`
      );

      return res.json({
        ok: true,

        mode:
          'learning',

        modifiedProfiles:
          result.modifiedCount,

        message:
          'LLM rate learning and key health state were reset. API keys were not deleted.'
      });
    }


    // ========================================================
    // SOFT RESET
    // ========================================================

    if (
      mode === 'soft'
    ) {

      const timestamp =
        now();

      const result =
        await collection.updateMany(
          {},
          {
            $set: {

              keyStatus:
                'available',

              cooldownUntil:
                null,

              lastErrorCode:
                null,

              lastErrorAt:
                null,

              consecutiveSuccesses:
                0,

              emptyResponseStreak:
                0,

              lastEmptyResponseAt:
                null,

              recentRequests:
                [],

              lastRequestAt:
                0,

              updatedAt:
                timestamp
            }
          }
        );

      console.log(
        `[LLM RESET] Soft reset modified ` +
        `${result.modifiedCount} profile(s)`
      );

      return res.json({
        ok: true,

        mode:
          'soft',

        modifiedProfiles:
          result.modifiedCount,

        message:
          'Temporary key lockouts, cooldowns, recent request history and empty-response streaks were cleared.'
      });
    }


    return res.status(400).json({
      ok: false,

      error:
        'Invalid reset mode. Use soft, learning, or hard.'
    });

  } catch (error) {

    console.error(
      '[LLM RESET] Failed:',
      error
    );

    return res.status(500).json({
      ok: false,

      error:
        errorText(error)
    });
  }
}

// ============================================================
// CLEAN UP STALE RATE PROFILES
// ============================================================
//
// Removes intelligence profiles whose key fingerprints no longer
// correspond to any key configured through the web/batches.
// ============================================================

async function cleanupStaleLLMProfiles(
  req,
  res
) {

  try {

    const db =
      await getDb();

    const configuredFingerprints =
      await getCurrentConfiguredKeyFingerprints(
        db
      );

    const collection =
      db.collection(
        'llm_rate_profiles'
      );

    const result =
      await collection.deleteMany(
        {
          keyFingerprint: {
            $nin:
              [
                ...configuredFingerprints
              ]
          }
        }
      );

    console.log(
      `[LLM CLEANUP] Removed ` +
      `${result.deletedCount} stale rate profile(s)`
    );

    return res.json({

      ok:
        true,

      deletedProfiles:
        result.deletedCount,

      message:
        'Stale LLM rate profiles removed.'
    });

  } catch (error) {

    console.error(
      '[LLM CLEANUP] Failed:',
      error
    );

    return res.status(500).json({

      ok:
        false,

      error:
        errorText(error)
    });
  }
}

// ============================================================
// LLM RATE INTELLIGENCE STATUS
// ============================================================

async function getLLMRateStatus(
  req,
  res
) {

  try {

    const db =
      await getDb();

    const collection =
      db.collection(
        'llm_rate_profiles'
      );

    // --------------------------------------------------------
    // Discover keys actually configured through the web/batches.
    // --------------------------------------------------------

    const configuredFingerprints =
      await getCurrentConfiguredKeyFingerprints(
        db
      );

    // --------------------------------------------------------
    // Load all profiles.
    // --------------------------------------------------------



    // Make sure every configured key has a rate profile.
// A fresh key must appear in the dashboard even before
// it has completed its first LLM request.

const configuredBatches =
  await db
    .collection('batches')
    .find({})
    .project({
      llmApiKeys: 1,
      llmUrl: 1,
      model: 1,
      mode: 1,
      com: 1
    })
    .sort({
      createdAt: -1
    })
    .toArray();

for (const batch of configuredBatches) {

  if (batch.mode === 'normal') {

    const keys =
      getConfiguredLLMKeys(batch);

    for (const apiKey of keys) {
      await getRateProfile({
        llmUrl: batch.llmUrl,
        model: batch.model,
        apiKey
      });
    }

  }

  if (batch.mode === 'com' && batch.com) {

    const llmAKeys =
      getConfiguredKeysFrom(
        batch.com.llmA
      );

    const llmBKeys =
      getConfiguredKeysFrom(
        batch.com.llmB
      );

    for (const apiKey of llmAKeys) {
      await getRateProfile({
        llmUrl: batch.com.llmA.url,
        model: batch.com.llmA.model,
        apiKey
      });
    }

    for (const apiKey of llmBKeys) {
      await getRateProfile({
        llmUrl: batch.com.llmB.url,
        model: batch.com.llmB.model,
        apiKey
      });
    }
  }
}


    
    const allProfiles =
      await collection
        .find({})
        .sort({
          updatedAt: -1
        })
        .toArray();

    // --------------------------------------------------------
    // Separate active configured profiles from historical/stale
    // profiles.
    // --------------------------------------------------------

    const activeProfiles =
      allProfiles.filter(
        profile =>
          configuredFingerprints.has(
            profile.keyFingerprint
          )
      );

    const staleProfiles =
      allProfiles.filter(
        profile =>
          !configuredFingerprints.has(
            profile.keyFingerprint
          )
      );

    // --------------------------------------------------------
    // Normalize active profiles.
    // --------------------------------------------------------

    const normalized =
      activeProfiles.map(
        raw => {

          const profile =
            normalizeRateProfile(
              raw,
              {
                profileId:
                  raw._id,

                llmUrl:
                  raw.llmUrl,

                model:
                  raw.model,

                apiKey:
                  ''
              }
            );

          const cooldownRemaining =
            getKeyCooldownRemaining(
              profile
            );

          const available =
            isKeyAvailable(
              profile
            );

          return {

            keyFingerprint:
              profile.keyFingerprint,

            status:
              available
                ? 'available'
                : (
                    profile.keyStatus ||
                    'cooldown'
                  ),

            cooldownRemaining,

            currentIntervalMs:
              profile.currentIntervalMs,

            fastestKnownSafeMs:
              profile.fastestKnownSafeMs,

            lastFailedIntervalMs:
              profile.lastFailedIntervalMs ||
              null,

            consecutiveSuccesses:
              profile.consecutiveSuccesses ||
              0,

            totalSuccesses:
              profile.totalSuccesses ||
              0,

            rateLimitHits:
              profile.rateLimitHits ||
              0,

            quotaHits:
              profile.quotaHits ||
              0,

            invalidKeyHits:
              profile.invalidKeyHits ||
              0,

            providerErrorHits:
              profile.providerErrorHits ||
              0,

            emptyResponseStreak:
              profile.emptyResponseStreak ||
              0,

            totalEmptyResponses:
              profile.totalEmptyResponses ||
              0,

            lastEmptyResponseAt:
              profile.lastEmptyResponseAt ||
              null,

            lastErrorCode:
              profile.lastErrorCode ||
              null,

            lastErrorAt:
              profile.lastErrorAt ||
              null,

            lastUsedAt:
              profile.lastUsedAt ||
              null,

            updatedAt:
              profile.updatedAt ||
              null
          };
        }
      );

    // --------------------------------------------------------
    // Count states.
    // --------------------------------------------------------

    const availableKeys =
      normalized.filter(
        key =>
          key.status ===
          'available'
      ).length;

    const cooldownKeys =
      normalized.filter(
        key =>
          key.status ===
          'cooldown'
      ).length;

    const disabledKeys =
      normalized.filter(
        key =>
          key.status ===
          'disabled'
      ).length;


    return res.json({

      ok:
        true,

      global: {

        totalKeys:
          configuredFingerprints.size,

        availableKeys,

        cooldownKeys,

        disabledKeys,

        staleProfiles:
          staleProfiles.length,

        queueActive:
          activeWorkers.size > 0
      },

      keys:
        normalized,

      staleProfiles:
        staleProfiles.map(
          profile => ({
            keyFingerprint:
              profile.keyFingerprint,

            keyStatus:
              profile.keyStatus ||
              'unknown',

            updatedAt:
              profile.updatedAt ||
              null
          })
        )
    });

  } catch (error) {

    console.error(
      '[LLM RATE STATUS] Failed:',
      error
    );

    return res.status(500).json({

      ok:
        false,

      error:
        errorText(error)
    });
  }
}

// ============================================================
// EXPRESS ROUTER
// ============================================================

const router =
  express.Router();


router.post(
  '/',
  createBatch
);

// ============================================================
// LLM RATE INTELLIGENCE ADMIN ROUTES
// ============================================================

router.get(
  '/llm-rate-status',
  getLLMRateStatus
);


router.post(
  '/llm-rate-reset',
  express.json(),
  resetLLMRateIntelligence
);


router.post(
  '/llm-rate-cleanup',
  cleanupStaleLLMProfiles
);


router.get(
  '/:batchId',
  getBatch
);


router.get(
  '/:batchId/items',
  getBatchItems
);


router.post(
  '/:batchId/pause',
  pauseBatch
);


router.post(
  '/:batchId/config',
  express.json(),
  updateBatchConfig
);


router.post(
  '/:batchId/resume',
  resumeBatch
);


router.post(
  '/:batchId/restart',
  restartBatch
);


router.delete(
  '/:batchId',
  clearBatch
);


router.get(
  '/:batchId/report/:address',
  downloadReport
);


// ============================================================
// EXPORTS
// ============================================================

function isWorkerActive(batchId) {
  return activeWorkers.has(batchId);
}

module.exports = {

  router,

  resumePendingBatches,

  isWorkerActive
};

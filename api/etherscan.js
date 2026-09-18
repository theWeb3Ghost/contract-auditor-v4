// GET /api/etherscan?address=0x...&chainId=1
// Looks up a contract's verified source via Etherscan's unified V2 API.
// If the contract is a proxy, resolves and returns the implementation's source instead.

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-etherscan-key');
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  const { address, chainId } = req.query;

  if (!address || !chainId) {
    return res.status(400).json({ error: 'address and chainId are required query params' });
  }
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
    return res.status(400).json({ error: `not a valid address: ${address}` });
  }

  const apiKey = req.headers['x-etherscan-key'] || process.env.ETHERSCAN_API_KEY;
  if (!apiKey) {
    return res.status(500).json({ error: 'No Etherscan API key provided (header x-etherscan-key or ETHERSCAN_API_KEY env var)' });
  }

  try {
    const base = await fetchSource(address, chainId, apiKey);
    if (!base) {
      return res.status(502).json({ error: 'Etherscan returned no result for this address' });
    }

    if (!base.SourceCode) {
      return res.json({ address, verified: false });
    }

    let finalSource = base.SourceCode;
    let finalName = base.ContractName;
    let implementation = null;

    const looksLikeProxy =
      base.Proxy === '1' && /^0x[a-fA-F0-9]{40}$/.test(base.Implementation || '');

    if (looksLikeProxy) {
      implementation = base.Implementation;
      const implData = await fetchSource(implementation, chainId, apiKey);
      if (implData && implData.SourceCode) {
        finalSource = implData.SourceCode;
        finalName = implData.ContractName || finalName;
      } else {
        return res.json({
          address,
          verified: true,
          isProxy: true,
          implementation,
          implementationVerified: false,
          contractName: base.ContractName,
          note: 'Proxy contract; implementation address found but its source is not verified.',
        });
      }
    }

    const flattened = flattenSource(finalSource);

    return res.json({
      address,
      verified: true,
      isProxy: looksLikeProxy,
      implementation,
      contractName: finalName || 'Unknown',
      source: flattened,
    });
  } catch (err) {
    return res.status(500).json({ error: String(err && err.message ? err.message : err) });
  }
}

async function fetchSource(address, chainId, apiKey) {
  const url = `https://api.etherscan.io/v2/api?chainid=${encodeURIComponent(
    chainId
  )}&module=contract&action=getsourcecode&address=${address}&apikey=${apiKey}`;
  const r = await fetch(url);
  const j = await r.json();
  if (j.status !== '1' || !Array.isArray(j.result) || !j.result[0]) return null;
  return j.result[0];
}

function flattenSource(raw) {
  let s = (raw || '').trim();
  try {
    if (s.startsWith('{{') && s.endsWith('}}')) {
      s = s.slice(1, -1);
    }
    if (s.startsWith('{')) {
      const parsed = JSON.parse(s);
      const sources = parsed.sources || parsed;
      let out = '';
      for (const [file, content] of Object.entries(sources)) {
        const code = (content && (content.content || content)) || '';
        out += `// ==== FILE: ${file} ====\n${code}\n\n`;
      }
      return out.trim() || raw;
    }
  } catch (e) {
    // Not valid JSON — treat as a raw single-file source instead.
  }
  return raw;
      }


module.exports.fetchSource = fetchSource;
module.exports.flattenSource = flattenSource;

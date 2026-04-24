const https = require('https');

// ─── Google Auth ────────────────────────────────────────────────────────────

function base64url(str) {
  return Buffer.from(str).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function getGoogleAccessToken() {
  const rawKey = process.env.GOOGLE_SERVICE_ACCOUNT_KEY;
  if (!rawKey) throw new Error('GOOGLE_SERVICE_ACCOUNT_KEY environment variable is not set');

  let key;
  try {
    key = JSON.parse(rawKey);
  } catch (e) {
    // Sometimes Netlify wraps the value in extra quotes — try stripping them
    try {
      key = JSON.parse(rawKey.trim().replace(/^"|"$/g, ''));
    } catch (e2) {
      throw new Error('Failed to parse GOOGLE_SERVICE_ACCOUNT_KEY — check that the full JSON was pasted correctly in Netlify env vars');
    }
  }

  if (!key.private_key || !key.client_email) {
    throw new Error('Service account key is missing private_key or client_email fields');
  }

  // Ensure private key newlines are correct (Netlify sometimes collapses \\n to literal \n)
  const privateKey = key.private_key.replace(/\\n/g, '\n');
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claim = base64url(JSON.stringify({
    iss: key.client_email,
    scope: 'https://www.googleapis.com/auth/drive.readonly',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now
  }));

  const { createSign } = require('crypto');
  const sign = createSign('RSA-SHA256');
  sign.update(`${header}.${claim}`);
  const sig = sign.sign(privateKey, 'base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  const jwt = `${header}.${claim}.${sig}`;

  return new Promise((resolve, reject) => {
    const body = `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`;
    const req = https.request({
      hostname: 'oauth2.googleapis.com',
      path: '/token',
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        const parsed = JSON.parse(data);
        if (parsed.access_token) resolve(parsed.access_token);
        else reject(new Error('Token error: ' + data));
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ─── Drive API helpers ───────────────────────────────────────────────────────

function driveRequest(path, token) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'www.googleapis.com',
      path,
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` }
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve(JSON.parse(data)));
    });
    req.on('error', reject);
    req.end();
  });
}

async function listFolder(folderId, token) {
  const q = encodeURIComponent(`'${folderId}' in parents and trashed = false`);
  const fields = encodeURIComponent('files(id,name,mimeType,size,createdTime,modifiedTime)');
  const result = await driveRequest(
    `/drive/v3/files?q=${q}&fields=${fields}&pageSize=50`,
    token
  );
  return result.files || [];
}

async function getSnippet(fileId, token) {
  const fields = encodeURIComponent('id,name,description');
  // Use export for Google Docs, otherwise get metadata with snippet
  const result = await driveRequest(
    `/drive/v3/files/${fileId}?fields=id,name,mimeType&supportsAllDrives=true`,
    token
  );
  return result;
}

// Read first ~3000 chars of a PDF via export
async function readFileSnippet(fileId, mimeType, token) {
  try {
    let path;
    if (mimeType === 'application/vnd.google-apps.document') {
      path = `/drive/v3/files/${fileId}/export?mimeType=text%2Fplain`;
    } else {
      // For PDFs, use the files.get with alt=media — but limit via range header
      path = `/drive/v3/files/${fileId}?alt=media&supportsAllDrives=true`;
    }

    return new Promise((resolve) => {
      const req = https.request({
        hostname: 'www.googleapis.com',
        path,
        method: 'GET',
        headers: {
          Authorization: `Bearer ${token}`,
          Range: 'bytes=0-4000' // first ~4KB only
        }
      }, res => {
        let data = '';
        res.on('data', c => { if (data.length < 3000) data += c; });
        res.on('end', () => resolve(data.replace(/[^\x20-\x7E\n\r\t]/g, ' ').substring(0, 1500)));
      });
      req.on('error', () => resolve(''));
      req.end();
    });
  } catch (e) {
    return '';
  }
}

// ─── RE Transactions 2026 folder ID ─────────────────────────────────────────
const RE_TRANSACTIONS_FOLDER = '1iuTI1fKo4IZps9hzXLPFoI3TUT3NaCKI';

// ─── Main handler ────────────────────────────────────────────────────────────

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  const body = JSON.parse(event.body || '{}');
  const {
    lastNameSearch,
    transactionType,    // BUYER or SELLER
    yearBuilt,
    hoaPresent,
    poolPresent,
    dualAgency,
    community55plus,
    submittedBy
  } = body;

  if (!lastNameSearch) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Last name is required' }) };
  }

  try {
    // ── 1. Get Google access token ──────────────────────────────────────────
    const token = await getGoogleAccessToken();

    // ── 2. Find transaction folder by last name ─────────────────────────────
    const q = encodeURIComponent(
      `'${RE_TRANSACTIONS_FOLDER}' in parents and name contains '${lastNameSearch}' and mimeType = 'application/vnd.google-apps.folder' and trashed = false`
    );
    const searchResult = await driveRequest(
      `/drive/v3/files?q=${q}&fields=files(id,name)&pageSize=10`,
      token
    );

    const folders = searchResult.files || [];
    if (folders.length === 0) {
      return {
        statusCode: 404,
        body: JSON.stringify({ error: `No transaction folder found containing "${lastNameSearch}"` })
      };
    }

    // Pick the most relevant folder — prefer the one matching transaction type
    const typeKeyword = transactionType === 'BUYER' ? 'Buyer' : 'Listing';
    const txFolder = folders.find(f => f.name.includes(typeKeyword)) || folders[0];

    // ── 3. Find 3. Active Transaction inside the parent folder ──────────────
    const parentContents = await listFolder(txFolder.id, token);
    const activeTransaction = parentContents.find(f =>
      f.name.includes('Active Transaction') && f.mimeType === 'application/vnd.google-apps.folder'
    );

    // ── 4. Find 4. Executed Docs ────────────────────────────────────────────
    let executedDocsId = null;
    if (activeTransaction) {
      const atContents = await listFolder(activeTransaction.id, token);
      const execDocs = atContents.find(f =>
        f.name.includes('Executed Docs') && f.mimeType === 'application/vnd.google-apps.folder'
      );
      if (execDocs) executedDocsId = execDocs.id;
    }

    if (!executedDocsId) {
      return {
        statusCode: 404,
        body: JSON.stringify({
          error: `Found folder "${txFolder.name}" but could not locate 4. Executed Docs. Has Offer Accepted been run for this transaction?`
        })
      };
    }

    // ── 5. Inventory E1–E5 ──────────────────────────────────────────────────
    const eSubfolders = await listFolder(executedDocsId, token);
    const inventory = {};

    for (const subfolder of eSubfolders) {
      if (subfolder.mimeType !== 'application/vnd.google-apps.folder') continue;
      const label = subfolder.name; // E1, E2, etc.
      const files = await listFolder(subfolder.id, token);

      // For each file, grab a snippet
      const fileData = [];
      for (const file of files) {
        const snippet = await readFileSnippet(file.id, file.mimeType, token);
        fileData.push({
          name: file.name,
          id: file.id,
          size: file.size || 0,
          snippet: snippet.substring(0, 1500)
        });
      }
      inventory[label] = fileData;
    }

    // ── 6. Also check parent folder for Pre-Audit Checklist ────────────────
    const checklistFile = parentContents.find(f =>
      f.name.includes('Pre-Audit') && f.mimeType === 'application/vnd.google-apps.document'
    );
    let checklistSnippet = '';
    if (checklistFile) {
      checklistSnippet = await readFileSnippet(checklistFile.id, checklistFile.mimeType, token);
    }

    // ── 7. Build dynamic required document list ─────────────────────────────
    const isPreX1978 = yearBuilt && parseInt(yearBuilt) < 1978;
    const conditions = {
      transactionType,
      yearBuilt,
      isPreX1978,
      hoaPresent: hoaPresent === 'yes',
      poolPresent: poolPresent === 'yes',
      dualAgency: dualAgency === 'yes',
      community55plus: community55plus === 'yes'
    };

    // ── 8. Send to Claude for analysis ─────────────────────────────────────
    const claudePrompt = buildClaudePrompt(txFolder.name, conditions, inventory, checklistSnippet, submittedBy);
    const auditReport = await callClaude(claudePrompt);

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      body: JSON.stringify({
        folderName: txFolder.name,
        folderId: txFolder.id,
        conditions,
        inventory: Object.fromEntries(
          Object.entries(inventory).map(([k, v]) => [k, v.map(f => f.name)])
        ),
        report: auditReport
      })
    };

  } catch (err) {
    console.error('Audit function error:', err.message, err.stack);
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      body: JSON.stringify({ error: err.message || 'Unknown error in audit function' })
    };
  }
};

// ─── Claude prompt builder ───────────────────────────────────────────────────

function buildClaudePrompt(folderName, conditions, inventory, checklistSnippet, submittedBy) {
  const { transactionType, isPreX1978, yearBuilt, hoaPresent, poolPresent, dualAgency, community55plus } = conditions;
  const isBuyer = transactionType === 'BUYER';

  const requiredE1 = [
    'Residential Purchase Agreement (RPA)',
    'Agency Disclosure (AD)',
    isBuyer ? 'Buyer Representation & Broker Compensation (BRBC)' : 'Listing Agreement (LA)',
    'Contingency Removal (CR-B or CR)',
    'Request for Repair (RR) — if repairs were requested',
    'Seller Response to RFR (RRRR) — if RFR was submitted',
    'Extension of Time (ETA) — if applicable',
  ];

  const requiredE2 = [
    'Transfer Disclosure Statement (TDS)',
    'Seller Property Questionnaire (SPQ)',
    'Agent Visual Inspection Disclosure (AVID) — Buyer\'s Agent',
    'Natural Hazard Disclosure (NHD)',
    'Statewide Buyer & Seller Advisory (SBSA)',
    'Buyer\'s Inspection Advisory (BIA)',
    isPreX1978 ? '⚠️ REQUIRED: Lead-Based Paint Disclosure (LPD) — pre-1978 property' : null,
    hoaPresent ? '⚠️ REQUIRED: HOA documents package' : null,
    dualAgency ? '⚠️ REQUIRED: Possible Representation of Both (PRBS)' : null,
  ].filter(Boolean);

  const requiredE3 = [
    'Pest Inspection Report',
    'Pest Section 1 Clearance Certificate — if Section 1 items were found',
    'Home Inspection Report',
    poolPresent ? '⚠️ REQUIRED: Pool/Spa Inspection Report' : null,
    'Roof Inspection Report — if roof was inspected',
    'All RFR documents',
  ].filter(Boolean);

  const requiredE4 = [
    'Preliminary Title Report',
    'Earnest Money Deposit (EMD) confirmation',
    'Commission Demand Letter',
    'Home Warranty Order',
    'Grant Deed (for reference)',
  ];

  const requiredE5 = hoaPresent ? [
    'HOA CC&Rs',
    'HOA Bylaws',
    'HOA Budget',
    'HOA Meeting Minutes',
    'Age Verification document — if 55+ community',
  ] : ['N/A — No HOA indicated for this property'];

  // Format inventory for Claude — keep snippets short to stay within token limits
  const inventoryText = Object.entries(inventory).map(([folder, files]) => {
    if (files.length === 0) return `${folder}: [EMPTY — no documents filed]`;
    return `${folder}:\n${files.map(f => `  • ${f.name} (${Math.round(f.size/1024)}KB)\n    SNIPPET: ${f.snippet.substring(0, 250)}`).join('\n')}`;
  }).join('\n\n');

  return `You are the SZREG AI Pre-Audit system. You are performing a transaction compliance audit for SZ Real Estate Group.

TRANSACTION: ${folderName}
TYPE: ${isBuyer ? 'Buyer Representation' : 'Seller Representation'}
YEAR BUILT: ${yearBuilt || 'Unknown'}
CONDITIONS: Pre-1978: ${isPreX1978 ? 'YES — Lead Paint disclosure required' : 'No'} | HOA: ${hoaPresent ? 'YES' : 'No'} | Pool: ${poolPresent ? 'YES' : 'No'} | Dual Agency: ${dualAgency ? 'YES' : 'No'} | 55+: ${community55plus ? 'YES' : 'No'}
SUBMITTED BY: ${submittedBy}

REQUIRED DOCUMENTS BY SECTION:

E1 — Contracts & Addendums:
${requiredE1.map(d => `- ${d}`).join('\n')}

E2 — Disclosures & Reports:
${requiredE2.map(d => `- ${d}`).join('\n')}

E3 — Inspections & RFR:
${requiredE3.map(d => `- ${d}`).join('\n')}

E4 — Title & Escrow:
${requiredE4.map(d => `- ${d}`).join('\n')}

E5 — HOA Docs:
${requiredE5.map(d => `- ${d}`).join('\n')}

ACTUAL DOCUMENTS IN FILE (from Google Drive E1–E5):

${inventoryText}

YOUR TASK:
Cross-reference the actual documents against the required list. For each finding, assign one of three ratings:

🔴 TRUE RISK — Required document is missing, or a document appears empty (0 bytes), or a required signature block shows blank/empty party lines with no name present. Requires action before COE.

🟡 MANAGEABLE ITEM — Document is present but may be misfiled, a duplicate exists, or the snippet suggests a potential issue that needs agent verification. Also flag any document where an Authentisign/DocuSign envelope is NOT detected (may be hand-signed — agent should verify).

✅ NON-ISSUE / CLEAR — Document confirmed present with correct party names visible in snippet.

SIGNATURE BLOCK GUIDANCE:
- If snippet shows "✘ [Name]" or "X [Name]" near signature lines → mark as appears executed
- If snippet shows "Buyer ___" or "Seller ___" with no name following → flag as possible empty signature block
- If Authentisign ID or DocuSign Envelope ID appears in snippet → note as electronically executed
- You are checking for PRESENCE of party names near signature blocks only — not authenticating signatures

OUTPUT FORMAT — respond in this exact JSON structure:
{
  "summary": "2-3 sentence overall assessment",
  "overallRisk": "HIGH | MEDIUM | LOW",
  "trueRisk": [
    { "item": "document name or issue", "detail": "specific finding and action required", "folder": "E1/E2/etc" }
  ],
  "manageable": [
    { "item": "document name or issue", "detail": "specific finding and recommended action", "folder": "E1/E2/etc" }
  ],
  "clear": [
    { "item": "document name", "detail": "confirmed present — brief note", "folder": "E1/E2/etc" }
  ],
  "disclaimer": "This report confirms document presence based on file names and content snippets from Google Drive. It does not verify signatures, initials, or document completeness on every page. Agent review of each document is required before COE."
}

Return ONLY the JSON object. No preamble, no markdown, no backticks.`;
}

// ─── Claude API call ─────────────────────────────────────────────────────────

function callClaude(prompt) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 4000,
      messages: [{ role: 'user', content: prompt }]
    });

    const req = https.request({
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      }
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          const text = parsed.content?.[0]?.text || '';
          console.log('Claude raw response (first 500):', text.substring(0, 500));
          // Strip any markdown code fences
          const clean = text.replace(/^```json\s*/i, '').replace(/^```\s*/i, '').replace(/```\s*$/i, '').trim();
          const result = JSON.parse(clean);
          // Ensure all required arrays exist
          result.trueRisk = result.trueRisk || [];
          result.manageable = result.manageable || [];
          result.clear = result.clear || [];
          result.summary = result.summary || 'Audit complete.';
          result.overallRisk = result.overallRisk || 'LOW';
          result.disclaimer = result.disclaimer || 'This report confirms document presence based on file names and content snippets from Google Drive. Agent review required before COE.';
          resolve(result);
        } catch (e) {
          // Return a structured error report rather than crashing
          resolve({
            summary: 'The AI analysis encountered a parsing error. Raw response captured for review.',
            overallRisk: 'MEDIUM',
            trueRisk: [],
            manageable: [{ item: 'AI Response Parse Error', detail: 'Claude returned a response that could not be parsed as JSON. Check function logs.', folder: 'System' }],
            clear: [],
            disclaimer: 'Audit incomplete — please re-run.'
          });
        }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

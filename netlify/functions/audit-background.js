/**
 * SZREG AI Compliance Audit — Netlify Background Function
 * File: netlify/functions/audit-background.js
 *
 * Architecture: Hybrid Compliance Read + Inventory
 *  - Filename + size classification determines READ vs INVENTORY for every file
 *  - Folder structure is irrelevant — AI decides per file
 *  - E1/E2/E4 contract & disclosure docs → full OpenAI GPT-4o read
 *  - Large reports, title, HOA → inventory confirm only
 *  - Fires Pabbly webhook with completed report when done
 */

const https = require('https');

// ─── Config ───────────────────────────────────────────────────────────────────
const PABBLY_WEBHOOK_URL = 'https://connect.pabbly.com/workflow/sendwebhookdata/IjU3NjcwNTZlMDYzNDA0MzU1MjY4NTUzNTUxMzQi_pc';
const RE_TRANSACTIONS_FOLDER = '1iuTI1fKo4IZps9hzXLPFoI3TUT3NaCKI';

// ─── File classification ──────────────────────────────────────────────────────
// Determines READ vs INVENTORY for every file, regardless of folder

const READ_PATTERNS = [
  // Contracts
  /rpa/i, /purchase.?agree/i, /contract/i, /executed.?contract/i,
  /brbc/i, /buyer.?rep/i, /broker.?comp/i,
  /listing.?agree/i,
  /agency/i,
  // Addendums & modifications
  /contingency.?remov/i, /buyer.?contingency/i,
  /extension/i, /\beta\b/i,
  /\brfr\b/i, /request.?repair/i, /request.?for.?repair/i, /rfr#/i,
  /\brrrr\b/i, /seller.?response/i, /repair.?response/i,
  /addendum/i, /counter.?offer/i,
  /verification.?of.?property/i, /property.?condition/i,
  // Disclosures
  /\btds\b/i, /transfer.?disclos/i,
  /\bspq\b/i, /seller.?property.?quest/i,
  /\bavid\b/i, /visual.?inspect.?disclos/i,
  /nhd.?signature/i, /nhd[-_]sig/i,
  /\bsbsa\b/i, /statewide.?buyer/i,
  /\bbia\b/i, /buyer.?inspect.?advis/i,
  /\blpd\b/i, /lead.?based.?paint/i, /lead.?paint/i,
  /\bprbs\b/i, /possible.?rep/i, /dual.?agency/i,
  /firpta/i, /earthquake/i, /\bwfda\b/i,
  /disclosure.?cover/i, /sacto.?disclos/i,
  // Title & Escrow (non-report)
  /commission.?demand/i, /szreg.?commission/i, /official.?commission/i,
  /\bemd\b/i, /earnest.?money/i, /deposit.?confirm/i,
  /warranty.?order/i, /home.?warranty/i,
  /closing.?instruct/i, /grant.?deed/i,
  // Pest clearance — small executed doc, must be read
  /pest.?clearance/i, /clearance.?cert/i, /section.?1.?clearance/i,
];

const INVENTORY_PATTERNS = [
  // Inspection reports — large scanned files, inventory only
  /inspection.?report/i, /inspect.?report/i,
  /home.?inspect/i, /property.?inspect/i,
  /pool.?inspect/i, /spa.?inspect/i,
  /roof.?inspect/i, /sewer.?inspect/i,
  /chimney/i, /hvac/i, /retrofit/i,
  // Pest REPORTS only (not clearance — clearance is in READ_PATTERNS)
  /pest.?report/i, /pest.?inspect/i,
  /termite.?report/i, /termite.?inspect/i,
  /wood.?destroy/i, /\bwdo\b/i,
  // Title reports — large files
  /prelim/i, /preliminary.?title/i, /title.?report/i, /title.?search/i,
  /\bptr\b/i,
  // HOA documents
  /cc.?r/i, /bylaw/i, /hoa.?budget/i, /hoa.?minutes/i, /hoa.?doc/i,
  /financ.?state/i, /reserve.?study/i,
  // NHD full report (large) — signature pages are small and readable
  /nhd.?full/i, /nhd.?report/i,
];


// Size thresholds
const SMALL_FILE_READ_THRESHOLD_KB = 400; // Unknown files under 400KB get read
const PER_FILE_CAP_KB = 6144;             // 6MB per file hard cap
const TOTAL_READ_CAP_KB = 51200;          // 50MB total read payload cap

function classifyFile(filename, sizeKB) {
  // Always inventory if matches report/large-doc pattern
  for (const pattern of INVENTORY_PATTERNS) {
    if (pattern.test(filename)) return 'INVENTORY';
  }
  // Always read if matches contract/disclosure pattern
  for (const pattern of READ_PATTERNS) {
    if (pattern.test(filename)) return 'READ';
  }
  // Small unknown file — read it, probably a contract
  if (sizeKB < SMALL_FILE_READ_THRESHOLD_KB) return 'READ';
  // Large unknown file — inventory only
  return 'INVENTORY';
}

// ─── Google Auth ──────────────────────────────────────────────────────────────

function base64url(str) {
  return Buffer.from(str).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function getGoogleAccessToken() {
  const rawKey = process.env.GOOGLE_SERVICE_ACCOUNT_KEY;
  if (!rawKey) throw new Error('GOOGLE_SERVICE_ACCOUNT_KEY not set');
  let key;
  try { key = JSON.parse(rawKey); }
  catch (e) {
    try { key = JSON.parse(rawKey.trim().replace(/^"|"$/g, '')); }
    catch (e2) { throw new Error('Failed to parse GOOGLE_SERVICE_ACCOUNT_KEY'); }
  }
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

// ─── Drive helpers ────────────────────────────────────────────────────────────

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
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { resolve({ error: 'JSON parse failed', raw: data.substring(0, 200) }); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function listFolderContents(folderId, token) {
  const q = encodeURIComponent(`'${folderId}' in parents and trashed = false`);
  const fields = encodeURIComponent('files(id,name,mimeType,size)');
  const result = await driveRequest(
    `/drive/v3/files?q=${q}&fields=${fields}&pageSize=100`,
    token
  );
  return result.files || [];
}

async function downloadFileAsBase64(fileId, token) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'www.googleapis.com',
      path: `/drive/v3/files/${fileId}?alt=media`,
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` }
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('base64')));
    });
    req.on('error', reject);
    req.end();
  });
}

// ─── HTTP POST helper ─────────────────────────────────────────────────────────

function postJSON(urlString, payload) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(payload);
    const url = new URL(urlString);
    const req = https.request({
      hostname: url.hostname,
      path: url.pathname + url.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body)
      }
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve(data));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ─── Main handler ─────────────────────────────────────────────────────────────

exports.handler = async (event) => {
  const body = JSON.parse(event.body || '{}');
  const {
    lastNameSearch, transactionType, yearBuilt,
    hoaPresent, poolPresent, dualAgency, community55plus,
    submittedBy, agentEmail, auditDate
  } = body;

  console.log(`[AUDIT] Starting compliance audit for: ${lastNameSearch}`);

  try {
    // ── 1. Authenticate ───────────────────────────────────────────────────────
    const token = await getGoogleAccessToken();
    console.log('[AUDIT] Google auth OK');

    // ── 2. Find transaction folder ────────────────────────────────────────────
    const typeKeyword = transactionType === 'BUYER' ? 'Buyer' : 'Listing';
    const q = encodeURIComponent(
      `'${RE_TRANSACTIONS_FOLDER}' in parents and name contains '${lastNameSearch}' and mimeType = 'application/vnd.google-apps.folder' and trashed = false`
    );
    const searchResult = await driveRequest(
      `/drive/v3/files?q=${q}&fields=files(id,name)&pageSize=10`, token
    );
    const folders = searchResult.files || [];
    if (!folders.length) {
      await postJSON(PABBLY_WEBHOOK_URL, { status: 'error', error: `No folder found for "${lastNameSearch}"`, submittedBy, agentEmail, auditDate });
      return { statusCode: 202 };
    }
    const txFolder = folders.find(f => f.name.includes(typeKeyword)) || folders[0];
    console.log(`[AUDIT] Folder: ${txFolder.name}`);

    // ── 3. Navigate to Executed Docs ──────────────────────────────────────────
    const parentContents = await listFolderContents(txFolder.id, token);
    const activeTransaction = parentContents.find(f =>
      f.name.includes('Active Transaction') && f.mimeType === 'application/vnd.google-apps.folder'
    );
    if (!activeTransaction) {
      await postJSON(PABBLY_WEBHOOK_URL, { status: 'error', error: `Active Transaction folder not found in ${txFolder.name}`, folderName: txFolder.name, submittedBy, agentEmail, auditDate });
      return { statusCode: 202 };
    }
    const atContents = await listFolderContents(activeTransaction.id, token);
    const execDocs = atContents.find(f =>
      f.name.includes('Executed Docs') && f.mimeType === 'application/vnd.google-apps.folder'
    );
    if (!execDocs) {
      await postJSON(PABBLY_WEBHOOK_URL, { status: 'error', error: `Executed Docs folder not found — has Offer Accepted been run?`, folderName: txFolder.name, submittedBy, agentEmail, auditDate });
      return { statusCode: 202 };
    }

    // ── 4. Inventory all files, classify each one ─────────────────────────────
    const eSubfolders = await listFolderContents(execDocs.id, token);
    const allFiles = []; // { folder, filename, fileId, sizeKB, classification }

    for (const subfolder of eSubfolders) {
      if (subfolder.mimeType !== 'application/vnd.google-apps.folder') continue;
      const files = await listFolderContents(subfolder.id, token);
      console.log(`[AUDIT] ${subfolder.name}: ${files.length} files`);
      for (const file of files) {
        if (file.mimeType === 'application/vnd.google-apps.folder') continue;
        const isPDF = file.mimeType === 'application/pdf' || file.name.toLowerCase().endsWith('.pdf');
        if (!isPDF) continue;
        const sizeKB = parseInt(file.size || 0) / 1024;
        const classification = classifyFile(file.name, sizeKB);
        allFiles.push({
          folder: subfolder.name,
          filename: file.name,
          fileId: file.id,
          sizeKB: Math.round(sizeKB),
          classification
        });
        console.log(`[AUDIT] ${classification}: ${file.name} (${Math.round(sizeKB)}KB)`);
      }
    }

    // ── 5. Download READ-classified files ─────────────────────────────────────
    let totalReadKB = 0;
    for (const file of allFiles) {
      if (file.classification !== 'READ') continue;
      if (file.sizeKB > PER_FILE_CAP_KB) {
        file.classification = 'INVENTORY';
        file.skipReason = `File is ${file.sizeKB}KB — exceeds ${PER_FILE_CAP_KB}KB per-file limit. Reclassified to inventory.`;
        continue;
      }
      if (totalReadKB + file.sizeKB > TOTAL_READ_CAP_KB) {
        file.classification = 'INVENTORY';
        file.skipReason = 'Total read payload cap reached. Reclassified to inventory.';
        continue;
      }
      try {
        file.base64 = await downloadFileAsBase64(file.fileId, token);
        totalReadKB += file.sizeKB;
        console.log(`[AUDIT] Downloaded: ${file.filename} (${file.sizeKB}KB) — running total: ${Math.round(totalReadKB)}KB`);
      } catch (err) {
        file.classification = 'INVENTORY';
        file.skipReason = `Download failed: ${err.message}`;
        console.error(`[AUDIT] Download failed: ${file.filename}`, err.message);
      }
    }

    const readFiles = allFiles.filter(f => f.classification === 'READ' && f.base64);
    const inventoryFiles = allFiles.filter(f => f.classification === 'INVENTORY');
    console.log(`[AUDIT] READ: ${readFiles.length} files (${Math.round(totalReadKB)}KB) | INVENTORY: ${inventoryFiles.length} files`);

    // ── 6. Build conditions object ────────────────────────────────────────────
    const conditions = {
      transactionType,
      yearBuilt,
      isPreX1978: yearBuilt && parseInt(yearBuilt) < 1978,
      hoaPresent: hoaPresent === 'yes',
      poolPresent: poolPresent === 'yes',
      dualAgency: dualAgency === 'yes',
      community55plus: community55plus === 'yes'
    };

    // ── 7. Call OpenAI with read files + inventory list ───────────────────────
    const auditReport = await callOpenAI(txFolder.name, conditions, readFiles, inventoryFiles, submittedBy);
    console.log('[AUDIT] OpenAI analysis complete');

    // ── 8. Build inventory summary ────────────────────────────────────────────
    const inventorySummary = [
      `READ & AUDITED (${readFiles.length} files):`,
      ...readFiles.map(f => `  ✅ [${f.folder}] ${f.filename} (${f.sizeKB}KB)`),
      '',
      `INVENTORY ONLY (${inventoryFiles.length} files):`,
      ...inventoryFiles.map(f => `  📋 [${f.folder}] ${f.filename} (${f.sizeKB}KB)${f.skipReason ? ' — ' + f.skipReason : ''}`)
    ].join('\n');

    // ── 9. Fire Pabbly ────────────────────────────────────────────────────────
    await postJSON(PABBLY_WEBHOOK_URL, {
      status: 'complete',
      folderName: txFolder.name,
      folderId: txFolder.id,
      submittedBy,
      agentEmail,
      auditDate,
      transactionType,
      conditions,
      inventorySummary,
      readCount: readFiles.length,
      inventoryCount: inventoryFiles.length,
      report: auditReport,
      reportFormatted: formatReport(txFolder.name, auditReport, submittedBy, auditDate, conditions, readFiles.length, inventoryFiles.length)
    });

    console.log('[AUDIT] Pabbly webhook fired — done');
    return { statusCode: 202 };

  } catch (err) {
    console.error('[AUDIT] Fatal error:', err.message);
    try {
      await postJSON(PABBLY_WEBHOOK_URL, {
        status: 'error',
        error: err.message,
        submittedBy, agentEmail, auditDate,
        folderName: lastNameSearch
      });
    } catch (e) { console.error('[AUDIT] Webhook error notify failed:', e.message); }
    return { statusCode: 202 };
  }
};

// ─── OpenAI Assistants API call ──────────────────────────────────────────────

async function callOpenAI(folderName, conditions, readFiles, inventoryFiles, submittedBy) {
  const apiKey = process.env.OPENAI_API_KEY;
  const MAX_ATTACHMENTS = 10; // OpenAI Assistants API limit per message

  // ── Step 1: Upload all PDFs to OpenAI Files API ──────────────────────
  const fileIds = [];
  for (const doc of readFiles) {
    try {
      const fileId = await uploadFileToOpenAI(doc, apiKey);
      fileIds.push({ fileId, doc });
      console.log(`[OPENAI] Uploaded: ${doc.filename} → ${fileId}`);
    } catch (err) {
      console.error(`[OPENAI] Upload failed for ${doc.filename}:`, err.message);
      inventoryFiles.push({ ...doc, skipReason: 'Upload failed: ' + err.message });
    }
  }
  console.log(`[OPENAI] ${fileIds.length} files uploaded`);

  // ── Step 2: Batch into chunks of 10 ──────────────────────────────────
  const batches = [];
  for (let i = 0; i < fileIds.length; i += MAX_ATTACHMENTS) {
    batches.push(fileIds.slice(i, i + MAX_ATTACHMENTS));
  }
  console.log(`[OPENAI] Processing ${batches.length} batch(es) of up to ${MAX_ATTACHMENTS} files each`);

  // ── Step 3: Create one Assistant (reused across batches) ─────────────
  const assistantId = await createAssistant(apiKey);
  console.log(`[OPENAI] Assistant: ${assistantId}`);

  // ── Step 4: Run each batch, collect results ───────────────────────────
  const batchResults = [];
  for (let b = 0; b < batches.length; b++) {
    const batch = batches[b];
    const batchLabel = `Batch ${b + 1} of ${batches.length}`;
    console.log(`[OPENAI] ${batchLabel}: ${batch.length} files`);

    const batchDocs = batch.map(f => f.doc);
    const batchPrompt = buildPrompt(folderName, conditions, submittedBy, batchDocs, b === 0 ? inventoryFiles : []);

    const threadId = await createThread(apiKey);
    const attachments = batch.map(({ fileId }) => ({
      file_id: fileId,
      tools: [{ type: 'file_search' }]
    }));

    await addMessageToThread(threadId, batchPrompt, attachments, apiKey);
    const runId = await runAssistant(assistantId, threadId, apiKey);
    const runResult = await pollForCompletion(threadId, runId, apiKey);

    if (runResult.status !== 'completed') {
      console.error(`[OPENAI] ${batchLabel} failed: ${runResult.status}`);
      batchResults.push(errorReport(`${batchLabel} did not complete: ${runResult.status}`));
      continue;
    }

    const responseText = await getThreadResponse(threadId, apiKey);
    console.log(`[OPENAI] ${batchLabel} response length: ${responseText.length}`);

    try {
      const clean = responseText
        .replace(/^```json\s*/i, '').replace(/^```\s*/i, '').replace(/```\s*$/i, '').trim();
      const jsonStart = clean.indexOf('{');
      const jsonEnd = clean.lastIndexOf('}');
      if (jsonStart === -1 || jsonEnd === -1) throw new Error('No JSON found');
      const result = JSON.parse(clean.substring(jsonStart, jsonEnd + 1));
      batchResults.push(result);
    } catch (e) {
      console.error(`[OPENAI] ${batchLabel} parse error:`, e.message);
      batchResults.push(errorReport('Parse error in ' + batchLabel + ': ' + e.message));
    }
  }

  // ── Step 5: Cleanup ───────────────────────────────────────────────────
  for (const { fileId } of fileIds) {
    try { await deleteFile(fileId, apiKey); } catch (e) { /* non-fatal */ }
  }
  try { await deleteAssistant(assistantId, apiKey); } catch (e) { /* non-fatal */ }

  // ── Step 6: Merge batch results ───────────────────────────────────────
  return mergeBatchResults(batchResults);
}

function mergeBatchResults(results) {
  if (!results.length) return errorReport('No batch results returned');
  if (results.length === 1) {
    const r = results[0];
    r.trueRisk               = r.trueRisk               || [];
    r.manageable             = r.manageable             || [];
    r.clear                  = r.clear                  || [];
    r.inventoryConfirmed     = r.inventoryConfirmed     || [];
    r.crossReferenceFindings = r.crossReferenceFindings || [];
    r.summary                = r.summary                || 'Audit complete.';
    r.overallRisk            = r.overallRisk            || 'LOW';
    r.disclaimer             = r.disclaimer             || 'Agent review required before COE.';
    return r;
  }

  const merged = {
    trueRisk: [],
    manageable: [],
    clear: [],
    inventoryConfirmed: [],
    crossReferenceFindings: [],
    summaries: [],
    disclaimer: 'This report reflects AI analysis of actual document content (read files) and filename confirmation (inventory files). It does not constitute legal review. Agent verification required before COE. SZ Real Estate Group.'
  };

  for (const r of results) {
    if (r.trueRisk)               merged.trueRisk.push(...r.trueRisk);
    if (r.manageable)             merged.manageable.push(...r.manageable);
    if (r.clear)                  merged.clear.push(...r.clear);
    if (r.inventoryConfirmed)     merged.inventoryConfirmed.push(...r.inventoryConfirmed);
    if (r.crossReferenceFindings) merged.crossReferenceFindings.push(...r.crossReferenceFindings);
    if (r.summary)                merged.summaries.push(r.summary);
  }

  // Overall risk — take highest across batches
  const riskOrder = { HIGH: 3, MEDIUM: 2, LOW: 1 };
  const highestRisk = results.reduce((max, r) => {
    return (riskOrder[r.overallRisk] || 0) > (riskOrder[max] || 0) ? r.overallRisk : max;
  }, 'LOW');

  merged.overallRisk = highestRisk;
  merged.summary = merged.summaries.join(' | ');

  // Deduplicate cross-reference findings by check description
  const seenChecks = new Set();
  merged.crossReferenceFindings = merged.crossReferenceFindings.filter(c => {
    const key = (c.check || '').toLowerCase().trim();
    if (seenChecks.has(key)) return false;
    seenChecks.add(key);
    return true;
  });

  // Deduplicate clear items by item name
  const seenClear = new Set();
  merged.clear = merged.clear.filter(c => {
    const key = (c.item || '').toLowerCase().trim();
    if (seenClear.has(key)) return false;
    seenClear.add(key);
    return true;
  });

  return merged;
}

// ─── OpenAI API helpers ───────────────────────────────────────────────────────

function uploadFileToOpenAI(doc, apiKey) {
  return new Promise((resolve, reject) => {
    const fileBuffer = Buffer.from(doc.base64, 'base64');
    const boundary = '----FormBoundary' + Math.random().toString(36).substring(2);
    const filename = doc.filename.replace(/[^a-zA-Z0-9._-]/g, '_');

    const bodyParts = [];
    bodyParts.push(Buffer.from(
      `--${boundary}
Content-Disposition: form-data; name="purpose"

assistants
`
    ));
    bodyParts.push(Buffer.from(
      `--${boundary}
Content-Disposition: form-data; name="file"; filename="${filename}"
Content-Type: application/pdf

`
    ));
    bodyParts.push(fileBuffer);
    bodyParts.push(Buffer.from(`
--${boundary}--
`));
    const body = Buffer.concat(bodyParts);

    const req = https.request({
      hostname: 'api.openai.com',
      path: '/v1/files',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        'Content-Length': body.length
      }
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try {
          const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (data.error) reject(new Error(data.error.message || JSON.stringify(data.error)));
          else resolve(data.id);
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function createAssistant(apiKey) {
  return openAIPost('/v1/assistants', {
    model: 'gpt-4o',
    name: 'SZREG Compliance Auditor',
    instructions: 'You are the SZREG AI Compliance Auditor for SZ Real Estate Group. You read actual transaction documents and perform rigorous compliance review. You never guess or infer — you only report what you can directly verify from document content. Always respond with valid JSON only. No preamble, no markdown, no explanation outside the JSON structure.',
    tools: [{ type: 'file_search' }]
  }, apiKey).then(data => {
    if (data.error) throw new Error(data.error.message || JSON.stringify(data.error));
    return data.id;
  });
}

function createThread(apiKey) {
  return openAIPost('/v1/threads', {}, apiKey).then(data => {
    if (data.error) throw new Error(data.error.message || JSON.stringify(data.error));
    return data.id;
  });
}

function addMessageToThread(threadId, prompt, attachments, apiKey) {
  return openAIPost(`/v1/threads/${threadId}/messages`, {
    role: 'user',
    content: prompt,
    attachments: attachments.length > 0 ? attachments : undefined
  }, apiKey).then(data => {
    if (data.error) throw new Error(data.error.message || JSON.stringify(data.error));
    return data.id;
  });
}

function runAssistant(assistantId, threadId, apiKey) {
  return openAIPost(`/v1/threads/${threadId}/runs`, {
    assistant_id: assistantId,
    max_completion_tokens: 8000
  }, apiKey).then(data => {
    if (data.error) throw new Error(data.error.message || JSON.stringify(data.error));
    return data.id;
  });
}

function pollForCompletion(threadId, runId, apiKey, maxWaitMs = 600000) {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    const poll = () => {
      openAIGet(`/v1/threads/${threadId}/runs/${runId}`, apiKey).then(data => {
        const status = data.status;
        console.log(`[OPENAI] Poll status: ${status}`);
        if (['completed', 'failed', 'cancelled', 'expired'].includes(status)) {
          resolve(data);
        } else if (Date.now() - startTime > maxWaitMs) {
          resolve({ status: 'timeout' });
        } else {
          setTimeout(poll, 3000); // poll every 3 seconds
        }
      }).catch(reject);
    };
    poll();
  });
}

function getThreadResponse(threadId, apiKey) {
  return openAIGet(`/v1/threads/${threadId}/messages`, apiKey).then(data => {
    if (data.error) throw new Error(data.error.message || JSON.stringify(data.error));
    // Get the first assistant message
    const assistantMsg = (data.data || []).find(m => m.role === 'assistant');
    if (!assistantMsg) throw new Error('No assistant message found in thread');
    // Extract text content
    const textBlock = (assistantMsg.content || []).find(c => c.type === 'text');
    if (!textBlock) throw new Error('No text content in assistant message');
    return textBlock.text.value || '';
  });
}

function deleteFile(fileId, apiKey) {
  return new Promise((resolve) => {
    const req = https.request({
      hostname: 'api.openai.com',
      path: `/v1/files/${fileId}`,
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${apiKey}` }
    }, res => { res.resume(); res.on('end', resolve); });
    req.on('error', resolve); // non-fatal
    req.end();
  });
}

function deleteAssistant(assistantId, apiKey) {
  return new Promise((resolve) => {
    const req = https.request({
      hostname: 'api.openai.com',
      path: `/v1/assistants/${assistantId}`,
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${apiKey}`, 'OpenAI-Beta': 'assistants=v2' }
    }, res => { res.resume(); res.on('end', resolve); });
    req.on('error', resolve); // non-fatal
    req.end();
  });
}

function openAIPost(path, payload, apiKey) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(payload);
    const req = https.request({
      hostname: 'api.openai.com',
      path,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
        'OpenAI-Beta': 'assistants=v2'
      }
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function openAIGet(path, apiKey) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'api.openai.com',
      path,
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'OpenAI-Beta': 'assistants=v2'
      }
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

function errorReport(detail) {
  return {
    summary: 'Audit encountered an error. See manageable items.',
    overallRisk: 'MEDIUM',
    trueRisk: [],
    manageable: [{ item: 'Audit Error', detail, folder: 'System', evidence: '' }],
    clear: [],
    inventoryConfirmed: [],
    crossReferenceFindings: [],
    disclaimer: 'Audit incomplete — please re-run or contact support.'
  };
}

// ─── Compliance prompt ────────────────────────────────────────────────────────

function buildPrompt(folderName, conditions, submittedBy, readFiles, inventoryFiles) {
  const { transactionType, yearBuilt, isPreX1978, hoaPresent, poolPresent, dualAgency, community55plus } = conditions;
  const isBuyer = transactionType === 'BUYER';

  const readList = readFiles.map(f => `  • [${f.folder}] ${f.filename} (${f.sizeKB}KB) — ATTACHED, READ THIS DOCUMENT`).join('\n');
  const inventoryList = inventoryFiles.map(f => `  • [${f.folder}] ${f.filename} (${f.sizeKB}KB) — NOT ATTACHED, confirm presence only`).join('\n');

  return `SZREG AI COMPLIANCE AUDIT
Transaction: ${folderName}
Submitted by: ${submittedBy}
Type: ${isBuyer ? 'Buyer Representation' : 'Seller Representation'}
Year Built: ${yearBuilt || 'Not provided'}
Conditions: Pre-1978=${isPreX1978 ? 'YES' : 'No'} | HOA=${hoaPresent ? 'YES' : 'No'} | Pool=${poolPresent ? 'YES' : 'No'} | Dual Agency=${dualAgency ? 'YES' : 'No'} | 55+=${community55plus ? 'YES' : 'No'}

═══════════════════════════════════════════════════════
HYBRID AUDIT — TWO MODES
═══════════════════════════════════════════════════════

MODE 1 — FULL COMPLIANCE READ (documents attached below):
${readList || '  (none)'}

For each attached document:
  • Read the actual content
  • Verify party names, dates, signatures, Authentisign/DocuSign IDs
  • Cross-reference commission %, party name consistency, property address
  • Report findings with specific evidence — never infer

MODE 2 — INVENTORY CONFIRM (not attached — filename only):
${inventoryList || '  (none)'}

For each inventory-only document:
  • Confirm it is present based on the filename listed
  • Note in inventoryConfirmed array — do NOT flag as missing
  • Do NOT attempt compliance analysis on these files

═══════════════════════════════════════════════════════
COMPLIANCE CHECKLIST — WHAT TO VERIFY IN READ DOCUMENTS
═══════════════════════════════════════════════════════

━━━ CONTRACTS (E1 or wherever filed) ━━━━━━━━━━━━━━━━━
• RPA — buyer/seller names, property address, purchase price, COE date, executed
• ${isBuyer ? 'BRBC' : 'Listing Agreement'} — client name matches RPA, commission terms, executed
• Agency Disclosure — present and executed by all parties
• Contingency Removal (CR) — contingencies listed, executed
• Request for Repair (RFR) — repair items, dollar amounts, executed
  CRITICAL: Note if pest clearance or pest work is included in any RFR
• Seller Response to RFR (RRRR) — matches RFR items, executed
• Extension of Time (ETA) — new dates, executed

━━━ DISCLOSURES (E2 or wherever filed) ━━━━━━━━━━━━━━━
• TDS — seller names match RPA, all sections complete, agent section complete, executed
• SPQ — seller names, executed
• AVID — agent name, property address, inspection items, executed
• NHD — property address matches, executed
• SBSA — executed
• BIA — executed
${isPreX1978 ? `• ⚠️ LPD REQUIRED (pre-1978) — seller acknowledgment, buyer acknowledgment, executed` : ''}
${dualAgency ? `• ⚠️ PRBS REQUIRED (dual agency) — executed by all parties` : ''}

━━━ TITLE & ESCROW (E4 or wherever filed) ━━━━━━━━━━━━━
• Commission Demand Letter — SZ Real Estate Group branded "Official Commission Demand Letter"
  May be filed as CD-[address], Commission Demand, or similar
  Verify: commission % matches RPA, broker John P. Klein / SZ Real Estate Group, Authentisign ID present
• EMD confirmation — amount matches RPA, deposit confirmed
• Home Warranty Order — present, property address visible

━━━ CROSS-REFERENCE CHECKS ━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Commission %: Demand Letter % matches RPA?
2. Party names: Consistent spelling across RPA, TDS, AVID, Commission Demand?
3. Property address: Consistent across all documents?
4. Pest clearance: Did any RFR include pest work? If yes, note clearance cert needed.
5. Repair amounts: RFR amounts consistent with RRRR response?

═══════════════════════════════════════════════════════
RATING DEFINITIONS
═══════════════════════════════════════════════════════
🔴 TRUE RISK — Document missing entirely, OR present but unexecuted, OR material cross-reference discrepancy. Action required before COE.
🟡 MANAGEABLE — Present but minor issue: blank date field, missing initials, agent should verify a specific detail.
✅ CLEAR — Confirmed present and properly executed. Cite evidence: party names, Authentisign ID, key data.
📋 INVENTORY CONFIRMED — Present by filename. Not read. No compliance determination made.

═══════════════════════════════════════════════════════
OUTPUT — RETURN ONLY THIS JSON, NO OTHER TEXT
═══════════════════════════════════════════════════════
{
  "summary": "3-4 sentence overall assessment. Specify what was read vs inventoried. Call out any material findings.",
  "overallRisk": "HIGH | MEDIUM | LOW",
  "trueRisk": [
    { "item": "name", "detail": "specific finding", "evidence": "exact text/ID cited from document", "folder": "E1/E2/E3/E4/E5" }
  ],
  "manageable": [
    { "item": "name", "detail": "finding and recommended action", "evidence": "what was found", "folder": "E1/E2/E3/E4/E5" }
  ],
  "clear": [
    { "item": "name", "detail": "confirmed present and executed", "evidence": "party names, Authentisign ID, key data verified", "folder": "E1/E2/E3/E4/E5" }
  ],
  "inventoryConfirmed": [
    { "item": "filename", "detail": "Present by filename — not read", "folder": "E1/E2/E3/E4/E5" }
  ],
  "crossReferenceFindings": [
    { "check": "check description", "result": "PASS | FAIL | UNABLE TO VERIFY", "detail": "specific finding" }
  ],
  "disclaimer": "This report reflects AI analysis of actual document content (read files) and filename confirmation (inventory files). It does not constitute legal review. Agent verification required before COE. SZ Real Estate Group."
}`;
}

// ─── Format report as plain text for email / Google Doc ───────────────────────

function formatReport(folderName, report, submittedBy, auditDate, conditions, readCount, inventoryCount) {
  const riskEmoji  = { HIGH: '🔴', MEDIUM: '🟡', LOW: '✅' };
  const riskLabel  = { HIGH: 'HIGH RISK — Action Required Before COE', MEDIUM: 'MEDIUM RISK — Review Items Below', LOW: 'LOW RISK — File Appears Complete' };
  const lines = [];

  lines.push('═══════════════════════════════════════════════════════');
  lines.push('SZREG AI COMPLIANCE AUDIT REPORT');
  lines.push('═══════════════════════════════════════════════════════');
  lines.push(`Transaction:  ${folderName}`);
  lines.push(`Audited by:   ${submittedBy}`);
  lines.push(`Date:         ${auditDate}`);
  lines.push(`Type:         ${conditions.transactionType}`);
  lines.push(`Documents:    ${readCount} fully read | ${inventoryCount} inventory confirmed`);
  lines.push('');
  lines.push(`${riskEmoji[report.overallRisk] || '🟡'} ${riskLabel[report.overallRisk] || report.overallRisk}`);
  lines.push('');
  lines.push('SUMMARY');
  lines.push('───────────────────────────────────────────────────────');
  lines.push(report.summary);
  lines.push('');

  if (report.trueRisk?.length) {
    lines.push('🔴 TRUE RISK — ACTION REQUIRED BEFORE COE');
    lines.push('───────────────────────────────────────────────────────');
    for (const i of report.trueRisk) {
      lines.push(`• ${i.item} [${i.folder}]`);
      lines.push(`  Finding:  ${i.detail}`);
      if (i.evidence) lines.push(`  Evidence: ${i.evidence}`);
      lines.push('');
    }
  }

  if (report.manageable?.length) {
    lines.push('🟡 MANAGEABLE — VERIFY BEFORE COE');
    lines.push('───────────────────────────────────────────────────────');
    for (const i of report.manageable) {
      lines.push(`• ${i.item} [${i.folder}]`);
      lines.push(`  Finding:  ${i.detail}`);
      if (i.evidence) lines.push(`  Evidence: ${i.evidence}`);
      lines.push('');
    }
  }

  if (report.clear?.length) {
    lines.push('✅ CLEAR — CONFIRMED PRESENT & EXECUTED');
    lines.push('───────────────────────────────────────────────────────');
    for (const i of report.clear) {
      lines.push(`• ${i.item} [${i.folder}]`);
      if (i.evidence) lines.push(`  Evidence: ${i.evidence}`);
      lines.push('');
    }
  }

  if (report.inventoryConfirmed?.length) {
    lines.push('📋 INVENTORY CONFIRMED — PRESENT (NOT READ)');
    lines.push('───────────────────────────────────────────────────────');
    for (const i of report.inventoryConfirmed) {
      lines.push(`• ${i.item} [${i.folder}]`);
    }
    lines.push('');
  }

  if (report.crossReferenceFindings?.length) {
    lines.push('🔍 CROSS-REFERENCE CHECKS');
    lines.push('───────────────────────────────────────────────────────');
    for (const c of report.crossReferenceFindings) {
      const icon = c.result === 'PASS' ? '✅' : c.result === 'FAIL' ? '🔴' : '🟡';
      lines.push(`${icon} ${c.check}: ${c.result}`);
      if (c.detail) lines.push(`   ${c.detail}`);
      lines.push('');
    }
  }

  lines.push('───────────────────────────────────────────────────────');
  lines.push(report.disclaimer || 'Agent review required before COE.');
  lines.push('═══════════════════════════════════════════════════════');
  lines.push('SZ Real Estate Group · DRE #02066500');
  lines.push('Samuel K. Zieour, Realtor · Co-Founder & Team Lead · DRE #01397303');

  return lines.join('\n');
}

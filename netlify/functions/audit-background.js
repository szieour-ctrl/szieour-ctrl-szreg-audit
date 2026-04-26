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

  console.log(`[AUDIT] Starting two-phase compliance audit for: ${lastNameSearch}`);

  try {
    const token = await getGoogleAccessToken();
    console.log('[AUDIT] Google auth OK');

    // Find transaction folder
    const typeKeyword = transactionType === 'BUYER' ? 'Buyer' : 'Listing';
    const q = encodeURIComponent(
      `'${RE_TRANSACTIONS_FOLDER}' in parents and name contains '${lastNameSearch}' and mimeType = 'application/vnd.google-apps.folder' and trashed = false`
    );
    const searchResult = await driveRequest(`/drive/v3/files?q=${q}&fields=files(id,name)&pageSize=10`, token);
    const folders = searchResult.files || [];
    if (!folders.length) {
      await postJSON(PABBLY_WEBHOOK_URL, { status: 'error', error: `No folder found for "${lastNameSearch}"`, submittedBy, agentEmail, auditDate });
      return { statusCode: 202 };
    }
    const txFolder = folders.find(f => f.name.includes(typeKeyword)) || folders[0];
    console.log(`[AUDIT] Folder: ${txFolder.name}`);

    // Navigate to Executed Docs
    const parentContents = await listFolderContents(txFolder.id, token);
    const activeTransaction = parentContents.find(f =>
      f.name.includes('Active Transaction') && f.mimeType === 'application/vnd.google-apps.folder'
    );
    if (!activeTransaction) {
      await postJSON(PABBLY_WEBHOOK_URL, { status: 'error', error: `Active Transaction folder not found`, folderName: txFolder.name, submittedBy, agentEmail, auditDate });
      return { statusCode: 202 };
    }
    const atContents = await listFolderContents(activeTransaction.id, token);
    const execDocs = atContents.find(f =>
      f.name.includes('Executed Docs') && f.mimeType === 'application/vnd.google-apps.folder'
    );
    if (!execDocs) {
      await postJSON(PABBLY_WEBHOOK_URL, { status: 'error', error: `Executed Docs folder not found`, folderName: txFolder.name, submittedBy, agentEmail, auditDate });
      return { statusCode: 202 };
    }

    // Inventory all subfolders and classify every file
    const eSubfolders = await listFolderContents(execDocs.id, token);
    const phase1Files = []; // E1 + E2 — Contracts & Disclosures
    const phase2Files = []; // E3 + E4 + E5 — Inspections, Title, HOA

    for (const subfolder of eSubfolders) {
      if (subfolder.mimeType !== 'application/vnd.google-apps.folder') continue;
      const files = await listFolderContents(subfolder.id, token);
      const fn = subfolder.name.toLowerCase();
      // Phase 1: E1 and E2 folders (contracts, disclosures, addendums, RFR)
      const isPhase1 = fn.includes('e1') || fn.includes('e2') ||
                       fn.includes('contract') || fn.includes('disclosure') ||
                       fn.includes('addendum') || fn.includes('rfr');
      console.log(`[AUDIT] ${subfolder.name} (${isPhase1 ? 'Phase 1' : 'Phase 2'}): ${files.length} files`);
      for (const file of files) {
        if (file.mimeType === 'application/vnd.google-apps.folder') continue;
        const isPDF = file.mimeType === 'application/pdf' || file.name.toLowerCase().endsWith('.pdf');
        if (!isPDF) continue;
        const sizeKB = parseInt(file.size || 0) / 1024;
        const fileObj = {
          folder: subfolder.name,
          filename: file.name,
          fileId: file.id,
          sizeKB: Math.round(sizeKB),
          classification: classifyFile(file.name, sizeKB)
        };
        console.log(`[AUDIT] ${fileObj.classification}: ${file.name} (${Math.round(sizeKB)}KB)`);
        if (isPhase1) phase1Files.push(fileObj);
        else phase2Files.push(fileObj);
      }
    }

    console.log(`[AUDIT] Phase 1 (E1+E2): ${phase1Files.length} files | Phase 2 (E3+E4+E5): ${phase2Files.length} files`);

    const conditions = {
      transactionType, yearBuilt,
      isPreX1978: yearBuilt && parseInt(yearBuilt) < 1978,
      hoaPresent: hoaPresent === 'yes',
      poolPresent: poolPresent === 'yes',
      dualAgency: dualAgency === 'yes',
      community55plus: community55plus === 'yes'
    };

    // Phase 1 — Contracts & Disclosures
    console.log('[AUDIT] === PHASE 1: Contracts & Disclosures ===');
    const { readFiles: p1Read, inventoryFiles: p1Inventory } = await downloadPhaseFiles(phase1Files, token);
    const phase1Report = await runPhaseAudit(txFolder.name, conditions, p1Read, p1Inventory, submittedBy, 1);
    console.log('[AUDIT] Phase 1 complete');

    // Pause between phases
    console.log('[AUDIT] Pausing 25s before Phase 2...');
    await new Promise(r => setTimeout(r, 25000));

    // Phase 2 — Inspections, Title & HOA
    console.log('[AUDIT] === PHASE 2: Inspections, Title & HOA ===');
    const { readFiles: p2Read, inventoryFiles: p2Inventory } = await downloadPhaseFiles(phase2Files, token);
    const phase2Report = await runPhaseAudit(txFolder.name, conditions, p2Read, p2Inventory, submittedBy, 2);
    console.log('[AUDIT] Phase 2 complete');

    // Merge both phase reports into one
    const allReadFiles      = [...p1Read, ...p2Read];
    const allInventoryFiles = [...p1Inventory, ...p2Inventory];
    const mergedReport = mergeBatchResults([phase1Report, phase2Report]);

    // Fire Pabbly with combined report
    await postJSON(PABBLY_WEBHOOK_URL, {
      status: 'complete',
      folderName: txFolder.name,
      folderId: txFolder.id,
      submittedBy, agentEmail, auditDate, transactionType, conditions,
      readCount: allReadFiles.length,
      inventoryCount: allInventoryFiles.length,
      report: mergedReport,
      reportFormatted: formatReport(txFolder.name, mergedReport, submittedBy, auditDate, conditions, allReadFiles.length, allInventoryFiles.length, allReadFiles, allInventoryFiles),
      reportHTML:      formatReportHTML(txFolder.name, mergedReport, submittedBy, auditDate, conditions, allReadFiles.length, allInventoryFiles.length, allReadFiles, allInventoryFiles)
    });

    console.log('[AUDIT] Pabbly webhook fired — done');
    return { statusCode: 202 };

  } catch (err) {
    console.error('[AUDIT] Fatal error:', err.message);
    try {
      await postJSON(PABBLY_WEBHOOK_URL, { status: 'error', error: err.message, submittedBy, agentEmail, auditDate, folderName: lastNameSearch });
    } catch (e) { console.error('[AUDIT] Webhook error notify failed:', e.message); }
    return { statusCode: 202 };
  }
};

// ─── Download files for a phase ───────────────────────────────────────────────

async function downloadPhaseFiles(phaseFiles, token) {
  const readFiles = [];
  const inventoryFiles = [];
  let totalReadKB = 0;

  for (const file of phaseFiles) {
    if (file.classification === 'INVENTORY') {
      inventoryFiles.push(file);
      continue;
    }
    if (file.sizeKB > PER_FILE_CAP_KB) {
      file.skipReason = `Exceeds ${PER_FILE_CAP_KB}KB per-file limit.`;
      inventoryFiles.push(file);
      continue;
    }
    if (totalReadKB + file.sizeKB > TOTAL_READ_CAP_KB) {
      file.skipReason = 'Total read cap reached.';
      inventoryFiles.push(file);
      continue;
    }
    try {
      file.base64 = await downloadFileAsBase64(file.fileId, token);
      totalReadKB += file.sizeKB;
      readFiles.push(file);
      console.log(`[AUDIT] Downloaded: ${file.filename} (${file.sizeKB}KB)`);
    } catch (err) {
      file.skipReason = `Download failed: ${err.message}`;
      inventoryFiles.push(file);
    }
  }

  console.log(`[AUDIT] Downloaded ${readFiles.length} files (${Math.round(totalReadKB)}KB) | ${inventoryFiles.length} inventory`);
  return { readFiles, inventoryFiles };
}

// ─── Run one phase audit — one vector store, one assistant, one run ───────────

async function runPhaseAudit(folderName, conditions, readFiles, inventoryFiles, submittedBy, phaseNumber) {
  const apiKey = process.env.OPENAI_API_KEY;
  const phaseLabel = phaseNumber === 1 ? 'Contracts & Disclosures' : 'Inspections, Title & HOA';

  if (readFiles.length === 0) {
    console.log(`[OPENAI] Phase ${phaseNumber}: no readable files`);
    return {
      summary: `Phase ${phaseNumber} (${phaseLabel}): ${inventoryFiles.length} documents confirmed present by filename.`,
      overallRisk: 'LOW', trueRisk: [], manageable: [], humanCheck: [], clear: [],
      inventoryConfirmed: inventoryFiles.map(f => ({ item: f.filename, detail: 'Present by filename — not read', folder: f.folder })),
      crossReferenceFindings: [],
      disclaimer: 'Agent review required before COE.'
    };
  }

  // Upload all files
  const fileIds = [];
  for (const doc of readFiles) {
    try {
      const fileId = await uploadFileToOpenAI(doc, apiKey);
      fileIds.push({ fileId, doc });
      console.log(`[OPENAI] P${phaseNumber} uploaded: ${doc.filename}`);
    } catch (err) {
      console.error(`[OPENAI] P${phaseNumber} upload failed: ${doc.filename}`, err.message);
      inventoryFiles.push({ ...doc, skipReason: 'Upload failed: ' + err.message });
    }
  }

  // Create one vector store for all files in this phase
  const allFileIds = fileIds.map(f => f.fileId);
  console.log(`[OPENAI] P${phaseNumber}: creating vector store (${allFileIds.length} files)`);
  const vectorStoreId = await createVectorStore(allFileIds, apiKey);
  console.log(`[OPENAI] P${phaseNumber} vector store ready: ${vectorStoreId}`);

  // Create assistant with vector store
  const assistantId = await createAssistantWithVectorStore(vectorStoreId, apiKey);
  console.log(`[OPENAI] P${phaseNumber} assistant: ${assistantId}`);

  // Build prompt and run
  const phaseDocs = fileIds.map(f => f.doc);
  const prompt = buildPrompt(folderName, conditions, submittedBy, phaseDocs, inventoryFiles, 0, 1);
  const threadId = await createThread(apiKey);
  await addMessageToThread(threadId, prompt, [], apiKey);
  const runId = await runAssistant(assistantId, threadId, apiKey);
  const runResult = await pollForCompletion(threadId, runId, apiKey);

  // Cleanup
  for (const { fileId } of fileIds) { try { await deleteFile(fileId, apiKey); } catch(e){} }
  try { await deleteAssistant(assistantId, apiKey); } catch(e) {}
  try { await deleteVectorStore(vectorStoreId, apiKey); } catch(e) {}

  if (runResult.status !== 'completed') {
    console.error(`[OPENAI] P${phaseNumber} failed: ${runResult.status}`);
    return errorReport(`Phase ${phaseNumber} (${phaseLabel}) did not complete: ${runResult.status}`);
  }

  const responseText = await getThreadResponse(threadId, apiKey);
  console.log(`[OPENAI] P${phaseNumber} response: ${responseText.length} chars`);

  try {
    const clean = responseText.replace(/^```json\s*/i,'').replace(/^```\s*/i,'').replace(/```\s*$/i,'').trim();
    const jsonStart = clean.indexOf('{');
    const jsonEnd   = clean.lastIndexOf('}');
    if (jsonStart === -1 || jsonEnd === -1) throw new Error('No JSON in response');
    const result = JSON.parse(clean.substring(jsonStart, jsonEnd + 1));
    result.trueRisk               = result.trueRisk               || [];
    result.manageable             = result.manageable             || [];
    result.humanCheck             = result.humanCheck             || [];
    result.clear                  = result.clear                  || [];
    result.inventoryConfirmed     = result.inventoryConfirmed     || [];
    result.crossReferenceFindings = result.crossReferenceFindings || [];
    result.summary     = result.summary     || '';
    result.overallRisk = result.overallRisk || 'LOW';
    return result;
  } catch (e) {
    console.error(`[OPENAI] P${phaseNumber} parse error:`, e.message);
    return errorReport(`Phase ${phaseNumber} parse error: ${e.message}`);
  }
}

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

async function createVectorStore(fileIds, apiKey) {
  // Create vector store
  const store = await openAIPost('/v1/vector_stores', {
    name: 'SZREG Audit Batch ' + Date.now()
  }, apiKey);
  if (store.error) throw new Error('Vector store create: ' + (store.error.message || JSON.stringify(store.error)));
  const storeId = store.id;

  // Add files to vector store
  for (const fileId of fileIds) {
    const res = await openAIPost(`/v1/vector_stores/${storeId}/files`, { file_id: fileId }, apiKey);
    if (res.error) console.error(`[OPENAI] Vector store file add error for ${fileId}:`, res.error.message);
  }

  // Poll until vector store is ready (files processed)
  let attempts = 0;
  while (attempts < 60) {
    await new Promise(r => setTimeout(r, 3000));
    const status = await openAIGet(`/v1/vector_stores/${storeId}`, apiKey);
    const completed = status.file_counts?.completed || 0;
    const total = status.file_counts?.total || fileIds.length;
    console.log(`[OPENAI] Vector store ${storeId}: ${status.status} (${completed}/${total} files)`);
    if (status.status === 'completed' || completed >= fileIds.length) break;
    if (status.status === 'expired' || status.status === 'failed') {
      throw new Error('Vector store failed: ' + status.status);
    }
    attempts++;
  }

  return storeId;
}

function createAssistantWithVectorStore(vectorStoreId, apiKey) {
  return openAIPost('/v1/assistants', {
    model: 'gpt-4o',
    name: 'SZREG Compliance Auditor',
    instructions: 'You are the SZREG AI Compliance Auditor for SZ Real Estate Group. You read actual transaction documents and perform rigorous compliance review. You never guess or infer — you only report what you can directly verify from document content. Always respond with valid JSON only. No preamble, no markdown, no explanation outside the JSON structure.',
    tools: [{ type: 'file_search' }],
    tool_resources: {
      file_search: { vector_store_ids: [vectorStoreId] }
    }
  }, apiKey).then(data => {
    if (data.error) throw new Error(data.error.message || JSON.stringify(data.error));
    return data.id;
  });
}

function deleteVectorStore(vectorStoreId, apiKey) {
  return new Promise((resolve) => {
    const req = https.request({
      hostname: 'api.openai.com',
      path: `/v1/vector_stores/${vectorStoreId}`,
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${apiKey}`, 'OpenAI-Beta': 'assistants=v2' }
    }, res => { res.resume(); res.on('end', resolve); });
    req.on('error', resolve);
    req.end();
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


// ─── Merge two phase reports into one ────────────────────────────────────────

function mergeBatchResults(results) {
  if (!results.length) return errorReport('No phase results returned');
  if (results.length === 1) {
    const r = results[0];
    r.trueRisk               = r.trueRisk               || [];
    r.manageable             = r.manageable             || [];
    r.humanCheck             = r.humanCheck             || [];
    r.clear                  = r.clear                  || [];
    r.inventoryConfirmed     = r.inventoryConfirmed     || [];
    r.crossReferenceFindings = r.crossReferenceFindings || [];
    r.summary     = r.summary     || 'Audit complete.';
    r.overallRisk = r.overallRisk || 'LOW';
    r.disclaimer  = r.disclaimer  || 'Agent review required before COE.';
    return r;
  }

  const merged = {
    trueRisk: [], manageable: [], humanCheck: [], clear: [],
    inventoryConfirmed: [], crossReferenceFindings: [],
    summaries: [],
    disclaimer: 'This report reflects AI analysis of actual document content (read files) and filename confirmation (inventory files). It does not constitute legal review. Agent verification required before COE. SZ Real Estate Group.'
  };

  for (const r of results) {
    if (r.trueRisk)               merged.trueRisk.push(...r.trueRisk);
    if (r.manageable)             merged.manageable.push(...r.manageable);
    if (r.humanCheck)             merged.humanCheck.push(...r.humanCheck);
    if (r.clear)                  merged.clear.push(...r.clear);
    if (r.inventoryConfirmed)     merged.inventoryConfirmed.push(...r.inventoryConfirmed);
    if (r.crossReferenceFindings) merged.crossReferenceFindings.push(...r.crossReferenceFindings);
    if (r.summary)                merged.summaries.push(r.summary);
  }

  // Overall risk — take highest
  const riskOrder = { HIGH: 3, MEDIUM: 2, LOW: 1 };
  merged.overallRisk = results.reduce((max, r) =>
    (riskOrder[r.overallRisk] || 0) > (riskOrder[max] || 0) ? r.overallRisk : max, 'LOW'
  );

  // Build clean summary
  const trueRiskItems = merged.trueRisk.length > 0 ? merged.trueRisk.map(r => r.item).join(', ') : 'none';
  const riskCounts = `${merged.trueRisk.length} True Risk, ${merged.manageable.length} Manageable, ${merged.humanCheck.length} Human Check, ${merged.clear.length} Clear`;
  merged.summary = `Compliance audit completed across ${results.length} phases (Contracts & Disclosures + Inspections, Title & HOA). Results: ${riskCounts}. ` +
    (merged.trueRisk.length > 0 ? `True Risk items requiring action: ${trueRiskItems}. ` : 'No True Risk items identified. ') +
    `All inventory-only documents confirmed present by filename. Agent verification required before COE.`;

  // Deduplicate cross-reference findings
  const seenChecks = new Set();
  merged.crossReferenceFindings = merged.crossReferenceFindings.filter(c => {
    const key = (c.check || '').toLowerCase().trim();
    if (seenChecks.has(key)) return false;
    seenChecks.add(key);
    return true;
  });

  // Deduplicate clear items
  const seenClear = new Set();
  merged.clear = merged.clear.filter(c => {
    const key = (c.item || '').toLowerCase().trim();
    if (seenClear.has(key)) return false;
    seenClear.add(key);
    return true;
  });

  return merged;
}

// ─── Compliance prompt ────────────────────────────────────────────────────────

function buildPrompt(folderName, conditions, submittedBy, readFiles, inventoryFiles, batchIndex = 0, totalBatches = 1) {
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

CRITICAL SCOPE RULE: You may ONLY report findings on the documents listed in this batch.
Do NOT reference documents not in this batch. If a cross-reference requires a document
not in this batch, mark it UNABLE TO VERIFY.

IMPORTANT — HOW TO READ THESE DOCUMENTS:
These documents are attached via file_search which gives you full access to all text,
including text extracted from scanned pages via OCR. Use the file_search tool to read
each document fully before reporting. Do not report "unable to read" unless the file
is genuinely blank after searching. For each document, explicitly call file_search
to retrieve its content before making any compliance determination.

CRITICAL FILING RULE — STANDALONE FILES SATISFY REQUIREMENTS:
Many disclosure documents are filed as standalone PDFs rather than embedded in the RPA or contract.
A standalone file satisfies its compliance requirement. Specific examples:
  • A standalone LPD.pdf satisfies the Lead-Based Paint Disclosure requirement
  • A standalone TDS.pdf satisfies the Transfer Disclosure Statement requirement
  • A standalone SPQ.pdf satisfies the Seller Property Questionnaire requirement
  • A standalone AVID.pdf satisfies the Agent Visual Inspection Disclosure requirement
  • A standalone NHD file satisfies the Natural Hazard Disclosure requirement
Do NOT flag a disclosure as missing if a standalone file for that disclosure exists in this batch.

For each attached document:
  • Use file_search to retrieve the full document content
  • Verify party names, dates, signatures, Authentisign/DocuSign IDs
  • Report findings with specific evidence — exact text, IDs, names found
  • If a document appears blank after searching, flag as Manageable (not True Risk)
  • Only cite evidence from files in this batch

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
${isPreX1978 ? `• ⚠️ LPD REQUIRED (pre-1978 property)
  IMPORTANT: LPD may be filed as a STANDALONE FILE (e.g. 40th 3306 - LPD.pdf) OR embedded in the RPA.
  If a standalone LPD file is present in the attached documents, that SATISFIES the LPD requirement.
  Do NOT flag LPD as missing if a standalone LPD file was read in this batch.
  Verify: seller acknowledgment present, buyer acknowledgment present, executed by all parties.` : ''}
${dualAgency ? `• ⚠️ PRBS REQUIRED (dual agency) — executed by all parties` : ''}

━━━ TITLE & ESCROW (E4 or wherever filed) ━━━━━━━━━━━━━
• Commission Demand Letter — SZ Real Estate Group branded "Official Commission Demand Letter"
  May be filed as CD-[address], Commission Demand, or similar
  Verify: commission % matches RPA, broker John P. Klein / SZ Real Estate Group, Authentisign ID present
• EMD confirmation — amount matches RPA, deposit confirmed
• Home Warranty Order — present, property address visible

━━━ CROSS-REFERENCE CHECKS ━━━━━━━━━━━━━━━━━━━━━━━━━━━
IMPORTANT: Only perform cross-reference checks on documents YOU HAVE ATTACHED IN THIS BATCH.
If a required document for a check is not in this batch, mark result as UNABLE TO VERIFY — do not guess.

1. Commission %: Does Commission Demand % match the RPA purchase agreement?
2. Party names: Consistent spelling across attached documents only?
3. Property address: Consistent across attached documents only?
4. Pest clearance: Did any attached RFR include pest work? Is clearance cert present?
5. Repair amounts: Do RFR amounts match RRRR response in attached documents?

═══════════════════════════════════════════════════════
RATING DEFINITIONS
═══════════════════════════════════════════════════════
🔴 TRUE RISK — Document completely missing from folder, OR no Authentisign/DocuSign ID AND no signatures visible. Agent action required before COE.

🟡 MANAGEABLE — Document present but substantive issue: unrecognized form, conflicting party names, date discrepancy, or content cannot be verified. Agent must review before COE.

🔵 HUMAN CHECK — Authentisign ID confirmed (execution proven), BUT a specific page has a blank or incomplete signature/initial block. LOW risk. Agent visually verifies that page before COE. Use this whenever Authentisign ID is present but a page-level issue exists.

✅ CLEAR — Authentisign ID confirmed — execution indicators present. No page-level issues detected.

📋 INVENTORY CONFIRMED — Present by filename. Not read. No compliance determination made.

═══════════════════════════════════════════════════════
OUTPUT — RETURN ONLY THIS JSON, NO OTHER TEXT
═══════════════════════════════════════════════════════

MANDATORY RULE: Every single attached document in this batch MUST appear in exactly one of:
trueRisk, manageable, humanCheck, OR clear. No attached document may be omitted.
Do not group multiple documents under one item — each document gets its own entry.

EXECUTION VERIFICATION RULE — follow this decision tree for every document:
1. Search for ANY execution indicator in the document:
   - Authentisign ID (UUID format after "Authentisign ID:")
   - DocuSign Envelope ID (UUID format after "Envelope ID:" or "DocuSign Envelope ID:")
   - Any "/ds/" link or docusign.net reference
   - zipForm or DotLoop signature certificate
   - Wet signature with typed name and date
   - Any "Signed by [name]" with timestamp
   → If ANY indicator found: document execution is confirmed. Proceed to step 2.
   → If NO indicator found after thorough search: flag as MANAGEABLE — requires manual verification
   → Never flag as TRUE RISK solely because execution cannot be verified

2. With Authentisign ID confirmed — search every page for blank signature or initial blocks:
   → If all signature/initial blocks appear completed: add to CLEAR
      Evidence must include: Authentisign ID, party names found, any key dates
   → If any page shows a blank or incomplete signature/initial block: add to HUMAN CHECK
      Evidence must include: Authentisign ID confirmed, which page, what appears incomplete
      Risk = LOW — Authentisign ID proves execution intent

3. Document completely absent from the folder: TRUE RISK only

SIGNATURE PLATFORM RECOGNITION:
Real estate transactions use multiple signature platforms. Recognize ALL of these as valid execution confirmation:
  - Authentisign: look for "Authentisign ID:" followed by a UUID (e.g. 73C06091-DE39-F111-8EF2-000D3A55CAFE)
  - DocuSign: look for "DocuSign Envelope ID:" or "Envelope ID:" followed by a UUID
  - DocuSign: look for "/ds/" or "docusign.net" in any embedded link or reference
  - DocuSign: look for "Signed by [name]" with a DocuSign certificate reference
  - zipForm / DotLoop: look for "Signed" with a timestamp and party name
  - Wet signature: look for a signature image with a typed name and date below it
  - Any digital certificate or envelope ID from any platform counts as execution confirmation

If ANY of these indicators are present, the document is CONFIRMED EXECUTED.
Only flag as unverifiable if the document is completely blank or has NO signature indicators of any kind.

PAGE-LEVEL SEARCH INSTRUCTION:
For each document, use file_search to find:
  - ANY signature platform ID (Authentisign, DocuSign, zipForm, DotLoop, or other)
  - Party names and property address
  - Any signature blocks that appear blank (look for lines with no name above them)
  - Any initial boxes that appear empty (look for □ or blank ___ near party name fields)
Report the specific page number or section where any issue is found.
When citing evidence, use whatever ID or signature indicator was found — not just Authentisign.

{
  "summary": "2-3 sentence assessment of THIS batch only. Name specific documents reviewed. Call out any findings.",
  "overallRisk": "HIGH | MEDIUM | LOW",
  "trueRisk": [
    { "item": "exact filename or document name", "detail": "specific finding with page/section reference", "evidence": "exact text, ID, or data point from the document", "folder": "E1/E2/E3/E4/E5" }
  ],
  "manageable": [
    { "item": "exact filename or document name", "detail": "finding and recommended action", "evidence": "specific text found", "folder": "E1/E2/E3/E4/E5" }
  ],
  "clear": [
    { "item": "exact filename or document name", "detail": "Authentisign ID confirmed — execution indicators present", "evidence": "Authentisign ID: [ID], party names: [names], address verified", "folder": "E1/E2/E3/E4/E5" }
  ],
  "humanCheck": [
    { "item": "exact filename or document name", "detail": "Authentisign ID confirmed but possible incomplete page — describe which page and what appears blank", "evidence": "Authentisign ID: [ID] confirmed. Page [N]: [signature/initial block] appears blank or incomplete.", "folder": "E1/E2/E3/E4/E5", "risk": "LOW" }
  ],
  "inventoryConfirmed": [
    { "item": "exact filename", "detail": "Present by filename — not read", "folder": "E1/E2/E3/E4/E5" }
  ],
  "crossReferenceFindings": [
    { "check": "specific check description", "result": "PASS | FAIL | UNABLE TO VERIFY", "detail": "specific finding or reason unable to verify" }
  ],
  "disclaimer": "This report reflects AI analysis of actual document content (read files) and filename confirmation (inventory files). It does not constitute legal review. Agent verification required before COE. SZ Real Estate Group."
}`;
}

// ─── Format report as plain text for email / Google Doc ───────────────────────

function formatReport(folderName, report, submittedBy, auditDate, conditions, readCount, inventoryCount, readFiles = [], inventoryFiles = []) {
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

  // Full document index
  lines.push('DOCUMENTS REVIEWED');
  lines.push('───────────────────────────────────────────────────────');
  if (readFiles.length > 0) {
    lines.push('Read & Audited:');
    for (const f of readFiles) {
      lines.push(`  ✅ [${f.folder}] ${f.filename} (${f.sizeKB}KB)`);
    }
  }
  if (inventoryFiles.length > 0) {
    lines.push('Inventory Confirmed (not read):');
    for (const f of inventoryFiles) {
      lines.push(`  📋 [${f.folder}] ${f.filename} (${f.sizeKB}KB)`);
    }
  }
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

  if (report.humanCheck?.length) {
    lines.push('🔵 HUMAN CHECK — LOW RISK — VERIFY BEFORE COE');
    lines.push('───────────────────────────────────────────────────────');
    lines.push('Authentisign ID confirmed on these documents. AI flagged a possible');
    lines.push('incomplete signature or initial block. Agent should visually verify.');
    lines.push('');
    for (const i of report.humanCheck) {
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

// ─── HTML report formatter for email + Google Doc ─────────────────────────────

function formatReportHTML(folderName, report, submittedBy, auditDate, conditions, readCount, inventoryCount, readFiles = [], inventoryFiles = []) {
  const riskColor  = { HIGH: '#c0392b', MEDIUM: '#d4860a', LOW: '#1e7a4b' };
  const riskLabel  = { HIGH: 'HIGH RISK — Action Required Before COE', MEDIUM: 'MEDIUM RISK — Review Items Below', LOW: 'LOW RISK — File Appears Complete' };
  const riskBg     = { HIGH: '#fdf0ef', MEDIUM: '#fef9ee', LOW: '#edf7f2' };
  const risk = report.overallRisk || 'MEDIUM';

  const s = (text) => `<span style="font-family:Arial,sans-serif;font-size:14px;line-height:1.6;">${text}</span>`;

  let h = '';

  // ── Header ──────────────────────────────────────────────────────────────────
  h += `<div style="background:#0a1628;padding:24px 32px;margin-bottom:0;">`;
  h += `<table width="100%" cellpadding="0" cellspacing="0"><tr>`;
  h += `<td><span style="font-family:Arial,sans-serif;font-size:11px;font-weight:bold;color:#c9a84c;letter-spacing:3px;text-transform:uppercase;">SZ REAL ESTATE GROUP</span><br>`;
  h += `<span style="font-family:Arial,sans-serif;font-size:18px;font-weight:bold;color:#ffffff;">AI Compliance Audit Report</span></td>`;
  h += `<td align="right"><span style="font-family:Arial,sans-serif;font-size:11px;color:rgba(255,255,255,0.5);">DRE #02066500</span></td>`;
  h += `</tr></table></div>`;

  // ── Transaction meta ─────────────────────────────────────────────────────────
  h += `<div style="background:#112040;padding:16px 32px;margin-bottom:24px;">`;
  h += `<table width="100%" cellpadding="0" cellspacing="0"><tr>`;
  h += `<td><span style="font-family:Arial,sans-serif;font-size:12px;color:rgba(255,255,255,0.5);text-transform:uppercase;letter-spacing:1px;">Transaction</span><br>`;
  h += `<span style="font-family:Arial,sans-serif;font-size:14px;font-weight:bold;color:#ffffff;">${folderName}</span></td>`;
  h += `<td><span style="font-family:Arial,sans-serif;font-size:12px;color:rgba(255,255,255,0.5);text-transform:uppercase;letter-spacing:1px;">Audited By</span><br>`;
  h += `<span style="font-family:Arial,sans-serif;font-size:14px;font-weight:bold;color:#ffffff;">${submittedBy}</span></td>`;
  h += `<td><span style="font-family:Arial,sans-serif;font-size:12px;color:rgba(255,255,255,0.5);text-transform:uppercase;letter-spacing:1px;">Date</span><br>`;
  h += `<span style="font-family:Arial,sans-serif;font-size:14px;font-weight:bold;color:#ffffff;">${auditDate}</span></td>`;
  h += `<td><span style="font-family:Arial,sans-serif;font-size:12px;color:rgba(255,255,255,0.5);text-transform:uppercase;letter-spacing:1px;">Documents</span><br>`;
  h += `<span style="font-family:Arial,sans-serif;font-size:14px;font-weight:bold;color:#ffffff;">${readCount} read | ${inventoryCount} inventory</span></td>`;
  h += `</tr></table></div>`;

  // ── Risk banner ───────────────────────────────────────────────────────────────
  h += `<div style="background:${riskBg[risk]};border-left:5px solid ${riskColor[risk]};padding:16px 24px;margin:0 24px 24px;border-radius:4px;">`;
  h += `<span style="font-family:Arial,sans-serif;font-size:16px;font-weight:bold;color:${riskColor[risk]};">`;
  h += `${risk === 'HIGH' ? '🔴' : risk === 'MEDIUM' ? '🟡' : '✅'} ${riskLabel[risk]}</span>`;
  h += `</div>`;

  // ── Summary ───────────────────────────────────────────────────────────────────
  h += `<div style="padding:0 24px 24px;">`;
  h += `<p style="font-family:Arial,sans-serif;font-size:14px;color:#444;line-height:1.7;margin:0 0 24px;">${report.summary || ''}</p>`;

  // ── Documents reviewed ────────────────────────────────────────────────────────
  h += `<div style="margin-bottom:24px;">`;
  h += `<h3 style="font-family:Arial,sans-serif;font-size:11px;font-weight:bold;color:#888;letter-spacing:2px;text-transform:uppercase;margin:0 0 12px;border-bottom:1px solid #e8e8e8;padding-bottom:8px;">DOCUMENTS REVIEWED</h3>`;

  if (readFiles.length > 0) {
    h += `<p style="font-family:Arial,sans-serif;font-size:12px;font-weight:bold;color:#444;margin:0 0 6px;">Read & Audited (${readFiles.length} files):</p>`;
    h += `<table width="100%" cellpadding="2" cellspacing="0" style="margin-bottom:12px;">`;
    for (const f of readFiles) {
      h += `<tr><td style="font-family:Arial,sans-serif;font-size:12px;color:#1e7a4b;">✅</td>`;
      h += `<td style="font-family:Arial,sans-serif;font-size:12px;color:#444;">${f.filename}</td>`;
      h += `<td style="font-family:Arial,sans-serif;font-size:11px;color:#999;text-align:right;">${f.folder} · ${f.sizeKB}KB</td></tr>`;
    }
    h += `</table>`;
  }

  if (inventoryFiles.length > 0) {
    h += `<p style="font-family:Arial,sans-serif;font-size:12px;font-weight:bold;color:#444;margin:0 0 6px;">Inventory Confirmed — Not Read (${inventoryFiles.length} files):</p>`;
    h += `<table width="100%" cellpadding="2" cellspacing="0" style="margin-bottom:12px;">`;
    for (const f of inventoryFiles) {
      h += `<tr><td style="font-family:Arial,sans-serif;font-size:12px;color:#888;">📋</td>`;
      h += `<td style="font-family:Arial,sans-serif;font-size:12px;color:#888;">${f.filename}</td>`;
      h += `<td style="font-family:Arial,sans-serif;font-size:11px;color:#bbb;text-align:right;">${f.folder} · ${f.sizeKB}KB</td></tr>`;
    }
    h += `</table>`;
  }
  h += `</div>`;

  // ── Helper: render a findings section ─────────────────────────────────────────
  function section(items, emoji, label, borderColor, bgColor, textColor) {
    if (!items || !items.length) return '';
    let out = `<div style="margin-bottom:24px;">`;
    out += `<h3 style="font-family:Arial,sans-serif;font-size:11px;font-weight:bold;color:${textColor};letter-spacing:2px;text-transform:uppercase;margin:0 0 12px;border-bottom:2px solid ${borderColor};padding-bottom:8px;">${emoji} ${label}</h3>`;
    for (const item of items) {
      out += `<div style="background:${bgColor};border-left:3px solid ${borderColor};padding:12px 16px;margin-bottom:10px;border-radius:0 4px 4px 0;">`;
      out += `<p style="font-family:Arial,sans-serif;font-size:13px;font-weight:bold;color:#222;margin:0 0 4px;">${item.item || ''} <span style="font-weight:normal;color:#888;font-size:11px;">[${item.folder || ''}]</span></p>`;
      if (item.detail) out += `<p style="font-family:Arial,sans-serif;font-size:12px;color:#555;margin:0 0 4px;"><strong>Finding:</strong> ${item.detail}</p>`;
      if (item.evidence) out += `<p style="font-family:Arial,sans-serif;font-size:12px;color:#555;margin:0;"><strong>Evidence:</strong> ${item.evidence}</p>`;
      out += `</div>`;
    }
    out += `</div>`;
    return out;
  }

  // ── Risk sections ─────────────────────────────────────────────────────────────
  h += section(report.trueRisk,    '🔴', 'TRUE RISK — ACTION REQUIRED BEFORE COE', '#c0392b', '#fdf0ef', '#c0392b');
  h += section(report.manageable,  '🟡', 'MANAGEABLE — VERIFY BEFORE COE',         '#d4860a', '#fef9ee', '#d4860a');

  if (report.humanCheck && report.humanCheck.length) {
    h += `<div style="margin-bottom:24px;">`;
    h += `<h3 style="font-family:Arial,sans-serif;font-size:11px;font-weight:bold;color:#1a5fa8;letter-spacing:2px;text-transform:uppercase;margin:0 0 6px;border-bottom:2px solid #2980b9;padding-bottom:8px;">🔵 HUMAN CHECK — LOW RISK — VERIFY BEFORE COE</h3>`;
    h += `<p style="font-family:Arial,sans-serif;font-size:12px;color:#555;margin:0 0 12px;font-style:italic;">Authentisign ID confirmed on these documents. AI flagged a possible incomplete signature or initial block. Agent should visually verify before COE.</p>`;
    for (const item of report.humanCheck) {
      h += `<div style="background:#eef6fb;border-left:3px solid #2980b9;padding:12px 16px;margin-bottom:10px;border-radius:0 4px 4px 0;">`;
      h += `<p style="font-family:Arial,sans-serif;font-size:13px;font-weight:bold;color:#222;margin:0 0 4px;">${item.item || ''} <span style="font-weight:normal;color:#888;font-size:11px;">[${item.folder || ''}]</span></p>`;
      if (item.detail) h += `<p style="font-family:Arial,sans-serif;font-size:12px;color:#555;margin:0 0 4px;"><strong>Finding:</strong> ${item.detail}</p>`;
      if (item.evidence) h += `<p style="font-family:Arial,sans-serif;font-size:12px;color:#555;margin:0;"><strong>Evidence:</strong> ${item.evidence}</p>`;
      h += `</div>`;
    }
    h += `</div>`;
  }

  h += section(report.clear, '✅', 'CLEAR — CONFIRMED PRESENT & EXECUTED', '#1e7a4b', '#edf7f2', '#1e7a4b');

  // ── Inventory confirmed ───────────────────────────────────────────────────────
  if (report.inventoryConfirmed && report.inventoryConfirmed.length) {
    h += `<div style="margin-bottom:24px;">`;
    h += `<h3 style="font-family:Arial,sans-serif;font-size:11px;font-weight:bold;color:#888;letter-spacing:2px;text-transform:uppercase;margin:0 0 12px;border-bottom:1px solid #e8e8e8;padding-bottom:8px;">📋 INVENTORY CONFIRMED — PRESENT (NOT READ)</h3>`;
    h += `<table width="100%" cellpadding="3" cellspacing="0">`;
    for (const item of report.inventoryConfirmed) {
      h += `<tr><td style="font-family:Arial,sans-serif;font-size:12px;color:#888;">📋 ${item.item || ''}</td>`;
      h += `<td style="font-family:Arial,sans-serif;font-size:11px;color:#bbb;text-align:right;">[${item.folder || ''}]</td></tr>`;
    }
    h += `</table></div>`;
  }

  // ── Cross-reference checks ────────────────────────────────────────────────────
  if (report.crossReferenceFindings && report.crossReferenceFindings.length) {
    h += `<div style="margin-bottom:24px;">`;
    h += `<h3 style="font-family:Arial,sans-serif;font-size:11px;font-weight:bold;color:#555;letter-spacing:2px;text-transform:uppercase;margin:0 0 12px;border-bottom:1px solid #e8e8e8;padding-bottom:8px;">🔍 CROSS-REFERENCE CHECKS</h3>`;
    for (const c of report.crossReferenceFindings) {
      const icon = c.result === 'PASS' ? '✅' : c.result === 'FAIL' ? '🔴' : '🟡';
      const color = c.result === 'PASS' ? '#1e7a4b' : c.result === 'FAIL' ? '#c0392b' : '#d4860a';
      h += `<div style="padding:8px 0;border-bottom:1px solid #f0f0f0;">`;
      h += `<span style="font-family:Arial,sans-serif;font-size:12px;font-weight:bold;color:${color};">${icon} ${c.check || ''}: ${c.result || ''}</span>`;
      if (c.detail) h += `<br><span style="font-family:Arial,sans-serif;font-size:12px;color:#777;padding-left:20px;">${c.detail}</span>`;
      h += `</div>`;
    }
    h += `</div>`;
  }

  // ── Disclaimer + footer ───────────────────────────────────────────────────────
  h += `<div style="background:#f7f7f7;border-top:1px solid #e8e8e8;padding:16px 24px;margin:0 -24px -24px;border-radius:0 0 6px 6px;">`;
  h += `<p style="font-family:Arial,sans-serif;font-size:11px;color:#999;margin:0 0 6px;line-height:1.5;">${report.disclaimer || ''}</p>`;
  h += `<p style="font-family:Arial,sans-serif;font-size:11px;color:#bbb;margin:0;">SZ Real Estate Group · DRE #02066500 · Samuel K. Zieour, Realtor · Co-Founder & Team Lead · DRE #01397303</p>`;
  h += `</div>`;

  h += `</div>`; // close main padding div

  return h;
}
